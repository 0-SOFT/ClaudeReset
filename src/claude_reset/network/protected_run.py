"""Run a reviewed Claude binary inside the owned package so every child inherits the network restriction.

The L1 deny rules bind to the exact claude.exe image, so commands and MCP servers it starts have
another image and stay open. A process started through Invoke-CommandInDesktopPackage carries the
package identity and passes it to its children; those are denied directly and may use only the relay.
The wrapper (an ordinary process that owns the caller's stdio) and the pump (inside the package)
talk over one authenticated named pipe; the pump starts the binary and forwards its stdio.

If the pump cannot be started the wrapper runs the binary directly, tells the caller on stderr and
logs it: the image rule still applies, only the child coverage is missing. Create
`~/.claude-reset/disable-wrapper.flag` to force that direct mode without editing any setting.
"""
import fnmatch
import glob
import json
import os
import secrets
import sys
import threading
from multiprocessing.connection import AuthenticationError, Client, Listener
from pathlib import Path

from .. import config, layout
from ..errors import SafetyError, error_kind
from ..model.ids import utc_now
from ..windows import powershell, process
from ..windows.job import KillOnClose

__all__ = ['drive', 'is_reviewed_binary', 'main', 'pump_job', 'pump_main', 'wrapper_main']

FAMILY, APP = config.OWNED_PACKAGE
STDIN, STDIN_EOF, STDOUT, STDERR, EXIT = range(5)
CHUNK = 65536
HANDSHAKE_SECONDS = 30
LOG_LIMIT = 200_000
ALLOWED = (layout.STANDALONE_CLI, layout.VSCODE_EXTENSIONS + '/' + layout.EXTENSION_CLI)


def state_folder():
    return Path.home() / layout.TOOL_HOME


def is_reviewed_binary(path, home=None):   # None: Path.home(), looked up on each call
    """Only the Claude images the L1 deny rules already name may be started by the pump."""
    home = Path(home or Path.home())
    try:
        resolved = Path(path).resolve(strict=True).as_posix().lower()
        root = home.resolve(strict=True).as_posix().lower()
    except OSError:
        return False
    return any(fnmatch.fnmatchcase(resolved, f'{glob.escape(root)}/{pattern}'.lower()) for pattern in ALLOWED)


def log(mode, reason=''):
    """One bounded line per start; never arguments or environment."""
    try:
        folder = state_folder()
        folder.mkdir(exist_ok=True)
        path = folder / 'protected-run.log'
        if path.exists() and path.stat().st_size > LOG_LIMIT:
            path.write_text('', encoding='ascii')
        with open(path, 'a', encoding='ascii') as stream:
            stream.write(json.dumps({'utc': utc_now(), 'mode': mode, 'reason': reason[:120]}) + '\n')
    except OSError:
        pass


def job_environment(environment):
    result = {str(k): str(v) for k, v in environment.items()}
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
        result.pop(name, None)
    result.update(dict.fromkeys(config.PROXY_VARIABLES, config.RELAY_URL), NO_PROXY=config.NO_PROXY)
    return result


# ----- pump (inside the package) ---------------------------------------------------------------

def pump_job(conn, job, home=None):
    """Start the job's binary and forward its stdio; returns when the binary exits or the pipe breaks."""
    argv = job.get('argv')
    if (not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv)
            or not is_reviewed_binary(argv[0], home)):
        conn.send_bytes(bytes([STDERR]) + b'ClaudeReset: binary is not a reviewed Claude image\n')
        conn.send_bytes(bytes([EXIT]) + (126).to_bytes(4, 'little', signed=True))
        return 126
    interactive = job.get('interactive') is True
    environment = job_environment(job.get('env') or {})
    lock = threading.Lock()
    killer = KillOnClose()
    if interactive:
        child = process.start_console(argv, cwd=job.get('cwd') or None, environment=environment)
        killer.adopt(child)
        code = child.wait()
        with lock:
            conn.send_bytes(bytes([EXIT]) + code.to_bytes(4, 'little', signed=True))
        return 0
    child = process.start_piped(argv, cwd=job.get('cwd') or None, environment=environment)
    killer.adopt(child)

    def forward(stream, kind):
        try:
            while True:
                data = stream.read1(CHUNK)
                if not data:
                    return
                with lock:
                    conn.send_bytes(bytes([kind]) + data)
        except (OSError, ValueError, EOFError):
            pass

    def listen():
        try:
            while True:
                frame = conn.recv_bytes()
                if frame[:1] == bytes([STDIN]):
                    child.stdin.write(frame[1:])
                    child.stdin.flush()
                elif frame[:1] == bytes([STDIN_EOF]):
                    child.stdin.close()
        except (EOFError, OSError, ValueError):
            # The wrapper is gone: end the binary and everything it started.
            process.kill_tree(child.pid)
    readers = [threading.Thread(target=forward, args=(child.stdout, STDOUT), daemon=True),
               threading.Thread(target=forward, args=(child.stderr, STDERR), daemon=True)]
    for reader in readers:
        reader.start()
    threading.Thread(target=listen, daemon=True).start()
    code = child.wait()
    for reader in readers:
        reader.join(5)
    with lock:
        try:
            conn.send_bytes(bytes([EXIT]) + code.to_bytes(4, 'little', signed=True))
        except (OSError, EOFError):
            pass
    return 0


def pump_main(pipe, hex_key):
    """Entry inside the package: `ClaudeReset.exe --protected-pump PIPE HEXKEY`."""
    try:
        conn = Client(pipe, family='AF_PIPE', authkey=bytes.fromhex(hex_key))
        job = json.loads(conn.recv_bytes())
        return pump_job(conn, job)
    except (OSError, EOFError, ValueError, AuthenticationError):
        return 1


# ----- wrapper (ordinary process owning the caller's stdio) ------------------------------------

def start_pump(pipe, key, executable, runner=powershell.run_process):
    arguments = f'--protected-pump {pipe} {key.hex()}'
    command = (f'Invoke-CommandInDesktopPackage -PackageFamilyName {powershell.quote(FAMILY)} -AppId {powershell.quote(APP)} '
               f'-Command {powershell.quote(executable)} -Args {powershell.quote(arguments)} -PreventBreakaway')
    result = powershell.start(['-Command', command], text=False, timeout=HANDSHAKE_SECONDS, runner=runner)
    if result.returncode != 0:
        raise SafetyError('Package launch refused')


def connect(pump_executable, *, starter=start_pump, seconds=HANDSHAKE_SECONDS):
    """Open the pipe, start the pump in the package and wait for its authenticated connection."""
    key = secrets.token_bytes(16)
    pipe = r'\\.\pipe\clauderesetrun-' + secrets.token_hex(8)
    listener = Listener(pipe, family='AF_PIPE', authkey=key)
    outcome = {}

    def accept():
        try:
            outcome['conn'] = listener.accept()
        except (OSError, AuthenticationError, EOFError) as exc:
            outcome['error'] = exc
    waiter = threading.Thread(target=accept, daemon=True)
    waiter.start()
    try:
        starter(pipe, key, str(pump_executable))
        waiter.join(seconds)
        if 'conn' not in outcome:
            raise SafetyError('Package process did not connect')
        return outcome['conn']
    finally:
        listener.close()


def drive(conn, job, stdin, stdout, stderr):
    """Send the job, forward stdio frames both ways and return the binary's exit code."""
    conn.send_bytes(json.dumps(job).encode('utf-8'))
    lock = threading.Lock()

    def feed():
        try:
            while True:
                data = stdin.read1(CHUNK) if hasattr(stdin, 'read1') else stdin.read(CHUNK)
                with lock:
                    conn.send_bytes(bytes([STDIN if data else STDIN_EOF]) + data)
                if not data:
                    return
        except (OSError, ValueError, EOFError):
            pass
    if stdin is not None:
        threading.Thread(target=feed, daemon=True).start()
    while True:
        try:
            frame = conn.recv_bytes()
        except (EOFError, OSError):
            stderr.write(b'ClaudeReset: package process ended unexpectedly\n')
            stderr.flush()
            return 1
        kind, payload = frame[0], frame[1:]
        if kind in (STDOUT, STDERR):
            target = stdout if kind == STDOUT else stderr
            target.write(payload)
            target.flush()
        elif kind == EXIT:
            return int.from_bytes(payload[:4], 'little', signed=True)


def run_direct(argv):
    environment = job_environment(os.environ)
    return process.run_attached(argv, environment)


def wrapper_main(argv, *, interactive=False, pump_executable=Path(sys.executable).with_name(config.CONTROLLER_EXE),
                 connector=connect, direct=run_direct):
    """argv = [claude.exe, args...]; the exit code is the binary's. direct runs the binary without the package."""
    if (state_folder() / 'disable-wrapper.flag').exists():
        log('direct', 'disable-wrapper.flag present')
        return direct(argv)
    if not is_reviewed_binary(argv[0]):
        sys.stderr.write('ClaudeReset: refusing to run an unreviewed binary\n')
        return 126
    try:
        conn = connector(pump_executable)
    except (SafetyError, OSError, process.SubprocessError) as exc:
        log('direct', error_kind(exc))
        sys.stderr.write('ClaudeReset: package launch failed; running without coverage of child processes\n')
        return direct(argv)
    log('package', 'interactive' if interactive else 'piped')
    job = {'argv': argv, 'cwd': os.getcwd(), 'env': dict(os.environ), 'interactive': interactive}
    return drive(conn, job, sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer)


def main(argv):
    """`ClaudeResetRun.exe [--interactive] CLAUDE_EXE ARGS...`, also the claudeProcessWrapper convention."""
    interactive = bool(argv) and argv[0] == '--interactive'
    rest = argv[1:] if interactive else argv
    if not rest:
        sys.stderr.write('usage: ClaudeResetRun [--interactive] claude.exe [args]\n')
        return 2
    return wrapper_main(rest, interactive=interactive)
