"""B1: portable test of the Windows boundary, no tunnel and no real client (see claude_reset.l1_mechanism).

One UAC prompt for the owner. Usage: python tools/l1_mechanism_test.py [OUTPUT_DIR]
Changes only a disposable sublayer that it deletes again; real clients, DNS, routes, proxy and the
router are never touched. Refuses to run while a backend or relay already listens on 25080/25082.
"""
import ctypes
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


def relaunch_elevated(report):
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    shell.ShellExecuteW.restype = ctypes.c_void_p
    args = subprocess.list2cmdline([str(Path(__file__).resolve()), '--elevated', str(report)])
    code = shell.ShellExecuteW(None, 'runas', sys.executable, args, None, 0)
    if not code or code <= 32:
        print('Elevation was not granted; nothing was changed')
        return 2
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            data = json.loads(report.read_text('utf-8'))
        except (OSError, ValueError):
            data = {}
        if data.get('finished'):
            print(json.dumps(data, indent=1))
            return 0 if data.get('verdict') == 'mechanism_passed' else 1
        time.sleep(1)
    print('No report from the elevated run')
    return 2


def main():
    from claude_reset import l1_mechanism
    if len(sys.argv) == 3 and sys.argv[1] == '--elevated':
        l1_mechanism.run(Path(sys.argv[2]))
        return 0
    errors = l1_mechanism.precondition_errors()
    if errors:
        print(json.dumps({'verdict': 'not_started', 'reasons': errors}, indent=1))
        return 2
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / '.claude-reset' / 'verify'
    out.mkdir(parents=True, exist_ok=True)
    return relaunch_elevated(out / ('mechanism-' + time.strftime('%Y%m%dT%H%M%S') + '.json'))


if __name__ == '__main__':
    raise SystemExit(main())
