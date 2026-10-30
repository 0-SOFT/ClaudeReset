"""Measure which time zone, language and host markers a Claude CLI puts into its own API request.

No account is used: a copy of the CLI (a different image path, so the L1 deny rules do not apply)
talks to a loopback sink with a dummy key. Every other destination is pointed at a closed
loopback port so the real IP can never leave. Only header names, an allowlist of values and
presence flags are written; raw headers and bodies are never saved.

Usage: python tools/measure_cli_locale.py OUTPUT.json [path-to-claude.exe] [work-dir-parent]
The working directory path is part of the CLI request, so pass a parent outside the user profile
to separate a leaked user name from a path that merely contains it.
"""
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

ALLOWED = ('accept-language', 'user-agent', 'x-stainless-os', 'x-stainless-arch', 'x-stainless-lang',
           'x-stainless-runtime', 'x-stainless-runtime-version', 'x-stainless-package-version',
           'anthropic-version', 'x-app')


def newest_extension_binary():
    found = sorted((Path.home() / '.vscode/extensions').glob('anthropic.claude-code-*-win32-x64/resources/native-binary/claude.exe'))
    if not found:
        raise SystemExit('No extension claude.exe found')
    return found[-1]


def windows_settings():
    script = ('$t=Get-TimeZone; $l=Get-WinUserLanguageList; '
              '@{timezone_id=$t.Id; utc_offset=$t.BaseUtcOffset.ToString(); culture=(Get-Culture).Name; '
              'ui_language=(Get-UICulture).Name; language_list=@($l | ForEach-Object {$_.LanguageTag})} | ConvertTo-Json -Compress')
    out = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                         capture_output=True, text=True, timeout=30)
    return json.loads(out.stdout)


class Sink(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length') or 0))
        text = body.decode('utf-8', 'replace')
        markers = {'timezone_word': 'timezone' in text.lower() or 'time zone' in text.lower(),
                   'istanbul': 'istanbul' in text.lower(), 'turkey': 'turk' in text.lower(),
                   'utc_offset_text': '+03:00' in text or 'UTC+3' in text or 'GMT+3' in text,
                   'hostname': os.environ.get('COMPUTERNAME', '\0').lower() in text.lower(),
                   'username': os.environ.get('USERNAME', '\0').lower() in text.lower(),
                   'locale_en_us': 'en-us' in text.lower()}
        Sink.seen.append({'path': self.path.split('?')[0], 'header_names': sorted(k.lower() for k in self.headers.keys()),
                          'values': {k: self.headers[k] for k in ALLOWED if self.headers.get(k) is not None},
                          'body_bytes': len(body), 'body_markers': markers})
        payload = json.dumps({'type': 'error', 'error': {'type': 'authentication_error', 'message': 'sink'}}).encode()
        self.send_response(401)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST

    def log_message(self, *args):
        pass


def main():
    output = Path(sys.argv[1])
    source = Path(sys.argv[2]) if len(sys.argv) > 2 else newest_extension_binary()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Sink)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    folder = Path(tempfile.mkdtemp(prefix='locale-measure-', dir=sys.argv[3] if len(sys.argv) > 3 else None))
    try:
        copy = folder / 'claude-measure.exe'
        shutil.copyfile(source, copy)
        environment = dict(os.environ)
        for name in list(environment):
            if name.upper().startswith(('ANTHROPIC_', 'CLAUDE_CODE_')) or name.upper() in ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'):
                del environment[name]
        environment.update(ANTHROPIC_BASE_URL=f'http://127.0.0.1:{server.server_address[1]}', ANTHROPIC_API_KEY='sk-ant-measure-dummy',
                           HTTP_PROXY='http://127.0.0.1:1', HTTPS_PROXY='http://127.0.0.1:1', NO_PROXY='127.0.0.1,localhost')
        try:
            result = subprocess.run([str(copy), '-p', 'x', '--output-format', 'json', '--max-turns', '1'], cwd=folder, env=environment,
                                    capture_output=True, timeout=45, creationflags=0x08000000)
            status = {'exit_code': result.returncode}
        except subprocess.TimeoutExpired:
            status = {'timed_out': True}
        report = {'schema': 1, 'observed_utc': datetime.now(timezone.utc).isoformat(),
                  'binary_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'binary': str(source.parent.parent.parent.name),
                  'account_used': False, 'real_network_used': False, 'raw_headers_or_bodies_saved': False,
                  'windows': windows_settings(), 'run': status, 'cwd_inside_user_profile': str(Path.home()).lower() in str(folder).lower(), 'requests_to_sink': Sink.seen}
        output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(json.dumps(report, indent=2))
    finally:
        server.shutdown()
        shutil.rmtree(folder, ignore_errors=True)


if __name__ == '__main__':
    main()
