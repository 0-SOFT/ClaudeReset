"""Opt-in loopback measurement of the chosen browser, not of Claude traffic."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import secrets
import threading
from .safeio import SafetyError

PAGE = '''<!doctype html><html lang="ru"><meta charset="utf-8">
<title>Claude Reset — проверка браузера</title>
<style>body{font:18px system-ui;max-width:850px;margin:60px auto;background:#faf8f5;color:#202020}pre{white-space:pre-wrap;background:white;padding:24px;border:1px solid #ddd}</style>
<h1>Проверка выбранного браузера</h1><p>Измеряются пояс, языки и разрешение геолокации этой страницы. Данные отправляются только на локальный адрес программы. Это не проверка запросов Claude или всего VPN.</p>
<pre id="result">Измерение…</pre><script>
(async()=>{const data={timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
offset_minutes:-new Date().getTimezoneOffset(),languages:[...navigator.languages],geolocation:'unavailable'};
try{data.geolocation=(await navigator.permissions.query({name:'geolocation'})).state}catch(e){}
const response=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
document.getElementById('result').textContent=JSON.stringify(await response.json(),null,2);})();
</script></html>'''


def validate_measurement(data, accept_language):
    if not isinstance(data, dict) or set(data) != {'timezone', 'offset_minutes', 'languages', 'geolocation'}:
        raise SafetyError('Unexpected browser measurement fields')
    if not isinstance(data['timezone'], str) or not re.fullmatch(r'[A-Za-z0-9_+\-/]{1,80}', data['timezone']):
        raise SafetyError('Invalid browser time zone')
    if type(data['offset_minutes']) is not int or not -840 <= data['offset_minutes'] <= 840:
        raise SafetyError('Invalid browser offset')
    if not isinstance(data['languages'], list) or not 1 <= len(data['languages']) <= 30 or any(
            not isinstance(x, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,35}', x) for x in data['languages']):
        raise SafetyError('Invalid browser languages')
    if data['geolocation'] not in ('granted', 'denied', 'prompt', 'unavailable'):
        raise SafetyError('Invalid browser permission')
    if not re.fullmatch(r'[A-Za-z0-9,*;. =\-]{0,512}', accept_language):
        raise SafetyError('Invalid language header')
    return {**data, 'accept_language': accept_language,
            'scope': 'selected browser, loopback page only; Claude payload and site permission not measured',
            'network_verified': False}


def browser_measurement(launch, timeout=45):
    """launch(url) must explicitly launch the selected managed browser profile."""
    token = '/' + secrets.token_hex(24)
    complete = threading.Event()
    results = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def valid(self):
            return self.path == token and self.headers.get('Host') == authority
        def reply(self, status, body, content_type='application/json'):
            self.send_response(status)
            self.send_header('Content-Type', content_type + '; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            if not self.valid():
                self.reply(404, b'{}')
                return
            self.reply(200, PAGE.encode('utf-8'), 'text/html')
        def do_POST(self):
            try:
                if len(self.headers.get_all('Content-Length', [])) != 1 or self.headers.get('Transfer-Encoding'):
                    raise ValueError()
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 4096:
                    raise ValueError()
                # Consume only the bounded, explicitly framed body before an
                # origin refusal. Closing with unread bytes can reset the TCP
                # connection on Windows and discard the HTTP error response.
                body = self.rfile.read(length)
                if (len(body) != length or not self.valid() or
                        self.headers.get('Origin') != 'http://' + authority or complete.is_set() or
                        self.headers.get_content_type() != 'application/json'):
                    raise ValueError()
                data = json.loads(body)
                result = validate_measurement(data, self.headers.get('Accept-Language', ''))
                results.append(result)
                self.reply(200, json.dumps(result, ensure_ascii=False).encode('utf-8'))
                complete.set()
            except (ValueError, SafetyError, OSError):
                self.reply(400, b'{"status":"invalid_measurement"}')
        def setup(self):
            super().setup()
            self.connection.settimeout(5)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    authority = '127.0.0.1:' + str(server.server_port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        launch('http://' + authority + token)
        if not complete.wait(timeout):
            raise SafetyError('Browser measurement timed out; no result was inferred')
        return results[0]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
