from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from .safeio import SafetyError, guarded

SERVER_LINKS = {
    'sessions': 'https://claude.ai/settings/account',
    'code_tokens': 'https://claude.ai/settings/claude-code',
    'help': 'https://support.claude.com/en/articles/10310342-how-do-i-log-out-of-all-active-sessions',
}
SERVER_STEPS = [
    'В старом аккаунте открыть Settings → Account и завершить нужные сессии. Выход со всех устройств затронет также другие ПК и телефоны.',
    'Отдельно открыть Settings → Claude Code и отозвать нужные токены. Выход из веб-сессий не засчитывается как этот шаг.',
    'Проверить доступные в аккаунте устройства Cowork/Remote Control и сопряжения. Неподдерживаемый интерфейс не считать автоматически очищенным.',
    'Повторить для каждого прежнего аккаунта, для которого нужен отзыв. Без доступа к аккаунту серверный отзыв здесь не выполняется.',
    'Сохранить/экспортировать нужную облачную память до выхода. Программа сохраняет только найденную локальную память.',
]


def open_server_page(kind: str):
    if kind not in SERVER_LINKS:
        raise SafetyError('Unknown server action')
    raise SafetyError('Открытие Claude через общий браузер отключено: этот браузер не входит в защищённую область. Требуется проверенный выделенный запуск.')


def chrome_executable(local: Path):
    candidates = [local / 'Google/Chrome/Application/chrome.exe']
    for name in ('PROGRAMFILES', 'PROGRAMFILES(X86)'):
        if os.environ.get(name):
            candidates.append(Path(os.environ[name]) / 'Google/Chrome/Application/chrome.exe')
    for path in candidates:
        guarded(path, path.parent)
        if path.is_file():
            return path
    raise SafetyError('Google Chrome was not found in supported installation locations')


def managed_chrome_directory(paths, run_id: str):
    import re
    if not re.fullmatch(r'[a-f0-9]{32}', run_id):
        raise SafetyError('Invalid Chrome profile ID')
    directory = guarded(paths.state / 'ChromeProfiles' / run_id, paths.state)
    marker = guarded(directory / 'claude-reset-profile.json', paths.state)
    if not marker.is_file():
        raise SafetyError('This profile was not created by Claude Reset')
    if marker.stat().st_size > 4096:
        raise SafetyError('Invalid managed profile marker')
    try:
        obj = json.loads(marker.read_text('utf-8'))
    except (ValueError, UnicodeError):
        raise SafetyError('Invalid managed profile marker') from None
    if obj != {'created_by': 'ClaudeReset', 'run': run_id}:
        raise SafetyError('Invalid managed profile marker')
    return directory


def managed_chrome_profiles(paths):
    """Discover only owned profiles; never guess which of several to open."""
    import re
    root = guarded(paths.state / 'ChromeProfiles', paths.state)
    if not root.exists():
        return []
    result = []
    for directory in sorted(root.iterdir()):
        if re.fullmatch(r'[a-f0-9]{32}', directory.name):
            managed_chrome_directory(paths, directory.name)
            result.append(directory.name)
    return result


def launch_clean_chrome(paths, run_id: str, url='https://claude.ai', *, loopback_probe=False):
    directory = managed_chrome_directory(paths, run_id)
    parsed = urlsplit(url)
    try:
        valid = (parsed.scheme == 'https' and parsed.hostname in ('claude.ai', 'claude.com', 'platform.claude.com') and parsed.port in (None, 443))
        if loopback_probe:
            valid = parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port is not None
        if not valid or parsed.username or parsed.password or any(ord(c) < 32 for c in url):
            raise ValueError()
    except ValueError:
        raise SafetyError('Only supported Claude HTTPS links or an explicit loopback measurement are allowed') from None
    # A separate user-data directory is not a Windows network identity. Even
    # opening a local measurement can let the browser send background requests.
    raise SafetyError('Прежний запуск Chrome без сетевой защиты отключён. Защищённый запуск пока недоступен: приёмка изоляции DNS/IPC не завершена.')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SafetyError('Unexpected network-test redirect')


def network_probe(opener=None):
    """Explicit, opt-in HTTPS observation from THIS process only. No router changes."""
    opener = opener or urllib.request.build_opener(NoRedirect())
    results = []
    for label, url in [('ipv4', 'https://api.ipify.org?format=json'), ('ipv6', 'https://api6.ipify.org?format=json')]:
        try:
            with opener.open(urllib.request.Request(url, headers={'User-Agent': 'ClaudeReset/0.2 network-check'}), timeout=8) as response:
                if response.geturl() != url:
                    raise SafetyError('Unexpected endpoint')
                payload = json.loads(response.read(4097))
                address = ipaddress.ip_address(payload['ip'])
                if (label == 'ipv4' and address.version != 4) or (label == 'ipv6' and address.version != 6):
                    raise SafetyError('Unexpected address family')
                results.append({'family': label, 'status': 'observed', 'address': str(address)})
        except Exception:
            results.append({'family': label, 'status': 'unavailable_or_error'})
    return {'observations': results, 'full_tunnel_verified': False, 'router_modified': False,
            'scope': 'HTTPS requests of this process only; no DNS, WebRTC, UDP or outage certification'}
