"""Proxy and protection in plain words: one summary, one main action, one fix per problem. No Tk.

Every action reuses the tested functions behind the specialist window (proxy_form,
protection_panel, l1_*). Public results carry fixed text only; the measured exit
address is shown to the person for confirmation and is never logged here.
"""
from . import connections, l1_check, protection_panel, remote_backend, strict_guard
from .safeio import SafetyError

PROBLEMS = {
    'exit_mismatch': ('Прокси выходит в интернет с другого адреса, чем вы подтвердили.', 'accept_exit'),
    'proxy_unreachable': ('Прокси не отвечает.', 'retry'),
    'exit_probe_failed': ('Не удалось проверить, через какой адрес выходит прокси.', 'retry'),
    'backend_changed': ('Прокси изменился или остановлен.', 'retry'),
    'backend_config_failed': ('Настройки прокси не прошли проверку.', 'reenter'),
    'profile_changed': ('Сохранённый адрес выхода изменился.', 'restart'),
    'monitor_error': ('Защита остановилась из-за ошибки наблюдения.', 'restart'),
    'exception': ('Защита остановилась из-за ошибки.', 'restart'),
}
FIXES = {
    'accept_exit': 'Проверить и принять новый адрес',
    'retry': 'Проверить прокси снова',
    'reenter': 'Ввести прокси заново',
    'restart': 'Перезапустить защиту',
    'install': 'Включить защиту заново',
    'resume': 'Снять с паузы и включить',
}
CLIENTS = (('client_desktop', 'Claude Desktop'), ('client_standalone_cli', 'Claude Code в терминале'),
           ('client_vscode_extension', 'Claude Code в VS Code'))
MESSAGES = {
    'proxy_checked': 'Прокси работает.',
    'proxy_unreachable': 'Прокси не отвечает. Проверьте адрес и порт.',
    'proxy_login_or_connect_refused': 'Прокси не принял логин и пароль или не пустил дальше.',
    'proxy_exit_unavailable': 'Прокси пустил, но адрес выхода не измерился. Повторите проверку.',
    'proxy_check_failed': 'Проверка не завершилась. Повторите её.',
    'proxy_confirmation_required': 'Сначала проверьте прокси.',
    'proxy_saved': 'Прокси и адрес выхода сохранены.',
    'engine_installed': 'Движок VLESS установлен.',
    'engine_needs_attention': 'Движок установлен, но проверка не прошла. Повторите её.',
    'engine_not_started': 'Движок не установлен: прежний движок ещё на месте. Сначала снимите его.',
    'engine_remote_profile_saved': 'Сохранён другой прокси. Сначала выключите защиту и снимите его.',
    'engine_install_failed': 'Движок не установился. Проверьте файл профиля и интернет.',
    'backend_removed': 'Прокси снят.',
    'backend_remove_refused': 'Прокси не снят: сначала выключите защиту.',
}


def message(status):
    return MESSAGES.get(status, 'Не получилось. Повторите или откройте «Режим для специалистов».')


def summary(paths, *, collect=l1_check.collect, evaluate=l1_check.evaluate, status=strict_guard.status,
            remote=remote_backend.load):
    """Fresh read-only state: off, on, paused, problem, partial or unknown, with one suggested fix."""
    try:
        facts = collect(paths)
        report = evaluate(facts)
        parts = {c['id']: c['status'] for c in report.get('checks', [])}
        task = (facts.get('tasks') or {}).get(l1_check.CONTROLLER_TASK)
    except Exception:
        return {'state': 'unknown', 'title': 'Состояние не прочиталось', 'text': 'Нажмите «Обновить».',
                'fix': None, 'proxy': None, 'proxy_saved': False, 'clients': []}
    try:
        last = status(paths).get('last_report') or {}
    except Exception:
        last = {}
    try:
        profile = remote(paths)
    except Exception:
        profile = None
    if profile is not None:
        proxy = 'HTTP' if profile.get('adapter') == remote_backend.HTTP_ADAPTER else 'SOCKS5'
    else:
        proxy = 'VLESS' if parts.get('backend_task') == 'ok' else None
    saved = parts.get('backend_task') == 'ok' and parts.get('connection_profile') == 'ok'
    controller = parts.get('controller_task') == 'ok' and parts.get('controller_files') == 'ok'
    clients = [{'name': name, 'present': parts.get(key) == 'ok'} for key, name in CLIENTS]
    base = {'proxy': proxy, 'proxy_saved': saved, 'clients': clients}
    if report.get('protection') == 'installed':
        return dict(base, state='on', title='Защита включена',
                    text='Claude выходит в интернет только через ваш прокси.', fix=None)
    if controller and task == 'Disabled' and parts.get('relay_listening') != 'ok':
        # The owner paused the protection: its task is switched off, Claude goes out directly.
        return dict(base, state='paused', title='Защита на паузе',
                    text='Claude сейчас выходит в интернет напрямую, без прокси.', fix='resume')
    if controller:
        reason, fix = PROBLEMS.get(last.get('stop_reason'), ('Защита установлена, но сейчас не работает.', 'restart'))
        return dict(base, state='problem', title='Claude сейчас без сети',
                    text=reason + ' Напрямую Claude не выйдет — так задумано.', fix=fix)
    if report.get('protection') == 'partial' and any(
            parts.get(k) == 'ok' for k in ('isolation_package', 'consent', 'controller_files', 'controller_task')):
        return dict(base, state='partial', title='Защита установлена не полностью',
                    text='Включите её заново или выключите совсем.', fix='install')
    return dict(base, state='off', title='Защита выключена',
                text='Claude выходит в интернет напрямую, как обычно.', fix=None)


def draft(proxy_type, host, port, username, password):
    """A private draft for checking; a wrong field returns the fixed hint and no draft."""
    from .proxy_form import ProxyDraft
    try:
        return ProxyDraft(host, port, username, password, proxy_type=proxy_type), None
    except SafetyError as exc:
        return None, str(exc)


def connect(paths, checked, *, installed, protect_extension=None, perform=protection_panel.perform):
    """Save the confirmed exit and switch the protection on, or apply it to the running protection."""
    if checked is None or checked.expected is None:
        return {'text': message('proxy_confirmation_required'), 'ok': False}
    if installed:
        result = perform(paths, 'change_proxy', confirmed=True, proxy_draft=checked)
    else:
        saved = checked.save(paths, confirmed=True)
        if saved.get('status') != 'proxy_saved':
            return {'text': message(saved.get('status')), 'ok': False}
        result = perform(paths, 'install', confirmed=True, protect_extension=protect_extension)
    return {'text': result['text'], 'ok': True}


def recheck(paths, *, check_saved=protection_panel.check_saved_proxy, load=connections.load):
    """Check the saved proxy again. Returns the private draft and whether the exit is unchanged."""
    checked, outcome = check_saved(paths)
    if outcome.get('status') != 'proxy_checked' or checked is None or checked.expected is None:
        return None, {'status': outcome.get('status', 'proxy_check_failed'), 'text': message(outcome.get('status'))}
    try:
        saved = (load(paths) or {}).get('expected_exit_ips') or []
    except Exception:
        saved = []
    same = checked.expected['expected_exit_ips'][0] in saved
    return checked, {'status': 'proxy_checked', 'same_exit': same, 'text': message('proxy_checked')}
