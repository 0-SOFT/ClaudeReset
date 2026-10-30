"""Proxy and protection in plain words: one summary, one main action, one fix per problem. No Tk.

Every action reuses the tested functions behind the specialist window (proxy_form,
protection_panel, l1_*). Public results carry fixed text only; the measured exit
address is shown to the person for confirmation and is never logged here.
"""
from types import MappingProxyType

from ..network import connections, controller_status, l1_check, remote_backend
from . import protection_panel
from ..errors import SafetyError
from ..model.status import ProtectionState, Proxy
from ..services import protection
from ..services import proxy

PROBLEMS = MappingProxyType({
    'exit_mismatch': 'Прокси выходит в интернет с другого адреса, чем вы подтвердили.',
    'proxy_unreachable': 'Прокси не отвечает.',
    'exit_probe_failed': 'Не удалось проверить, через какой адрес выходит прокси.',
    'backend_changed': 'Прокси изменился или остановлен.',
    'backend_config_failed': 'Настройки прокси не прошли проверку.',
    'profile_changed': 'Сохранённый адрес выхода изменился.',
    'monitor_error': 'Защита остановилась из-за ошибки наблюдения.',
    'exception': 'Защита остановилась из-за ошибки.',
})
# Title and text of each protection state; a problem says why the protection stopped.
STATES = MappingProxyType({
    ProtectionState.ON: ('Защита включена', 'Claude выходит в интернет только через ваш прокси.'),
    ProtectionState.PAUSED: ('Защита на паузе', 'Claude сейчас выходит в интернет напрямую, без прокси.'),
    ProtectionState.PARTIAL: ('Защита установлена не полностью', 'Включите её заново или выключите совсем.'),
    ProtectionState.OFF: ('Защита выключена', 'Claude выходит в интернет напрямую, как обычно.'),
    ProtectionState.UNKNOWN: ('Состояние не прочиталось', 'Нажмите «Обновить».'),
})
FIXES = MappingProxyType({
    'accept_exit': 'Проверить и принять новый адрес',
    'retry': 'Проверить прокси снова',
    'reenter': 'Ввести прокси заново',
    'restart': 'Перезапустить защиту',
    'install': 'Включить защиту заново',
    'resume': 'Снять с паузы и включить',
})
CLIENTS = MappingProxyType({'client_desktop': 'Claude Desktop', 'client_standalone_cli': 'Claude Code в терминале',
                            'client_vscode_extension': 'Claude Code в VS Code'})
MESSAGES = MappingProxyType({
    Proxy.PROXY_CHECKED: 'Прокси работает.',
    Proxy.PROXY_UNREACHABLE: 'Прокси не отвечает. Проверьте адрес и порт.',
    Proxy.PROXY_LOGIN_OR_CONNECT_REFUSED: 'Прокси не принял логин и пароль или не пустил дальше.',
    Proxy.PROXY_EXIT_UNAVAILABLE: 'Прокси пустил, но адрес выхода не измерился. Повторите проверку.',
    Proxy.PROXY_CHECK_FAILED: 'Проверка не завершилась. Повторите её.',
    Proxy.PROXY_CONFIRMATION_REQUIRED: 'Сначала проверьте прокси.',
    Proxy.PROXY_SAVED: 'Прокси и адрес выхода сохранены.',
    Proxy.ENGINE_INSTALLED: 'Движок VLESS установлен.',
    Proxy.ENGINE_NEEDS_ATTENTION: 'Движок установлен, но проверка не прошла. Повторите её.',
    Proxy.ENGINE_NOT_STARTED: 'Движок не установлен: прежний движок ещё на месте. Сначала снимите его.',
    Proxy.ENGINE_REMOTE_PROFILE_SAVED: 'Сохранён другой прокси. Сначала выключите защиту и снимите его.',
    Proxy.ENGINE_INSTALL_FAILED: 'Движок не установился. Проверьте файл профиля и интернет.',
    Proxy.BACKEND_REMOVED: 'Прокси снят.',
    Proxy.BACKEND_REMOVE_REFUSED: 'Прокси не снят: сначала выключите защиту.',
})


def message(status):
    return MESSAGES.get(status, 'Не получилось. Повторите или откройте «Режим для специалистов».')


def summary(paths, *, collect=l1_check.collect, evaluate=l1_check.evaluate, status=controller_status.status,
            remote=remote_backend.load):
    """The protection state in plain words, with one suggested fix."""
    found = protection.state(paths, collect=collect, evaluate=evaluate, status=status, remote=remote)
    reason = found.pop('stop_reason', None)
    if found['state'] == ProtectionState.PROBLEM:
        title = 'Claude сейчас без сети'
        text = PROBLEMS.get(reason,
                            'Защита установлена, но сейчас не работает.') + ' Напрямую Claude не выйдет — так задумано.'
    else:
        title, text = STATES[found['state']]
    clients = [{'name': CLIENTS[client['check']], 'present': client['present']} for client in found['clients']]
    return dict(found, title=title, text=text, clients=clients)


def draft(proxy_type, host, port, username, password, *, language, probe=None):
    """A private draft for checking; a wrong field returns the fixed hint in the window's language and no draft.
    probe makes the draft's network checks (network.probe.Probe when not given)."""
    from ..services.proxy import ProxyDraft
    try:
        return ProxyDraft(host, port, username, password, proxy_type=proxy_type, probe=probe), None
    except SafetyError as exc:
        return None, language.error_text(exc)


def connect(paths, checked, *, installed, protect_extension=None, perform=protection_panel.perform):
    """Save the confirmed exit and switch the protection on, or apply it to the running protection."""
    if checked is None or checked.expected is None:
        return {'text': message(Proxy.PROXY_CONFIRMATION_REQUIRED), 'ok': False}
    if installed:
        result = perform(paths, 'change_proxy', confirmed=True, proxy_draft=checked)
    else:
        saved = checked.save(paths, confirmed=True)
        if saved.get('status') != Proxy.PROXY_SAVED:
            return {'text': message(saved.get('status')), 'ok': False}
        result = perform(paths, 'install', confirmed=True, protect_extension=protect_extension)
    return {'text': result['text'], 'ok': True}


def recheck(paths, *, check_saved=proxy.check_saved, load=connections.load):
    """Check the saved proxy again. Returns the private draft and whether the exit is unchanged."""
    checked, outcome = check_saved(paths)
    if outcome.get('status') != Proxy.PROXY_CHECKED or checked is None or checked.expected is None:
        return None, {'status': outcome.get('status', 'proxy_check_failed'), 'text': message(outcome.get('status'))}
    try:
        saved = (load(paths) or {}).get('expected_exit_ips') or []
    except Exception:
        saved = []
    same = checked.expected['expected_exit_ips'][0] in saved
    return checked, {'status': Proxy.PROXY_CHECKED, 'same_exit': same, 'text': message('proxy_checked')}
