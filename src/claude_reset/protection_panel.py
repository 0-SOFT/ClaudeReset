"""Thin GUI adapter for L1. Public results contain only fixed vocabulary."""
from . import l1_check, l1_install, l1_remove, strict_guard


LIMITS = {
    'controller_lifetime_lease': 'Срок жизни контроллера не обеспечивает полную изоляцию.',
    'complete_ipc_boundary': 'Не все обращения через другие процессы изолированы.',
    'control_files_and_broker_integrity': 'Целостность управляющих файлов и посредников ограничена.',
    'working_client_compatibility': 'Совместимость всех рабочих клиентов не подтверждена.',
    'cowork_guest_boundary': 'Гостевая среда Cowork не покрыта L1.',
    'local_network_metadata': 'Локальные сетевые сведения не скрыты полностью.',
    'helper_process_thread_access': 'Доступ к процессам и потокам помощников не изолирован полностью.',
    'helper_bootstrap_before_execution': 'Изоляция помощников до начала выполнения не подтверждена.',
    'helper_token_integrity': 'Целостность токенов помощников не подтверждена.',
    'dns_service_delegation': 'DNS через системную службу Windows не изолирован полностью.',
}
RESULTS = {
    'extension_exclusion_failed': 'Исключение расширения не завершено. Контроллер остановлен; нужна сверка фильтров и настроек.',
    'extension_choice_required': 'Сначала выберите область расширения.',
    'extension_proxy_failed': 'Настройки расширения не применены. Контроллер остановлен; нужна проверка.',
    'proxy_confirmation_required': 'Сначала проверьте прокси и подтвердите новый выход.',
    'installed': 'Установка L1 завершена. Полная изоляция не подтверждена.',
    'installed_needs_attention': 'Установка частичная: требуется проверка состояния.',
    'restarted': 'Контроллер перезапущен, новое реле подтверждено.',
    'removed': 'Удаление защиты завершено.',
    'removed_with_leftovers': 'Удаление завершено с остатками. Нужна проверка.',
    'not_installed': 'Контроллер не установлен.',
    'needs_backend': 'Сначала настройте прокси на вкладке «Соединение».',
    'needs_connection_profile': 'Сначала проверьте и сохраните ожидаемый выход.',
    'needs_consent': 'Необходимо согласие на границы L1.',
    'blocked': 'Предусловия установки не выполнены. Обновите состояние.',
    'controller_not_stopped': 'Остановка контроллера не подтверждена.',
    'relay_not_open': 'Реле не открылось. Клиенты могут оставаться без сети.',
    'start_failed': 'Контроллер не запустился. Клиенты могут оставаться без сети.',
    'reconcile_required': 'Исход не подтверждён. Требуется сверка; повтор запрещён.',
    'pending_elevation': 'Предыдущий запрос Windows не завершён. Требуется сверка.',
}


def limits(paths):
    names = strict_guard.l1_accept(paths, False)['open_boundaries']
    return {'known': all(n in LIMITS for n in names),
            'lines': [LIMITS.get(n, 'Новая неизвестная граница: установка из окна недоступна.') for n in names]}


def status(paths):
    fresh = l1_check.check(paths)
    saved = strict_guard.status(paths).get('last_report') or {}
    checks = {c['id']: c['status'] for c in fresh.get('checks', [])}
    def part(key):
        return {'ok': 'обнаружено', 'missing': 'не обнаружено', 'info': 'не требуется'}.get(checks.get(key), 'не подтверждено')
    rows = [f'Контроллер (задача): {part("controller_task")}',
            f'Реле (слушатель): {part("relay_listening")}',
            f'Профиль прокси: {part("backend_task")}',
            f'Ожидаемый выход (профиль): {part("connection_profile")}',
            f'Desktop: {part("client_desktop")}',
            f'CLI: {part("client_standalone_cli")}',
            f'Расширение VS Code: {part("client_vscode_extension")}']
    old = saved.get('state')
    rows.append('Тип прокси в последнем отчёте (исторический): ' + {
        'remote_http': 'HTTP CONNECT',
        'remote_socks5': 'SOCKS5',
    }.get(saved.get('backend'), 'не установлен'))
    rows.append('Последний отчёт контроллера (исторический): ' + {
        'relay_open': 'реле было открыто',
        'blocked_controller_stopped': 'контроллер был остановлен',
    }.get(old, 'нет подтверждённого состояния'))
    rows.append('Наличие компонентов и старый отчёт не подтверждают текущую защиту или выход.')
    rows.append('Причина последней остановки: ' + {
        'exit_mismatch': 'выход не совпал с ожидаемым',
        'proxy_unreachable': 'прокси недоступен',
        'exit_probe_failed': 'не удалось измерить выход после повторных проверок',
        'monitor_error': 'ошибка наблюдения за соединением',
        'close_requested': 'запрошена остановка',
        'profile_changed': 'профиль соединения изменён',
        'backend_changed': 'backend изменён или остановлен',
        'backend_config_failed': 'проверка конфигурации backend не пройдена',
        'exception': 'ошибка контроллера',
    }.get(saved.get('stop_reason'), 'не установлена'))
    if fresh.get('can_install') is not True:
        rows.append('Установка: предусловия не подтверждены. Требуется диагностика.')
    return {'text': '\n'.join(rows)}


def result(report):
    text = RESULTS.get(report.get('status'), 'Операция не завершена полностью. Обновите состояние; проверьте журнал операции.')
    if report.get('extension_protection') == 'excluded':
        text += '\nУстановленные бинарники расширения исключены. Фильтры удалённых версий требуют отдельной проверки.'
    if report.get('profile_saved'):
        text += '\nНовый профиль сохранён DPAPI. Это само по себе не подтверждает работу реле.'
    if report.get('retry_blocked'):
        text += '\nПовтор запрещён до сверки незавершённой операции.'
    seconds = report.get('seconds_without_relay')
    if type(seconds) in (int, float) and 0 <= seconds < 86400:
        text += f'\nВремя без реле: {seconds} с.'
    return {'text': text}


def perform(paths, action, *, confirmed=False, protect_extension=None, proxy_draft=None):
    if not confirmed:
        return {'text': 'Действие отменено. Изменения не выполнялись.'}
    if action in ('install', 'reinstall'):
        if not limits(paths)['known']:
            return {'text': 'Список границ изменился. Установка из окна недоступна.'}
        report = l1_install.run(paths, confirmed=True, protect_extension=protect_extension,
                                reinstall_controller=action == 'reinstall')
    elif action == 'restart':
        report = l1_install.restart(paths)
    elif action == 'change_proxy':
        if proxy_draft is None or proxy_draft.expected is None:
            return result({'status': 'proxy_confirmation_required'})
        report = l1_install.restart(paths, proxy_draft=proxy_draft)
    elif action == 'extension':
        if protect_extension is None:
            return result({'status': 'extension_choice_required'})
        report = l1_install.restart(paths, protect_extension=protect_extension)
    elif action == 'remove':
        report = l1_remove.run(paths)
    else:
        raise ValueError('Unknown protection action')
    return result(report)

def check_saved_proxy(paths):
    """Return a private draft separately from the fixed public outcome."""
    from . import remote_backend
    from .proxy_form import ProxyDraft
    try:
        profile = remote_backend.load(paths)
        if profile is None:
            from .proxy_form import LocalBackendDraft
            draft = LocalBackendDraft(paths)
            return draft, draft.check()
        draft = ProxyDraft(**{k: profile[k] for k in ('host', 'port', 'username', 'password')},
                           proxy_type='http' if profile.get('adapter') == remote_backend.HTTP_ADAPTER else 'socks5')
        return draft, draft.check()
    except Exception:
        return None, {'status': 'proxy_check_failed'}
