"""Thin GUI adapter for L1. Public results contain only fixed vocabulary."""
from types import MappingProxyType

from ..model.status import Check, Protection
from ..services import protection

__all__ = ['LIMITS', 'RESULTS', 'limits', 'perform', 'result', 'status']


LIMITS = MappingProxyType({
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
})
RESULTS = MappingProxyType({
    Protection.EXTENSION_EXCLUSION_FAILED: 'Исключение расширения не завершено. Контроллер остановлен; нужна сверка фильтров и настроек.',
    Protection.EXTENSION_CHOICE_REQUIRED: 'Сначала выберите область расширения.',
    Protection.EXTENSION_PROXY_FAILED: 'Настройки расширения не применены. Контроллер остановлен; нужна проверка.',
    Protection.PROXY_CONFIRMATION_REQUIRED: 'Сначала проверьте прокси и подтвердите новый выход.',
    Protection.INSTALLED: 'Установка L1 завершена. Полная изоляция не подтверждена.',
    Protection.INSTALLED_NEEDS_ATTENTION: 'Установка частичная: требуется проверка состояния.',
    Protection.RESTARTED: 'Контроллер перезапущен, новое реле подтверждено.',
    Protection.REMOVED: 'Удаление защиты завершено.',
    Protection.REMOVED_WITH_LEFTOVERS: 'Удаление завершено с остатками. Нужна проверка.',
    Protection.NOT_INSTALLED: 'Контроллер не установлен.',
    Protection.NEEDS_BACKEND: 'Сначала настройте прокси на вкладке «Соединение».',
    Protection.NEEDS_CONNECTION_PROFILE: 'Сначала проверьте и сохраните ожидаемый выход.',
    Protection.NEEDS_CONSENT: 'Необходимо согласие на границы L1.',
    Protection.BLOCKED: 'Предусловия установки не выполнены. Обновите состояние.',
    Protection.CONTROLLER_NOT_STOPPED: 'Остановка контроллера не подтверждена.',
    Protection.RELAY_NOT_OPEN: 'Реле не открылось. Клиенты могут оставаться без сети.',
    Protection.START_FAILED: 'Контроллер не запустился. Клиенты могут оставаться без сети.',
    Protection.RECONCILE_REQUIRED: 'Исход не подтверждён. Требуется сверка; повтор запрещён.',
    Protection.PENDING_ELEVATION: 'Предыдущий запрос Windows не завершён. Требуется сверка.',
    Protection.PACKAGE_FAILED: 'Пакет изоляции не зарегистрирован. Установка остановлена; проверьте состояние.',
    Protection.AUTOSTART_FAILED: 'Автозапуск контроллера не установлен. Установка остановлена; проверьте состояние.',
    Protection.AUTOSTART_NOT_REMOVED: 'Автозапуск контроллера не удалён. Удаление остановлено; проверьте состояние.',
    Protection.FILTERS_NOT_REMOVED: 'Фильтры защиты не удалены. Удаление остановлено; клиенты могут оставаться без сети.',
    Protection.BACKEND_NOT_REMOVED: 'Локальный прокси не удалён. Удаление остановлено; проверьте состояние.',
    Protection.PACKAGE_NOT_REMOVED: 'Пакет изоляции не удалён. Удаление остановлено; проверьте состояние.',
    Protection.CONNECTION_PROFILE_NOT_REMOVED: 'Сохранённый ожидаемый выход не удалён. Удаление остановлено; проверьте состояние.',
})


def limits(paths, *, l1=protection.L1()):
    names = protection.open_boundaries(paths, l1=l1)
    return {'known': all(n in LIMITS for n in names),
            'lines': [LIMITS.get(n, 'Новая неизвестная граница: установка из окна недоступна.') for n in names]}


def status(paths, *, l1=protection.L1()):
    found = protection.details(paths, l1=l1)
    saved, checks = found.last_report, found.parts
    def part(key):
        return {Check.OK: 'обнаружено', Check.MISSING: 'не обнаружено', Check.INFO: 'не требуется'}.get(checks.get(key), 'не подтверждено')
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
    if found.can_install is not True:
        rows.append('Установка: предусловия не подтверждены. Требуется диагностика.')
    return {'text': '\n'.join(rows)}


def result(report):
    """The words for how a protection action ended (services.protection.ActionResult)."""
    text = RESULTS.get(report.status, 'Операция не завершена полностью. Обновите состояние; проверьте журнал операции.')
    if report.extension_protection == 'excluded':
        text += '\nУстановленные бинарники расширения исключены. Фильтры удалённых версий требуют отдельной проверки.'
    if report.profile_saved:
        text += '\nНовый профиль сохранён DPAPI. Это само по себе не подтверждает работу реле.'
    if report.retry_blocked:
        text += '\nПовтор запрещён до сверки незавершённой операции.'
    seconds = report.seconds_without_relay
    if type(seconds) in (int, float) and 0 <= seconds < 86400:
        text += f'\nВремя без реле: {seconds} с.'
    return {'text': text}


def perform(paths, action, *, confirmed=False, protect_extension=None, proxy_draft=None, l1=protection.L1()):
    """Run a protection action the person confirmed in the window, and word its result."""
    if not confirmed:
        return {'text': 'Действие отменено. Изменения не выполнялись.'}
    if action in ('install', 'reinstall') and not limits(paths, l1=l1)['known']:
        return {'text': 'Список границ изменился. Установка из окна недоступна.'}
    return result(protection.run_action(paths, action, protect_extension=protect_extension, proxy_draft=proxy_draft,
                                        l1=l1))
