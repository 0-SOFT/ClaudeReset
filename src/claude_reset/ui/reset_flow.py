"""What the one-button reset says: the blockers, the names and sizes of the locations. The reset is services.reset."""
from types import MappingProxyType

__all__ = ['BLOCKERS', 'LABELS', 'UNKNOWN_BLOCKER', 'shown', 'size_text']

# What the window says about each blocker (services.reset.BLOCKER_KINDS says who resolves it).
BLOCKERS = MappingProxyType({
    'processes': 'Закроет Claude Desktop и Claude Code.',
    'vscode': 'Открыт VS Code: в нём работает Claude Code. Сохраните файлы и закройте все окна VS Code.',
    'claude_running': 'Claude не закрылся сам. Закройте Claude Desktop, в том числе значок у часов.',
    'cowork_service': 'Остановит службу Cowork.',
    'cowork_export': 'Сохранит копию вашей работы в Cowork.',
    'extra_entries': 'Сохранит копию ваших команд, агентов и настроек Claude Code.',
    'unlisted_version': 'Эта версия Claude ещё не проверялась с программой.',
    'restore_sources': 'В автозагрузке Windows есть программа, которая снова запустит Claude. Отключите её в '
                       '«Автозагрузке».',
    'inventory': 'Не удалось прочитать часть папок Claude. Откройте «Режим для специалистов» → «Очистка».',
    'cowork_location': 'Работа Cowork лежит в непроверенном месте. Нужен «Режим для специалистов».',
})
LABELS = MappingProxyType({
    'Desktop MSIX': 'Claude Desktop: программа из Microsoft Store',
    'Desktop': 'Claude Desktop: вход, история, настройки',
    'Desktop 3p': 'Claude Desktop: подключения',
    'Claude Code': 'Claude Code: история, проекты, память',
    'Code config': 'Claude Code: файл настроек',
    'Extension storage': 'Claude Code в VS Code',
    'Desktop / Cowork data': 'Claude Desktop и Cowork: данные',
    'Code config backup': 'Claude Code: резервные копии настроек',
})
UNKNOWN_BLOCKER = 'Нужна проверка в «Режиме для специалистов».'


def size_text(count):
    for unit, factor in (('ГБ', 1024 ** 3), ('МБ', 1024 ** 2), ('КБ', 1024)):
        if count >= factor:
            return f'{count / factor:.1f} {unit}'.replace('.', ',')
    return f'{count} Б'


def shown(result):
    """A check result (services.reset.CheckResult) with what the window shows: location names and sizes, and the
    text of each blocker."""
    shown = result.to_json()
    shown['rows'] = [{'label': LABELS.get(r.label, r.label), 'size': size_text(r.bytes), 'status': r.status}
                     for r in result.rows]
    shown['total'] = size_text(result.total_bytes)
    shown['blockers'] = [dict(b.to_json(), text=BLOCKERS.get(b.key, UNKNOWN_BLOCKER)) for b in result.blockers]
    return shown
