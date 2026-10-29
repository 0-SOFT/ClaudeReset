"""Read-only diagnostics with a closed public schema, using existing collectors."""
from datetime import datetime, timezone

from . import cleanup, l1_check
from .windows import inspect_windows
from .safeio import guarded
from .windows_pin import PinnedFile
import json


ADVICE = {
    'DE': ('W. Europe Standard Time', ('de-DE',), 'Германия: проверьте центральноевропейский пояс и язык de-DE.'),
    'TR': ('Turkey Standard Time', ('tr-TR',), 'Турция: проверьте пояс Турции и язык tr-TR.'),
    'GB': ('GMT Standard Time', ('en-GB',), 'Великобритания: проверьте местный пояс и язык en-GB.'),
}


def advise(country):
    """Country is explicitly supplied by the user, never inferred from an IP."""
    choice = ADVICE.get(country.strip().upper()) if isinstance(country, str) else None
    if choice is None:
        return {'status': 'unsupported', 'text': 'Для этой страны нет однозначного совета. Уточните регион выхода и сравните пояс и язык вручную.',
                'settings_changed': False, 'exit_country_verified': False}
    try:
        facts = inspect_windows()
        zone, languages, text = choice
        actual_zone = facts.get('timezone', {}).get('id')
        actual_language = facts.get('locale')
        if not isinstance(actual_zone, str) or not actual_zone or not isinstance(actual_language, str) or not actual_language:
            raise ValueError('Missing comparison facts')
        return {'status': 'compared', 'text': text,
                'timezone_matches': facts['timezone']['id'] == zone,
                'language_matches': facts['locale'] in languages,
                'settings_changed': False, 'exit_country_verified': False,
                'note': 'Страна указана вами, выход не измерялся. Сравнивается идентификатор пояса Windows, а не текущее смещение UTC. Язык — личный выбор; несовпадение не требует изменения системы, совпадение не доказывает приватность.'}
    except Exception:
        return {'status': 'unavailable', 'text': 'Не удалось прочитать пояс и язык Windows. Сравните их вручную.',
                'settings_changed': False, 'exit_country_verified': False}


def open_settings(kind):
    import os
    from .safeio import SafetyError
    uris = {'timezone': 'ms-settings:dateandtime', 'language': 'ms-settings:regionlanguage',
            'startup': 'ms-settings:startupapps'}
    if kind not in uris:
        raise SafetyError('Неизвестный раздел настроек')
    try:
        os.startfile(uris[kind])
    except Exception:
        raise SafetyError('Не удалось открыть настройки Windows') from None
    return {'opened': True, 'settings_changed': False}


LIMITATIONS = (
    'Наличие компонентов L1 не подтверждает действующую защиту или выход прокси.',
    'Проверяются только фиксированные файловые расположения; нулевой общий остаток не подтверждён.',
    'Cowork: неизвестные расположения и схемы VM не поддержаны; остановка с повышением остаётся отдельным шагом.',
    'Resolve для дочерних инструментов, источников восстановления и ошибок чтения остаётся ручным.',
    'Chrome/Edge: автоматическая очистка охватывает cookies и IndexedDB; общие хранилища и кэш требуют ручной проверки.',
    'Открытие настроек браузера не подтверждает удаление; portable, синхронизация и восстановление сессии не проверены.',
    'Ключи устройства, серверный отзыв, живое соединение и новый вход этим отчётом не проверяются.',
)


def operation_history(paths):
    """Read existing reset/wipe reports; never read private recovery journals."""
    labels = {
        'started': 'Начато; итог не записан',
        'failed_or_partial': 'Ошибка или частичное выполнение',
        'local_operations_completed_partial_coverage': 'Выбранные операции завершены; охват частичный',
        'fixed_locations_wiped': 'Записано завершение стирания фиксированных расположений',
    }
    result = {'schema': 1, 'collection': 'complete', 'rows': [], 'truncated': False,
              'live_result_verified': False,
              'note': 'Сохранённые отчёты сброса и стирания, не полный журнал всех действий. '
                      'Порядок не хронологический. Имена, пути и ошибки скрыты. '
                      'Запись не подтверждает текущее состояние и не разрешает повтор операции.'}
    try:
        root = guarded(paths.state / 'runs', paths.state)
        try:
            root.stat()
        except FileNotFoundError:
            return result
        for index, entry in enumerate(root.iterdir()):
            if index == 100:
                result.update(truncated=True, collection='partial')
                break
            row = {'position': index + 1, 'status': 'unavailable', 'text': 'Отчёт недоступен или схема неизвестна'}
            try:
                target = guarded(entry / 'result.json', paths.state)
                with PinnedFile(target, limit=65536) as source:
                    raw = json.loads(source.data)
                status = raw.get('status')
                if isinstance(status, str) and status in labels:
                    row.update(status=status, text=labels[status])
                else:
                    result['collection'] = 'partial'
            except Exception:
                result['collection'] = 'partial'
            result['rows'].append(row)
    except Exception:
        result['collection'] = 'unavailable'
    return result


def collect(paths):
    """Never export collector strings, paths, exception text or arbitrary keys."""
    report = {'schema': 1, 'observed_utc': datetime.now(timezone.utc).isoformat(),
              'network_measured': False, 'ready_for_new_account': False,
              'limitations': list(LIMITATIONS)}
    try:
        raw = l1_check.check(paths)
        state = raw.get('protection')
        report['protection'] = {
            'collection': 'complete' if state in ('installed', 'partial', 'not_installed') else 'unavailable',
            'components': state if state in ('installed', 'partial', 'not_installed') else 'unknown',
            'live_protection_verified': False,
        }
    except Exception:
        report['protection'] = {'collection': 'unavailable', 'components': 'unknown',
                                'live_protection_verified': False}
    try:
        raw = cleanup.audit(paths)
        rows = raw['rows']
        complete = (raw.get('complete') is True and bool(rows)
                    and all(r.get('status') in ('absent', 'present') for r in rows))
        report['files'] = {
            'collection': 'complete' if complete else 'partial',
            'present_locations': sum(r.get('status') == 'present' for r in rows),
            'unavailable_locations': sum(r.get('status') not in ('absent', 'present') for r in rows),
            'zero_fixed_file_remainder': complete and all(r['status'] == 'absent' for r in rows),
            'zero_total_remainder': False,
        }
    except Exception:
        report['files'] = {'collection': 'unavailable', 'zero_fixed_file_remainder': False,
                           'zero_total_remainder': False}
    report['collection_complete'] = all(report[k]['collection'] == 'complete'
                                        for k in ('protection', 'files'))
    return report
