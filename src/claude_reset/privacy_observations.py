"""Summarize a selected historical relay journal without publishing destinations."""
import json
import re

from .windows_pin import PinnedFile


def summarize(path):
    """Read only; never start capture or contact a client."""
    result = {
        'schema': 1, 'collection': 'unavailable', 'source': 'selected_relay_journal',
        'live_client_verified': False, 'network_measured': False,
        'counts': {key: 0 for key in ('sentry', 'datadog', 'claude_domains', 'other')},
        'records': 0, 'rejected_records': 0,
        'payload_fields': {key: 'unknown' for key in
                           ('timezone', 'language', 'hardware', 'windows_username')},
        'note': 'Исторический журнал запросов к реле, не доказательство соединения или отправки. '
                'Принадлежность запросов Desktop не проверена. Прочие назначения не означают '
                'телеметрию; домены Claude также могут принимать телеметрию. Содержимое TLS '
                'не исследовано. Отсутствие записей не доказывает отсутствие канала. '
                'Имена узлов, пути, время и порты не экспортируются. Максимум файла — 64 КиБ.',
    }
    try:
        with PinnedFile(path, limit=65536) as source:
            lines = source.data.decode('utf-8').splitlines()
    except Exception:
        return result
    for line in lines:
        try:
            row = json.loads(line)
            if not isinstance(row, dict) or set(row) != {'t', 'host', 'port'}:
                raise ValueError()
            if type(row['t']) is not int or row['t'] < 0:
                raise ValueError()
            if type(row['port']) is not int or not 1 <= row['port'] <= 65535:
                raise ValueError()
            host = row['host']
            if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9.:_-]{1,253}', host):
                raise ValueError()
            host = host.lower().rstrip('.')
            category = 'other'
            for name, suffixes in (
                ('sentry', ('sentry.io',)), ('datadog', ('datadoghq.com',)),
                ('claude_domains', ('claude.ai', 'anthropic.com', 'claudeusercontent.com')),
            ):
                if any(host == suffix or host.endswith('.' + suffix) for suffix in suffixes):
                    category = name
                    break
            result['counts'][category] += 1
            result['records'] += 1
        except (ValueError, TypeError, KeyError):
            result['rejected_records'] += 1
    result['collection'] = ('partial' if result['rejected_records'] else
                            'complete' if result['records'] else 'empty')
    return result
