"""Narrow offline cleanup; shared browser stores are explicitly unverified."""
import re
import sqlite3
import os
from pathlib import Path
import subprocess

from .safeio import SafetyError, guarded, remove_owned, tree_entries
from .windows import ps_json

ROOTS = {'Chrome': 'Google/Chrome/User Data', 'Edge': 'Microsoft/Edge/User Data'}
ORIGIN_DIRS = ('IndexedDB/https_claude.ai_0.indexeddb.leveldb',
               'IndexedDB/https_claude.ai_0.indexeddb.blob')
COOKIE_MATCH = "host_key IN ('claude.ai', '.claude.ai') OR host_key LIKE '%.claude.ai'"


def manual_cleanup_profiles(paths):
    """Public ordinal list; never expose profile names or stored content."""
    return [{'browser': browser, 'profile_number': number}
            for number, (browser, _) in enumerate(profiles(paths), 1)]


def open_site_settings(paths, profile_number, *, launch=subprocess.Popen, environ=None):
    """Open a selected standard profile; deletion stays with the person."""
    selected = profiles(paths)
    if type(profile_number) is not int or not 1 <= profile_number <= len(selected):
        raise SafetyError('Выберите существующий номер профиля из нового списка.')
    browser, profile = selected[profile_number - 1]
    env = os.environ if environ is None else environ
    relative = ('Google/Chrome/Application/chrome.exe' if browser == 'Chrome'
                else 'Microsoft/Edge/Application/msedge.exe')
    roots = [paths.local] + [Path(env[key]) for key in ('ProgramFiles', 'ProgramFiles(x86)') if env.get(key)]
    executable = next((root / relative for root in roots if (root / relative).is_file()), None)
    if executable is None:
        raise SafetyError('Стандартная установка браузера не найдена. Откройте настройки нужного профиля вручную.')
    try:
        launch([str(executable), '--profile-directory=' + profile.name,
                ('chrome' if browser == 'Chrome' else 'edge') + '://settings/'],
               shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        raise SafetyError('Не удалось открыть настройки браузера. Выполните ручной шаг в нужном профиле.') from None
    return {'status': 'manual_action_required', 'browser': browser,
            'profile_number': profile_number, 'all_site_data_verified_absent': False,
            'ready_for_new_account': False,
            'steps': [
                'Проверьте выбранный профиль в открытом окне браузера.',
                'Закройте вкладки claude.ai, включая закреплённые, чтобы они не восстановили данные и Session Storage.',
                'В настройках откройте данные и разрешения сайтов; найдите claude.ai.',
                'Удалите данные только claude.ai и его поддоменов. Не выбирайте удаление всех сайтов или профиля.',
                'Проверьте список сайтов повторно. Штатное удаление данных сайта предназначено также для Local Storage и Service Worker.',
                'Закройте браузер штатно. Не восстанавливайте старые вкладки Claude при следующем запуске.',
            ],
            'unsupported': [
                'Автоматическое удаление и независимая проверка Local Storage, Session Storage, Service Worker и Cache Storage не реализованы.',
                'Выборочная очистка общего HTTP/Code/GPU-кэша не поддержана; общий кэш не удаляется ради сохранности чужих сайтов.',
                'Нестандартные профили, переносные браузеры, синхронизация и восстановление сессии не проверены.',
            ]}


def browsers_running():
    return ps_json("@(Get-Process -Name chrome,msedge -ErrorAction SilentlyContinue).Count | ConvertTo-Json") != 0


def profiles(paths):
    result = []
    for browser, relative in ROOTS.items():
        root = guarded(paths.local / relative, paths.local)
        if root.exists():
            for child in sorted(root.iterdir()):
                if re.fullmatch(r'Default|Profile [0-9]+', child.name):
                    guarded(child, paths.local)
                    if child.is_dir():
                        result.append((browser, child))
    return result


def _database(path, root):
    guarded(path, root)
    for suffix in ('-wal', '-shm', '-journal'):
        guarded(path.with_name(path.name + suffix), root)
    return sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=0)


def site_data(paths, *, erase=False, confirmation='', inspect=browsers_running):
    if erase and confirmation != 'СТЕРЕТЬ':
        raise SafetyError('Для удаления данных сайтов введите СТЕРЕТЬ.')
    try:
        if inspect():
            raise SafetyError('Закройте Chrome и Edge самостоятельно и повторите проверку.')
        rows = []
        for browser, profile in profiles(paths):
            cookies = removed = 0
            directories = [guarded(profile / name, paths.local) for name in ORIGIN_DIRS]
            for directory in directories:
                list(tree_entries(directory, paths.local))
            for relative in ('Network/Cookies', 'Cookies'):
                database = guarded(profile / relative, paths.local)
                if not database.exists():
                    continue
                connection = _database(database, paths.local)
                try:
                    with connection:
                        connection.execute('BEGIN IMMEDIATE' if erase else 'BEGIN')
                        count = connection.execute('SELECT count(*) FROM cookies WHERE ' + COOKIE_MATCH).fetchone()[0]
                        cookies += count
                        if erase:
                            connection.execute('DELETE FROM cookies WHERE ' + COOKIE_MATCH)
                            if connection.execute('SELECT count(*) FROM cookies WHERE ' + COOKIE_MATCH).fetchone()[0]:
                                raise SafetyError('Не удалось проверить удаление cookies.')
                            removed += count
                finally:
                    connection.close()
            found = sum(directory.exists() for directory in directories)
            if erase:
                for directory in directories:
                    remove_owned(directory, paths.local)
            rows.append({'browser': browser, 'profile_number': len(rows) + 1,
                         'cookies_found': cookies, 'cookies_removed': removed,
                         'origin_directories_found': found,
                         'origin_directories_remaining': sum(p.exists() for p in directories)})
        return {'status': 'supported_data_removed' if erase else 'preview', 'profiles': rows,
                'profiles_preserved': True, 'all_site_data_verified_absent': False,
                'remaining': ['Общие Local Storage, Session Storage, Service Worker и кэш требуют удаления данных claude.ai в настройках браузера.',
                              'Нестандартные каталоги профилей и синхронизация не проверены.'],
                'ready_for_new_account': False}
    except SafetyError:
        raise
    except Exception:
        raise SafetyError('Данные сайтов недоступны или схема не поддержана. Возможен частичный результат; повторите предпросмотр.') from None


def external_scope_report():
    """Do not traverse projects or invoke remote runtimes for cleanup."""
    return {'mode': 'report_only', 'changed': False,
            'areas': [{'area': name, 'status': 'not_inspected', 'action': 'Проверить вручную; автоматическое удаление исключено.'}
                      for name in ('Проекты', 'Переменные среды', 'WSL', 'Docker', 'SSH')]}
