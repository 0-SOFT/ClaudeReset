# Разработка ClaudeReset

## Окружение

Python 3.12 x64:

```
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

`requirements-lock.txt` — инструменты разработки и сборки; `requirements-runtime.txt` — только то, что программе нужно во время работы (это попадает в установщик).

## Тесты

```
cd src
..\.venv\Scripts\python.exe -m pytest -q -k "not abrupt_process_exit and not abrupt_checkpoint_exit"
```

Около 30 минут. Тесты создают временные профили, используют Windows DPAPI, скрытое окно Tk и тестовые junction; тесты символических ссылок пропускаются без соответствующего права Windows. Системные изменения (UAC, защита, стирание) в тестах подменены.

## Сборка установщика

```
.venv\Scripts\python.exe tools\build_bundle.py --out <пустая папка>
```

Получаются `ClaudeReset-<версия>-setup.exe` и `ClaudeReset-<версия>-windows-x64.zip`: переносимый CPython 3.12 с Tk (python-build-standalone, хеш в `packaging/bundle/python-lock.json`), пакеты из `requirements-runtime.txt`, программа, готовый контроллер защиты (собирается PyInstaller-ом и проверяется по манифесту при установке защиты), лаунчер с иконкой и манифест с SHA-256 всех файлов. Лаунчер и установщик компилируются компилятором C# из .NET Framework.

## Устройство

| Файл в `src/claude_reset` | Что делает |
|---|---|
| `shell.py` | Главное окно: два шага, тема, клавиатура |
| `reset_flow.py`, `cleanup.py`, `cleanup_actions.py` | Сброс: проверка, автоматическое устранение блокеров, стирание, аудит остатков |
| `proxy_flow.py`, `proxy_form.py`, `remote_backend.py` | Прокси: проверка, сохранение, состояние защиты |
| `l1_install.py`, `l1_check.py`, `l1_remove.py`, `protection_panel.py` | Защита L1: установка, проверка, снятие |
| `brand.py`, `ui_settings.py`, `markdown_view.py` | Фирменный стиль, тема, справка |
| `program_setup.py` | Установленная программа и её удаление |
| `public_view.py` | Очистка показываемых и сохраняемых данных от секретов |
| `app.py` | Режим для специалистов и командная строка |
