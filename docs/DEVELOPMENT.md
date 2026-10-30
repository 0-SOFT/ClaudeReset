# Разработка ClaudeReset

[English](DEVELOPMENT.en.md) · **Русский**

## Окружение

Python 3.12 x64:

```
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

`requirements-lock.txt` — инструменты разработки и сборки; `requirements-runtime.txt` — только то, что программе нужно во время работы (это попадает в установщик).

## Тесты

```
.venv\Scripts\python.exe -m ruff check src tools packaging
cd src
..\.venv\Scripts\python.exe -m pytest -q
```

Около двух-трёх минут. Тесты создают временные профили, используют Windows DPAPI, скрытое окно Tk и тестовые junction; без права Windows на символические ссылки тесты ссылок пропускаются (2 теста). `ruff` (правила — `ruff.toml`) проверяет порядок и использование импортов и неопределённые имена; его же запускает храповик. Системные изменения (UAC, защита, стирание) в тестах подменены; тесты `abrupt_*` обрывают свой дочерний процесс посреди сброса временного профиля и проверяют восстановление. Запускать из `src`: из корня репозитория тесты с дочерними процессами падают.

## Сборка установщика

```
.venv\Scripts\python.exe tools\build_bundle.py --out <пустая папка>
```

Получаются `ClaudeReset-<версия>-setup.exe` и `ClaudeReset-<версия>-windows-x64.zip`: переносимый CPython 3.12 с Tk (python-build-standalone, хеш в `packaging/bundle/python-lock.json`), пакеты из `requirements-runtime.txt`, программа, готовый контроллер защиты (собирается PyInstaller-ом и проверяется по манифесту при установке защиты), лаунчер с иконкой и манифест с SHA-256 всех файлов. Лаунчер и установщик компилируются компилятором C# из .NET Framework.

## Устройство пакета

`src/claude_reset` разделён на слои. Модуль импортирует только свой слой и нижние; храповик проверяет это
(`layer_violations` = 0) и отсутствие циклов импорта.

| Слой | Пакеты | Что там |
|---|---|---|
| 0 | `errors`, `config` | Исключения; неизменяемые константы продукта (имена задач, порты, пакеты) |
| 1 | `windows`, `safeio` | Вся работа с ОС: DLL через `windows/api.Library` (прототип каждой функции объявлен один раз), процессы — `windows/process`, PowerShell — `windows/powershell`, реестр, планировщик, WFP, DPAPI; безопасные пути и атомарная запись |
| 2 | `model`, `layout` | Типы и статусы (`Enum`, `dataclass`), идентификаторы и время (`model/ids`), строгий разбор JSON; места файлов (`Paths`) |
| 3 | `reset`, `network`, `backend`, `privacy`, `elevation` | Области: сброс и стирание; прокси, контроллер L1 и его установка; локальный backend; наблюдения приватности; запросы UAC с долговременной заявкой |
| 4 | `services` | Сценарии для окон и командной строки: сброс, прокси, защита, диагностика, установка программы |
| 5 | `ui`, `cli` | Главное окно: рамка `ui/shell.py` (тема, меню, переключение страниц, фоновая работа, вопросы) и страницы `ui/pages/` — `home.py`, `reset.py`, `proxy.py`, `help.py`; окно для специалистов (`--expert`): `ui/expert_window.py` и вкладки `ui/expert/` — `wizard.py` (мастер и серверные действия), `analysis.py`, `cleanup.py`, `settings.py` (пояс, сеть и память), `protection.py` (сетевая и Windows-защита), `connection.py`, `policy.py`, `diagnostics.py`; тексты окна (`ui/text`), командная строка (`cli.py`) |

Правила:

- `ctypes`, `winreg` и `subprocess` импортируются только в `windows/`; новую функцию DLL сначала объявляют в
  таблице прототипов, потом вызывают через `Library`.
- Константы модулей неизменяемы (`MappingProxyType`, `frozenset`, `tuple`), `global` не используется.
- Слова для человека живут в `ui/text`; области возвращают статусы (`model/status`) и заметки (`model/notes`).
- Одна инструкция в строке; в модулях, переписанных заново, строки не длиннее 120 символов.

## Где что лежит

Пути относительно `src/claude_reset`. Окно вызывает сценарий, сценарий — модули областей, области — платформу.

| Что меняете | Окно | Сценарий | Логика | Windows |
|---|---|---|---|---|
| Шаг 1 · Сброс | `ui/pages/reset.py`, `ui/reset_flow.py`; у специалиста — `ui/expert/analysis.py`, `cleanup.py` | `services/reset.py` | `reset/cleanup.py` → `reset/execution.py` (журнал, восстановление) → `reset/planner.py`, `reset/discovery.py`; память — `reset/memory.py`; отдельные области — `reset/cowork.py`, `desktop_keys.py`, `browser_sites.py`, `customizations.py` | `windows/inventory.py` (процессы и настройки запуска), `dpapi.py`, `cng.py`, `cleanup_actions.py` |
| Шаг 2 · Прокси | `ui/pages/proxy.py`, `ui/proxy_flow.py`; у специалиста — `ui/expert/connection.py` | `services/proxy.py` | `network/connections.py`, `probe.py`, `remote_backend.py`, `tunnel_transport.py` | — |
| Защита L1: проверка, включение, снятие | карточка защиты — `ui/pages/proxy.py`, `ui/protection_panel.py`; у специалиста — `ui/expert/protection.py` | `services/protection.py` | `network/l1_check.py`, `l1_install.py`, `l1_remove.py`, `l1_consent.py`; контроллер — `controller.py`, `gate_rules.py`, `strict_wfp.py`, `relay.py`, `autostart.py` | `windows/wfp_session.py`, `wfp.py`, `tasks.py` |
| Запросы UAC | — | — | `elevation/request.py`, `claims.py`, `launch.py` | `windows/runas.py`, `mutex.py` |
| Установленная программа и удаление | `ui/pages/help.py` (Помощь) | `services/program_setup.py` | — | `windows/registry.py` |
| Тексты, язык, тема | `ui/text/ru.py`, `ui/text/en.py`, `ui/brand.py`, `ui/settings.py`; стили темы — `Theme` в `ui/shell.py`, выбор — `ui/pages/help.py` | — | — | `windows/display.py` |
| Режим специалиста, командная строка | `ui/expert_window.py` (окно), вкладки — `ui/expert/`; `cli.py` | — | — | — |

Имена файлов и папок программы и клиентов — `layout.py`, общие константы (порты, задачи, пакеты) — `config.py`,
статусы и формы документов — `model/`.

## Словарь

- **L1** — защита: правила WFP пускают процессы Claude в сеть только через локальный relay, а relay — через прокси
  пользователя. Её **контроллер** (`network/controller.py`) — один процесс с правами администратора. Во флагах командной
  строки и в папке состояния контроллер исторически называется **strict guard** (`--strict-guard-*`,
  `layout.CONTROLLER = 'strict-guard'`): эти имена записаны на установленных ПК и не меняются.
- **Backend** — локальный движок туннеля (sing-box для VLESS) или удалённый прокси (`network/remote_backend.py`), к
  которому relay выходит в интернет.
- **Сброс** — план (`reset/planner.py`), его выполнение с журналом (`reset/execution.py`) и стирание фиксированных мест
  (`reset/cleanup.py`); **память** — файлы CLAUDE.md, которые сброс сохраняет и возвращает (`reset/memory.py`).
- **Заявка** (claim) — долговременная запись о шаге с правами администратора (`elevation/claims.py`): пока она не
  закрыта, другое изменение защиты не начнётся.
- `safeio.guarded` — проверка пути внутри разрешённого корня, а не сетевая защита.

## Инструменты

В `tools/` четыре файла (`tools/README.md`): сборка установщика `build_bundle.py`, показатели архитектуры
`architecture_metrics.py` и две части программы, которые установленные ПК запускают по этому пути —
`vscode_claude_proxy.py` и `l1_recovery_watch.py`.

## Тесты и зависимости

Тест не подменяет функцию пакета. Зависимость, которую нужно заменить (PowerShell, планировщик, DLL, сеть, окно
диалога, область программы), приходит параметром по ключу, значение которого по умолчанию — настоящая функция или
объект, указанные в сигнатуре (`run=powershell.run`); класс получает их в `__init__`, не атрибутами класса. `None`
по умолчанию остаётся, только когда настоящего значения ещё нет при определении функции (оно зависит от другого
аргумента, читается или создаётся при каждом вызове), и на строке параметра сказано почему: `# None: <причина>`.
Подсистема, которую тесты заменяют целиком, — класс-порт (`Probe`, `protection.L1`, `reset.Actions`, `Dialogs`,
`Desktop`, `Deps`). Тест передаёт своего двойника. Двойники — `tests/scripted.py` (`Scripted` отвечает по таблице и
записывает вызовы; `Strict` отвергает вызов, на который у него нет ответа), `tests/dialog_fakes.py`,
`tests/proxy_fakes.py`, `tests/wfp_fakes.py`; командная строка получает папки теста через переменные окружения
(`tests/cli_env.py`). DPAPI в тестах настоящий, текущего пользователя. `monkeypatch` остаётся для времени,
окружения и библиотек; тесты не обращаются к именам пакета, начинающимся с `_`.

`tests/test_live_contracts.py` с `tests/golden/live_contracts.json` закрепляет то, от чего зависят уже установленные
компьютеры: параметры командной строки, ключи фильтров WFP, форматы сохранённых документов. Менять их только
намеренно (`UPDATE_LIVE_CONTRACTS=1`).

## Показатели архитектуры

```
.venv\Scripts\python.exe tools\architecture_metrics.py --root .
.venv\Scripts\python.exe tools\architecture_metrics.py --root . --details
```

Первая команда печатает показатели (циклы, нарушения слоёв, модули с вызовами ОС, сложность, длинные строки,
клоны, подмены в тестах, объём кода), вторая — ещё и список мест. `src/tests/test_architecture.py` — храповик:
для каждого показателя записан предел, и тест падает, если показатель стал хуже. Когда показатель улучшился,
предел снижают в том же коммите. Окно — рамка, которая собирает страницы и вкладки: модуль не длиннее 800 строк
(`modules_over_800_lines`), класс — не больше 30 методов (`largest_class_methods`).

## Форк

- **Имена.** Собственные имена продукта — в `config.py` (задачи, пакеты, службы, порты) и `layout.py` (папки).
  Имена, которые уже есть на установленных компьютерах, для этого продукта неизменны; форку, который ставится рядом,
  нужны свои. Пакет идентичности описан `packaging/identity/AppxManifest.xml` (и `IdentityStub.cs`); `identity.msix`
  и `identity-stub.exe` собраны из них `makeappx` из Windows SDK, их SHA-256 закреплены в
  `network/package_isolation.py`. Издатель, папка и запись удаления установщика — в
  `packaging/bundle/ClaudeResetSetup.cs`; фирменный стиль — `ui/brand.py`.
- **Лицензии.** Собственный код ClaudeReset — MIT. В установщик и переносимый архив входят dissect.hypervisor и
  dissect.extfs под AGPL-3.0-or-later, поэтому тот, кто распространяет установщик из форка, обязан предоставить полный
  соответствующий исходный код этого форка. Подробности —
  `third_party/NOTICES.md`.
- **Платформа.** Программа только для Windows намеренно: WFP, DPAPI, CNG, MSIX, планировщик и UAC — её рабочие
  инструменты, а не случайные зависимости.
