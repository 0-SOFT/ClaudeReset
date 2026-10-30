## ClaudeReset 1.1.2

**English**

- Fixed: removing ClaudeReset from the program itself (Help → "Uninstall ClaudeReset", or Settings → Apps → ClaudeReset → Uninstall) stopped with an error in 1.1.0 and 1.1.1. It now switches the protection off first and removes the program as described.
- The specialist window no longer has the checks of the old 0.3 local guard, and the command line no longer has `--network-guard-probe`, `--network-guard-filters` and `--network-guard-launch`. `--network-guard-status` stays.
- The licence notes in the window no longer list Sandboxie: it was never part of the installer, and its integration code has left the repository.
- For developers: the code is easier to read and to fork — the windows are split into page and tab modules, the scenarios return typed results, dependencies come in one way, `ruff` and a Windows CI check every change, and there are CONTRIBUTING.md, SECURITY.md and an English developer guide (`docs/DEVELOPMENT.en.md`).

Download `ClaudeReset-1.1.2-setup.exe` (installer, no administrator rights) or `ClaudeReset-1.1.2-windows-x64.zip` (no installation). The installer is not signed: Windows shows "Windows protected your PC" — click "More info" → "Run anyway". The program is checked by automated tests; reset and protection have not been run on users' computers.

**Русский**

- Исправлено: удаление ClaudeReset из самой программы («Помощь» → «Удалить ClaudeReset» или «Параметры» → «Приложения» → ClaudeReset → «Удалить») в 1.1.0 и 1.1.1 останавливалось с ошибкой. Теперь программа сначала выключает защиту и удаляется, как описано.
- В окне для специалистов больше нет проверок прежней локальной защиты версий 0.3, а в командной строке — `--network-guard-probe`, `--network-guard-filters` и `--network-guard-launch`. `--network-guard-status` остаётся.
- Лицензионные уведомления в окне больше не называют Sandboxie: он никогда не входил в установщик, а код интеграции с ним ушёл из репозитория.
- Для разработчиков: код проще читать и форкать — окна разделены на модули страниц и вкладок, сценарии возвращают типизированные результаты, зависимости передаются одним способом, каждое изменение проверяют `ruff` и CI на Windows, есть CONTRIBUTING.md, SECURITY.md и руководство разработчика на английском (`docs/DEVELOPMENT.en.md`).

Скачайте `ClaudeReset-1.1.2-setup.exe` (установщик, права администратора не нужны) или `ClaudeReset-1.1.2-windows-x64.zip` (без установки). Установщик не подписан: Windows покажет «Windows защитила ваш компьютер» — «Подробнее» → «Выполнить в любом случае». Программа проверена автоматическими тестами; на компьютерах пользователей сброс и защита не проверялись.
