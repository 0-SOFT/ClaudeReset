## ClaudeReset 1.1.1

**English**

- Fixed: when two parts of ClaudeReset created the program's folder at the same moment (for example, the window and the protection controller on the first start), one of them could stop with "Resolved target is outside the approved root". Windows sometimes reports such a folder in its long form (`\\?\C:\…`) while it is being created; the path check now compares both forms the same way. Paths outside the program's folders are still refused.

Download `ClaudeReset-1.1.1-setup.exe` (installer, no administrator rights) or `ClaudeReset-1.1.1-windows-x64.zip` (no installation). The installer is not signed: Windows shows "Windows protected your PC" — click "More info" → "Run anyway". The program is checked by automated tests; reset and protection have not been run on users' computers.

**Русский**

- Исправлено: если две части ClaudeReset одновременно создавали папку программы (например, окно и контроллер защиты при первом запуске), одна из них могла остановиться с ошибкой «Resolved target is outside the approved root». Пока папка создаётся, Windows иногда называет её в длинной форме (`\\?\C:\…`); проверка путей теперь сравнивает обе формы одинаково. Пути вне папок программы по-прежнему отвергаются.

Скачайте `ClaudeReset-1.1.1-setup.exe` (установщик, права администратора не нужны) или `ClaudeReset-1.1.1-windows-x64.zip` (без установки). Установщик не подписан: Windows покажет «Windows защитила ваш компьютер» — «Подробнее» → «Выполнить в любом случае». Программа проверена автоматическими тестами; на компьютерах пользователей сброс и защита не проверялись.
