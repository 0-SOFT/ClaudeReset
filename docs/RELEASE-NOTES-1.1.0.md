## ClaudeReset 1.1.0

**English**

- The code was rebuilt from the inside: it is split into layers (Windows calls, data types, scenarios, windows), every Windows call has one place, and the tests check the program through its public interfaces. The program does the same as 1.0.1: the reset and the protection steps are unchanged.
- The protection window has its own message for every final result, including a failed package registration, a failed autostart and parts that could not be removed. Before, these showed the general "The action did not fully finish" text.
- Open browsers are recognized reliably before site data is cleaned, in both languages of the window.
- In the English window, the default dialog buttons are in English; they were in Russian.
- Error messages of the reset and proxy steps, and a diagnostic report saved from the window, are in the window's language.
- On the command line, notes are printed in English.

Download `ClaudeReset-1.1.0-setup.exe` (installer, no administrator rights) or `ClaudeReset-1.1.0-windows-x64.zip` (no installation). The installer is not signed: Windows shows "Windows protected your PC" — click "More info" → "Run anyway". The program is checked by automated tests; reset and protection have not been run on users' computers.

**Русский**

- Код перестроен изнутри: он разделён на слои (вызовы Windows, типы данных, сценарии, окна), у каждого вызова Windows одно место, а тесты проверяют программу через её открытые интерфейсы. Программа делает то же, что 1.0.1: шаги сброса и защиты не изменились.
- У окна защиты есть своё сообщение для каждого итога, в том числе для неудачной регистрации пакета, неудачного автозапуска и частей, которые не удалось снять. Раньше в этих случаях показывался общий текст «Операция не завершена полностью».
- Открытые браузеры перед очисткой данных сайтов распознаются надёжно на обоих языках окна.
- В английском окне кнопки диалогов по умолчанию — английские; раньше они были русскими.
- Сообщения об ошибках шагов сброса и прокси и сохранённый из окна отчёт диагностики — на языке окна.
- Командная строка печатает заметки по-английски.

Скачайте `ClaudeReset-1.1.0-setup.exe` (установщик, права администратора не нужны) или `ClaudeReset-1.1.0-windows-x64.zip` (без установки). Установщик не подписан: Windows покажет «Windows защитила ваш компьютер» — «Подробнее» → «Выполнить в любом случае». Программа проверена автоматическими тестами; на компьютерах пользователей сброс и защита не проверялись.
