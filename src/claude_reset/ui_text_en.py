"""English texts of the main window. Keys are the Russian originals (see ui_text)."""

EN = {
    # Frame, navigation, status
    'Выполняем…': 'Working…', 'Отмена': 'Cancel', 'Остановить': 'Stop', 'Понятно': 'OK',
    'Главная': 'Home', 'Шаг 1 · Сброс': 'Step 1 · Reset', 'Шаг 2 · Прокси и защита': 'Step 2 · Proxy',
    'Помощь': 'Help', 'ПОМОЩЬ': 'HELP', '0-SOFT · НАЧНЁМ С НУЛЯ': '0-SOFT · START FROM ZERO',
    'Все инструменты программы — для тех, кто знает, что делает.': 'Every tool of the program — for those who know what they are doing.',
    'Режим для специалистов': 'Specialist mode (Russian)',
    'Режим для специалистов открывается в отдельном окне.': 'Specialist mode opens in a separate window.',
    'Не открылось': 'Could not open',
    'Не удалось открыть режим для специалистов. Запустите ClaudeReset.cmd ещё раз.': 'Specialist mode did not open. Start ClaudeReset again.',
    'Готово к работе. Открытие окна ничего не меняет.': 'Ready. Opening the window changes nothing.',
    'Подождите: предыдущее действие ещё выполняется.': 'Please wait: the previous action is still running.',
    'Действие ещё выполняется. Если закрыть окно, оно продолжится без вас, а результат придётся проверить заново.':
        'An action is still running. If you close the window it continues without you, and you will need to check the result again.',
    'Закрыть окно?': 'Close the window?', 'Закрыть': 'Close', 'Остаться': 'Stay',
    'Готово.': 'Done.', 'Готово': 'Done', 'Не получилось': 'Did not work', 'Не получилось.': 'Did not work.',
    'Действие остановилось с ошибкой. Ничего не повторялось автоматически. Проверьте состояние ещё раз; если ошибка повторится — сохраните отчёт на странице «Помощь».':
        'The action stopped with an error. Nothing was retried automatically. Check the state again; if the error repeats, save a report on the Help page.',
    'Windows просит разрешение. Нажмите «Да» в окне запроса — без него защита не включится.':
        'Windows is asking for permission. Click "Yes" in its window — without it the protection cannot be switched.',
    'Тема сменится после текущего действия: выберите её ещё раз.': 'The theme changes after the current action: choose it again then.',
    'Язык сменится после текущего действия: выберите его ещё раз.': 'The language changes after the current action: choose it again then.',
    # Progress steps
    'Проверяем компьютер…': 'Checking the computer…', 'Закрываем Claude…': 'Closing Claude…',
    'Останавливаем службу Cowork…': 'Stopping the Cowork service…', 'Сохраняем копию работы Cowork…': 'Saving a copy of your Cowork work…',
    'Сохраняем копию ваших файлов Claude Code…': 'Saving a copy of your Claude Code files…',
    'Сбрасываем ключ устройства Claude Desktop…': 'Resetting the Claude Desktop device key…', 'Стираем данные Claude…': 'Erasing Claude data…',
    'Выходим из claude.ai в Chrome и Edge…': 'Signing out of claude.ai in Chrome and Edge…',
    'Проверяем прокси: связь, вход и адрес выхода…': 'Checking the proxy: connection, sign-in and exit address…',
    'Устанавливаем движок VLESS…': 'Installing the VLESS engine…', 'Готовим описание защиты…': 'Preparing the protection details…',
    'Включаем защиту…': 'Switching the protection on…', 'Применяем новый прокси…': 'Applying the new proxy…',
    'Перезапускаем защиту…': 'Restarting the protection…', 'Выключаем защиту…': 'Switching the protection off…',
    'Обновляем защиту…': 'Updating the protection…', 'Применяем выбор для VS Code…': 'Applying the VS Code choice…',
    'Проверяем состояние…': 'Checking the state…', 'Собираем отчёт…': 'Collecting the report…',
    'Сравниваем пояс и язык…': 'Comparing time zone and language…', 'Удаляем сохранённый прокси…': 'Removing the saved proxy…',
    'Остановлено на безопасной границе. Уже выполненные шаги не отменяются.': 'Stopped at a safe point. Steps already done are not undone.',
    'Начатый шаг нельзя прервать. Дождитесь его результата.': 'A started step cannot be interrupted. Wait for its result.',
    'Не удалось показать результат. Операция могла завершиться; проверьте состояние перед повтором.':
        'The result could not be shown. The action may have finished; check the state before repeating it.',
    'Сохранён незавершённый запрос Windows. Закрытие окна не отменит операцию. Запрет повторного запроса сохранится после открытия программы; перед продолжением нужна сверка результата. Закрыть окно?':
        'A Windows request is still pending. Closing the window will not cancel it, and a repeat stays blocked after the program reopens until the result is checked. Close the window?',
    # Home
    'Начнём с нуля': 'Start from zero',
    'Два шага, чтобы Claude увидел вас как нового пользователя: сначала сотрите его следы на этом компьютере, затем направьте его через ваш прокси.':
        'Two steps so that Claude sees you as a new user: first erase its traces on this computer, then route it through your proxy.',
    'ШАГ 1': 'STEP 1', 'ШАГ 2': 'STEP 2', 'Сброс': 'Reset', 'Прокси и защита': 'Proxy and protection',
    'Удаляет вход, историю и данные Claude Desktop и Claude Code. Сами программы остаются установленными.':
        'Removes the sign-in, history and data of Claude Desktop and Claude Code. The programs themselves stay installed.',
    'Перейти к сбросу →': 'Go to reset →',
    'Claude будет выходить в интернет только через ваш прокси. Если прокси пропадёт, Claude останется без сети, а не выйдет напрямую.':
        'Claude will reach the internet only through your proxy. If the proxy goes away, Claude stays offline instead of going direct.',
    'Настроить прокси →': 'Set up the proxy →',
    'После обоих шагов откройте Claude и войдите под новым аккаунтом. Порядок важен: сначала сброс, потом прокси.':
        'After both steps, open Claude and sign in with a new account. The order matters: reset first, then the proxy.',
    'Проверяем…': 'Checking…', 'Сброс уже выполнялся на этом компьютере': 'A reset has already been done on this computer',
    'Ещё не выполнялся': 'Not done yet',
    # Reset page
    'ШАГ 1 · СБРОС': 'STEP 1 · RESET', 'Сброс Claude': 'Reset Claude',
    'Сотрём всё, что Claude хранит на этом компьютере: вход, историю, настройки и сохранённые пароли. Сами программы останутся — после сброса они откроются как в первый раз.':
        'We erase everything Claude keeps on this computer: sign-in, history, settings and saved passwords. The programs stay — after the reset they open as on the first day.',
    'Что сохранить': 'What to keep', 'Стереть всё, но оставить память': 'Erase everything, keep memory',
    'Ваши заметки и инструкции для Claude Code (файлы CLAUDE.md) вернутся на место. Всё остальное будет удалено.':
        'Your notes and instructions for Claude Code (CLAUDE.md files) are put back. Everything else is removed.',
    'Стереть всё': 'Erase everything', 'Ничего не сохраняется. Полностью с нуля.': 'Nothing is kept. Fully from zero.',
    'Сначала — на сайте Claude': 'First — on the Claude website',
    'В браузере, где вы вошли в старый аккаунт, выйдите на всех устройствах и отзовите доступ Claude Code. Иначе сервер свяжет новый вход со старым. Скопируйте адрес и вставьте его в браузер.':
        'In the browser where you are signed in to the old account, sign out on all devices and revoke Claude Code access. Otherwise the server links the new sign-in to the old one. Copy the address and paste it into the browser.',
    'Скопировать адрес: сессии': 'Copy address: sessions', 'Скопировать адрес: доступ Claude Code': 'Copy address: Claude Code access',
    'Адрес скопирован. Вставьте его в адресную строку браузера.': 'Address copied. Paste it into the browser address bar.',
    'Готово: я вышел на всех устройствах и сохранил нужное из облака': 'Done: I signed out on all devices and saved what I need from the cloud',
    'Браузеры': 'Browsers',
    'Также выйти из claude.ai в Chrome и Edge (закройте их перед сбросом)': 'Also sign out of claude.ai in Chrome and Edge (close them before the reset)',
    'Проверить и очистить': 'Check and clean', 'Только посмотреть, что найдено': 'Only show what is found',
    'Программа сама закроет Claude, остановит службу Cowork и сохранит копии ваших файлов. Перед удалением она покажет, что найдено, и попросит подтверждение.':
        'The program closes Claude, stops the Cowork service and saves copies of your files by itself. Before removing anything it shows what it found and asks you to confirm.',
    'Сначала сайт Claude': 'The Claude website first',
    'Выйдите из старого аккаунта на всех устройствах и поставьте отметку «Готово». Без этого новый вход может связаться со старым.':
        'Sign out of the old account on all devices and tick "Done". Without it the new sign-in may be linked to the old one.',
    'Здесь пусто': 'Nothing here',
    'Данных Claude на этом компьютере не найдено. Начнём с нуля — переходите к прокси.': 'No Claude data was found on this computer. Start from zero — go on to the proxy.',
    'Дальше: прокси и защита →': 'Next: proxy and protection →',
    'Что найдено': 'Found', 'не прочиталось': 'could not be read',
    'Сохранённые пароли Claude в Windows: {n}': 'Saved Claude passwords in Windows: {n}', 'Всего файлов на {size}': 'Files in total: {size}',
    'Программа сделает сама': 'The program will', 'Нужно сделать вам': 'For you to do',
    'Проверить снова': 'Check again', 'Открыть автозагрузку': 'Open startup apps', 'Очистить': 'Clean',
    'Окно проверяет само каждые несколько секунд и продолжит, как только всё будет готово.':
        'The window checks again every few seconds and continues as soon as everything is ready.',
    'Непроверенная версия Claude': 'Unverified Claude version',
    'Эта версия Claude ещё не проверялась с программой. Программа сотрёт те же папки, что и обычно, но новые места хранения, если версия их добавила, не найдёт. Продолжить?':
        'This Claude version has not been checked with the program yet. It erases the usual folders, but new storage places the version may have added will not be found. Continue?',
    'Продолжить': 'Continue', 'Не сейчас': 'Not now',
    'Это нельзя отменить. ': 'This cannot be undone. ', 'Память Claude Code вернётся на место после очистки. ': 'Your Claude Code memory is put back after cleaning. ',
    'Ничего не сохранится. ': 'Nothing is kept. ',
    'Перед удалением программа закроет Claude и сохранит копии ваших файлов. ': 'Before removing anything, the program closes Claude and saves copies of your files. ',
    'Будет удалено:': 'To be removed:', 'Вход на claude.ai в Chrome и Edge': 'Sign-in on claude.ai in Chrome and Edge',
    'Стереть данные Claude?': 'Erase Claude data?', 'Стереть': 'Erase', 'СТЕРЕТЬ': 'ERASE',
    'Чтобы подтвердить, введите {word}': 'To confirm, type {word}',
    'Остановились перед удалением': 'Stopped before removing anything',
    'Не всё получилось сделать автоматически. Ничего не удалено. Посмотрите, что осталось сделать, и нажмите «Проверить снова».':
        'Not everything could be done automatically. Nothing was removed. See what is left to do and click "Check again".',
    'Стирание остановилось': 'Erasing stopped',
    'Часть данных могла остаться. Копия памяти, если вы её сохраняли, не потеряна. Нажмите «Проверить и очистить» ещё раз; если ошибка повторится — сохраните отчёт на странице «Помощь».':
        'Some data may remain. The memory copy, if you kept it, is not lost. Click "Check and clean" again; if the error repeats, save a report on the Help page.',
    'Готово ✓': 'Done ✓', 'Почти готово': 'Almost done',
    'Данные Claude стёрты. В проверенных папках ничего не осталось.': 'Claude data is erased. Nothing is left in the checked folders.',
    'Данные стёрты, но в проверенных папках что-то осталось. Нажмите «Проверить и очистить» ещё раз.':
        'The data is erased, but something is left in the checked folders. Click "Check and clean" again.',
    'Память Claude Code возвращена на место.': 'Your Claude Code memory is back in place.',
    'Удалено сохранённых паролей Claude: {n}.': 'Saved Claude passwords removed: {n}.',
    'Ключ устройства Claude Desktop сброшен: Desktop увидит новое устройство.': 'The Claude Desktop device key is reset: Desktop will see a new device.',
    'Ключ устройства Claude Desktop не сброшен: эта версия Desktop ещё не проверена. Desktop может узнать этот компьютер.':
        'The Claude Desktop device key is not reset: this Desktop version is not verified yet. Desktop may recognise this computer.',
    'Ключ устройства Claude Desktop не сброшен из-за ошибки.': 'The Claude Desktop device key was not reset because of an error.',
    'Вы вышли из claude.ai в Chrome и Edge.': 'You are signed out of claude.ai in Chrome and Edge.',
    'Chrome или Edge были открыты, поэтому вход на claude.ai там остался.': 'Chrome or Edge was open, so the claude.ai sign-in is still there.',
    'Выйти из claude.ai в браузерах не получилось.': 'Signing out of claude.ai in the browsers did not work.',
    'Проверьте вручную': 'Check by hand', 'Выйти из claude.ai в браузерах': 'Sign out of claude.ai in browsers',
    'Выйти из claude.ai в браузерах?': 'Sign out of claude.ai in browsers?',
    'Сначала закройте Chrome и Edge. Профили браузеров и другие сайты не пострадают — удаляются только cookies и данные claude.ai.':
        'Close Chrome and Edge first. Browser profiles and other sites are not touched — only cookies and data of claude.ai are removed.',
    'Выйти': 'Sign out', 'Готово ✓ Вы вышли из claude.ai в Chrome и Edge.': 'Done ✓ You are signed out of claude.ai in Chrome and Edge.',
    'Chrome или Edge ещё открыты. Закройте их полностью и повторите.': 'Chrome or Edge is still open. Close them completely and try again.',
    'Не получилось. Повторите после закрытия браузеров.': 'Did not work. Try again after closing the browsers.',
    'Откройте вручную: Параметры Windows → Приложения → Автозагрузка.': 'Open it yourself: Windows Settings → Apps → Startup.',
    'Данные claude.ai в браузерах, кроме cookies и IndexedDB: кэш и локальное хранилище — через настройки браузера.':
        'claude.ai data in browsers other than cookies and IndexedDB: cache and local storage — through the browser settings.',
    'Ваши проекты и папки с кодом на диске — программа их не трогает.': 'Your projects and code folders on disk — the program does not touch them.',
    'Переменные среды, WSL, Docker и SSH — если вы настраивали в них Claude.': 'Environment variables, WSL, Docker and SSH — if you set Claude up there.',
    # Reset blockers and found items (from reset_flow)
    'Закроет Claude Desktop и Claude Code.': 'Close Claude Desktop and Claude Code.',
    'Открыт VS Code: в нём работает Claude Code. Сохраните файлы и закройте все окна VS Code.':
        'VS Code is open and Claude Code runs in it. Save your files and close every VS Code window.',
    'Claude не закрылся сам. Закройте Claude Desktop, в том числе значок у часов.': 'Claude did not close by itself. Close Claude Desktop, including the icon near the clock.',
    'Остановит службу Cowork.': 'Stop the Cowork service.', 'Сохранит копию вашей работы в Cowork.': 'Save a copy of your Cowork work.',
    'Сохранит копию ваших команд, агентов и настроек Claude Code.': 'Save a copy of your Claude Code commands, agents and settings.',
    'Эта версия Claude ещё не проверялась с программой.': 'This Claude version has not been checked with the program yet.',
    'В автозагрузке Windows есть программа, которая снова запустит Claude. Отключите её в «Автозагрузке».':
        'A Windows startup entry would start Claude again. Turn it off in Startup apps.',
    'Не удалось прочитать часть папок Claude. Откройте «Режим для специалистов» → «Очистка».': 'Some Claude folders could not be read. Open specialist mode → Cleanup.',
    'Работа Cowork лежит в непроверенном месте. Нужен «Режим для специалистов».': 'Cowork work is in an unverified place. Specialist mode is needed.',
    'Нужна проверка в «Режиме для специалистов».': 'This needs a check in specialist mode.',
    'Claude Desktop: программа из Microsoft Store': 'Claude Desktop: Microsoft Store app', 'Claude Desktop: вход, история, настройки': 'Claude Desktop: sign-in, history, settings',
    'Claude Desktop: подключения': 'Claude Desktop: connectors', 'Claude Code: история, проекты, память': 'Claude Code: history, projects, memory',
    'Claude Code: файл настроек': 'Claude Code: settings file', 'Claude Code в VS Code': 'Claude Code in VS Code',
    'Claude Desktop и Cowork: данные': 'Claude Desktop and Cowork: data', 'Claude Code: резервные копии настроек': 'Claude Code: settings backups',
    # Proxy page
    'ШАГ 2 · ПРОКСИ И ЗАЩИТА': 'STEP 2 · PROXY AND PROTECTION',
    'Защита пускает Claude в интернет только через ваш прокси. Остальные программы — браузер, игры, Discord — работают как обычно.':
        'The protection lets Claude reach the internet only through your proxy. Other programs — browser, games, Discord — work as usual.',
    'Ваш прокси': 'Your proxy',
    'Данные выдаёт ваш провайдер прокси. Пароль хранится только на этом компьютере в зашифрованном виде.':
        'Your proxy provider gives you these details. The password is stored only on this computer, encrypted.',
    'VLESS — файл профиля': 'VLESS — profile file', 'Адрес сервера': 'Server address', 'Например 203.0.113.10': 'For example 203.0.113.10',
    'Порт': 'Port', 'Например 1080': 'For example 1080', 'Логин': 'Username', 'Если выдан': 'If you have one', 'Пароль': 'Password',
    'Файл профиля VLESS (.json)': 'VLESS profile file (.json)', 'Профиль VLESS+Reality': 'VLESS+Reality profile',
    'Архив движка — если есть; иначе скачаем сами': 'Engine archive — if you have one; otherwise we download it',
    'Архив движка': 'Engine archive', 'Выбрать файл…': 'Choose file…',
    'Также защищать Claude Code внутри VS Code': 'Also protect Claude Code inside VS Code',
    'После включения перезагрузите окно VS Code: Ctrl+Shift+P → «Reload Window», затем продолжите разговор командой /resume.':
        'After switching on, reload the VS Code window: Ctrl+Shift+P → "Reload Window", then continue the conversation with /resume.',
    'Проверить и включить защиту': 'Check and switch on protection', 'Проверить и применить новый прокси': 'Check and apply the new proxy',
    'Прокси: {name}': 'Proxy: {name}', 'Под защитой: ': 'Protected: ', 'Найдены: ': 'Found: ',
    'Проверить сейчас': 'Check now', 'Перезапустить': 'Restart', 'Выключить защиту': 'Switch protection off', 'Обновить': 'Refresh',
    'Удалить сохранённый прокси': 'Remove the saved proxy', 'Обновить защиту после обновления программы': 'Update the protection after a program update',
    'Применить выбор для VS Code': 'Apply the VS Code choice',
    'Прокси работает ✓': 'The proxy works ✓',
    'Claude будет выходить в интернет с этого адреса. Он совпадает с тем, что выдал ваш провайдер прокси?':
        'Claude will reach the internet from this address. Does it match what your proxy provider gave you?',
    'Да, всё верно': 'Yes, correct', 'Нет': 'No',
    'Применить новый прокси?': 'Apply the new proxy?', 'Защита перезапустится. Claude на несколько секунд останется без сети.':
        'The protection restarts. Claude is offline for a few seconds.', 'Применить': 'Apply',
    'Перед включением': 'Before switching on', 'Включить защиту заново?': 'Switch the protection on again?', 'Включить защиту': 'Switch on protection',
    'Защита закрывает собственные соединения Claude. Вот что она не закрывает — это ограничения Windows, а не ошибки. Windows попросит разрешение: нажмите «Да».':
        'The protection covers Claude\'s own connections. This is what it does not cover — Windows limits, not mistakes. Windows will ask for permission: click "Yes".',
    'Программа поставит защиту текущей версии и включит её. ': 'The program installs the protection of this version and switches it on. ',
    'Нужна новая версия': 'A newer version is needed',
    'Список того, что защита не закрывает, изменился. Включите защиту в «Режиме для специалистов».':
        'The list of what the protection does not cover has changed. Switch it on in specialist mode.',
    'Сначала выключите защиту': 'Switch the protection off first',
    'Чтобы перейти на VLESS, выключите защиту, затем установите профиль.': 'To move to VLESS, switch the protection off, then install the profile.',
    'Выберите файл профиля VLESS.': 'Choose a VLESS profile file.',
    'Введите данные прокси ниже и нажмите «Проверить и применить новый прокси».': 'Enter the proxy details below and click "Check and apply the new proxy".',
    'Перезапустить защиту?': 'Restart the protection?', 'Claude на несколько секунд останется без сети.': 'Claude is offline for a few seconds.',
    'Прокси не работает': 'The proxy does not work', ' Если не поможет — введите прокси заново ниже.': ' If that does not help, enter the proxy again below.',
    'Выключить защиту?': 'Switch the protection off?',
    'Claude снова будет выходить в интернет напрямую, без прокси. Сохранённый прокси и адрес выхода тоже будут удалены. Windows попросит разрешение.':
        'Claude will reach the internet directly again, without the proxy. The saved proxy and exit address are removed too. Windows will ask for permission.',
    'Выключить': 'Switch off',
    'Применить выбор для VS Code?': 'Apply the VS Code choice?',
    'Claude Code в VS Code тоже будет выходить только через прокси.': 'Claude Code in VS Code will also go out only through the proxy.',
    'Claude Code в VS Code снова будет выходить напрямую.': 'Claude Code in VS Code will go out directly again.',
    ' Сохраните работу: после применения перезагрузите окно VS Code (Ctrl+Shift+P → «Reload Window») и продолжите командой /resume.':
        ' Save your work: after applying, reload the VS Code window (Ctrl+Shift+P → "Reload Window") and continue with /resume.',
    'Удалить сохранённый прокси?': 'Remove the saved proxy?', 'Адрес, логин и пароль прокси будут удалены с этого компьютера.':
        'The proxy address, username and password are removed from this computer.', 'Удалить': 'Remove', 'Прокси': 'Proxy',
    # Protection states and messages (from proxy_flow)
    'Защита включена': 'Protection is on', 'Claude выходит в интернет только через ваш прокси.': 'Claude reaches the internet only through your proxy.',
    'Защита выключена': 'Protection is off', 'Claude выходит в интернет напрямую, как обычно.': 'Claude reaches the internet directly, as usual.',
    'Защита на паузе': 'Protection is paused', 'Claude сейчас выходит в интернет напрямую, без прокси.': 'Claude is reaching the internet directly now, without the proxy.',
    'Claude сейчас без сети': 'Claude is offline now', 'Защита установлена, но сейчас не работает.': 'The protection is installed but not working now.',
    'Защита установлена не полностью': 'The protection is only partly installed', 'Включите её заново или выключите совсем.': 'Switch it on again or switch it off completely.',
    'Состояние не прочиталось': 'The state could not be read', 'Нажмите «Обновить».': 'Click "Refresh".',
    'Прокси выходит в интернет с другого адреса, чем вы подтвердили.': 'The proxy reaches the internet from a different address than you confirmed.',
    'Прокси не отвечает.': 'The proxy does not answer.', 'Не удалось проверить, через какой адрес выходит прокси.': 'The proxy exit address could not be checked.',
    'Прокси изменился или остановлен.': 'The proxy changed or stopped.', 'Настройки прокси не прошли проверку.': 'The proxy settings did not pass the check.',
    'Сохранённый адрес выхода изменился.': 'The saved exit address changed.', 'Защита остановилась из-за ошибки наблюдения.': 'The protection stopped because of a monitoring error.',
    'Защита остановилась из-за ошибки.': 'The protection stopped because of an error.',
    'Проверить и принять новый адрес': 'Check and accept the new address', 'Проверить прокси снова': 'Check the proxy again',
    'Ввести прокси заново': 'Enter the proxy again', 'Перезапустить защиту': 'Restart the protection', 'Включить защиту заново': 'Switch the protection on again',
    'Снять с паузы и включить': 'Resume and switch on',
    'Прокси работает.': 'The proxy works.', 'Прокси не отвечает. Проверьте адрес и порт.': 'The proxy does not answer. Check the address and port.',
    'Прокси не принял логин и пароль или не пустил дальше.': 'The proxy refused the username and password or did not let the connection through.',
    'Прокси пустил, но адрес выхода не измерился. Повторите проверку.': 'The proxy let us in, but the exit address was not measured. Check again.',
    'Проверка не завершилась. Повторите её.': 'The check did not finish. Run it again.', 'Сначала проверьте прокси.': 'Check the proxy first.',
    'Прокси и адрес выхода сохранены.': 'The proxy and exit address are saved.', 'Движок VLESS установлен.': 'The VLESS engine is installed.',
    'Движок установлен, но проверка не прошла. Повторите её.': 'The engine is installed but the check did not pass. Run it again.',
    'Движок не установлен: прежний движок ещё на месте. Сначала снимите его.': 'The engine is not installed: the previous engine is still in place. Remove it first.',
    'Сохранён другой прокси. Сначала выключите защиту и снимите его.': 'Another proxy is saved. Switch the protection off and remove it first.',
    'Движок не установился. Проверьте файл профиля и интернет.': 'The engine did not install. Check the profile file and the internet connection.',
    'Прокси снят.': 'The proxy is removed.', 'Прокси не снят: сначала выключите защиту.': 'The proxy is not removed: switch the protection off first.',
    'Не получилось. Повторите или откройте «Режим для специалистов».': 'Did not work. Try again or open specialist mode.',
    'Claude Desktop': 'Claude Desktop', 'Claude Code в терминале': 'Claude Code in the terminal',
    'Проверьте публичный IPv4, порт и пару логин/пароль.': 'Check the public IPv4 address, the port and the username/password pair.',
    # Protection limits and results (from protection_panel)
    'Срок жизни контроллера не обеспечивает полную изоляцию.': 'The controller lifetime does not give full isolation.',
    'Не все обращения через другие процессы изолированы.': 'Not all requests made through other processes are isolated.',
    'Целостность управляющих файлов и посредников ограничена.': 'Integrity of control files and intermediaries is limited.',
    'Совместимость всех рабочих клиентов не подтверждена.': 'Compatibility of every Claude client is not confirmed.',
    'Гостевая среда Cowork не покрыта L1.': 'The Cowork guest machine is not covered.',
    'Локальные сетевые сведения не скрыты полностью.': 'Local network details are not fully hidden.',
    'Доступ к процессам и потокам помощников не изолирован полностью.': 'Access to helper processes and threads is not fully isolated.',
    'Изоляция помощников до начала выполнения не подтверждена.': 'Helper isolation before they start is not confirmed.',
    'Целостность токенов помощников не подтверждена.': 'Integrity of helper tokens is not confirmed.',
    'DNS через системную службу Windows не изолирован полностью.': 'DNS through the Windows system service is not fully isolated.',
    'Новая неизвестная граница: установка из окна недоступна.': 'A new unknown limit: installing from the window is not available.',
    'Исключение расширения не завершено. Контроллер остановлен; нужна сверка фильтров и настроек.':
        'Excluding the extension did not finish. The controller is stopped; filters and settings need checking.',
    'Сначала выберите область расширения.': 'Choose the extension option first.',
    'Настройки расширения не применены. Контроллер остановлен; нужна проверка.': 'The extension settings were not applied. The controller is stopped; it needs checking.',
    'Сначала проверьте прокси и подтвердите новый выход.': 'Check the proxy and confirm the new exit first.',
    'Установка L1 завершена. Полная изоляция не подтверждена.': 'The protection is installed. Full isolation is not confirmed.',
    'Установка частичная: требуется проверка состояния.': 'The installation is partial: the state needs checking.',
    'Контроллер перезапущен, новое реле подтверждено.': 'The controller restarted and the new relay is confirmed.',
    'Удаление защиты завершено.': 'The protection is removed.', 'Удаление завершено с остатками. Нужна проверка.': 'Removal finished with leftovers. It needs checking.',
    'Контроллер не установлен.': 'The controller is not installed.',
    'Сначала настройте прокси на вкладке «Соединение».': 'Set up the proxy first.', 'Сначала проверьте и сохраните ожидаемый выход.': 'Check and save the expected exit first.',
    'Необходимо согласие на границы L1.': 'Agreement to the protection limits is needed.',
    'Предусловия установки не выполнены. Обновите состояние.': 'Installation conditions are not met. Refresh the state.',
    'Остановка контроллера не подтверждена.': 'The controller stop is not confirmed.',
    'Реле не открылось. Клиенты могут оставаться без сети.': 'The relay did not open. Claude may stay offline.',
    'Контроллер не запустился. Клиенты могут оставаться без сети.': 'The controller did not start. Claude may stay offline.',
    'Исход не подтверждён. Требуется сверка; повтор запрещён.': 'The outcome is not confirmed. It needs checking; a repeat is blocked.',
    'Предыдущий запрос Windows не завершён. Требуется сверка.': 'The previous Windows request has not finished. It needs checking.',
    'Операция не завершена полностью. Обновите состояние; проверьте журнал операции.': 'The action did not fully finish. Refresh the state and check the action log.',
    'Установленные бинарники расширения исключены. Фильтры удалённых версий требуют отдельной проверки.':
        'The installed extension binaries are excluded. Filters of removed versions need a separate check.',
    'Новый профиль сохранён DPAPI. Это само по себе не подтверждает работу реле.': 'The new profile is saved encrypted. That alone does not confirm the relay works.',
    'Повтор запрещён до сверки незавершённой операции.': 'A repeat is blocked until the unfinished action is checked.',
    'Действие отменено. Изменения не выполнялись.': 'Cancelled. Nothing was changed.',
    'Список границ изменился. Установка из окна недоступна.': 'The list of limits changed. Installing from the window is not available.',
    # Help page
    'Руководство': 'Guide', 'Пошагово: сброс, прокси, вход в новый аккаунт.': 'Step by step: reset, proxy, sign-in with a new account.',
    'Открыть руководство': 'Open the guide', 'Что-то не работает': 'Something does not work',
    'Сохраните отчёт и отправьте тому, кто вам помогает. В отчёте нет паролей, адресов прокси и имени пользователя.':
        'Save a report and send it to whoever helps you. It contains no passwords, proxy addresses or user name.',
    'Сохранить отчёт': 'Save report', 'Отчёт сохранён. В нём нет паролей, адресов прокси и имени пользователя.':
        'Report saved. It contains no passwords, proxy addresses or user name.',
    'Язык и часовой пояс': 'Language and time zone',
    'Сайты сравнивают часовой пояс и язык компьютера со страной, из которой вы заходите. Укажите страну вашего прокси: DE, TR или GB.':
        'Websites compare the computer\'s time zone and language with the country you connect from. Enter your proxy\'s country: DE, TR or GB.',
    'Сравнить': 'Compare', 'Настройки времени': 'Time settings', 'Настройки языка': 'Language settings',
    'Откройте настройки Windows вручную.': 'Open the Windows settings yourself.',
    ' Пояс: ': ' Time zone: ', '. Язык: ': '. Language: ', 'совпадает ✓': 'matches ✓', 'не совпадает': 'does not match',
    'не совпадает — это ваш выбор, менять не обязательно': 'does not match — that is your choice, no need to change it',
    'Германия: проверьте центральноевропейский пояс и язык de-DE.': 'Germany: check the Central European time zone and the de-DE language.',
    'Турция: проверьте пояс Турции и язык tr-TR.': 'Turkey: check the Turkey time zone and the tr-TR language.',
    'Великобритания: проверьте местный пояс и язык en-GB.': 'United Kingdom: check the UK time zone and the en-GB language.',
    'Для этой страны нет однозначного совета. Уточните регион выхода и сравните пояс и язык вручную.':
        'There is no clear advice for this country. Check the exit region and compare time zone and language yourself.',
    'Не удалось прочитать пояс и язык Windows. Сравните их вручную.': 'The Windows time zone and language could not be read. Compare them yourself.',
    'Ограничения и лицензии': 'Limits and licences', 'Что защита не закрывает и чьи компоненты использует программа.':
        'What the protection does not cover and whose components the program uses.',
    'Ограничения': 'Limits', 'Лицензии': 'Licences', 'Границы и приёмка': 'Limits', 'Лицензионные уведомления': 'Licence notices',
    'Справка недоступна': 'Help is not available', 'Файл справки не найден рядом с программой.': 'The help file was not found next to the program.',
    'Оформление': 'Appearance', 'Тема и язык окна. Клавиши: Tab — следующая кнопка, Enter — нажать, Alt+1…4 — страницы.':
        'Window theme and language. Keys: Tab — next button, Enter — press, Alt+1…4 — pages.',
    'Как в Windows': 'As in Windows', 'Светлая': 'Light', 'Тёмная': 'Dark',
    'Удалить программу': 'Uninstall the program',
    'Сначала выключит защиту, если она включена, затем удалит ClaudeReset, его ярлыки и запись в «Приложениях». Сохранённые копии памяти останутся.':
        'Switches the protection off first if it is on, then removes ClaudeReset, its shortcuts and its Apps entry. Saved memory copies stay.',
    'Удалить ClaudeReset': 'Uninstall ClaudeReset', 'Удалить ClaudeReset?': 'Uninstall ClaudeReset?', 'УДАЛИТЬ': 'DELETE',
    'Удаление': 'Uninstall', 'Эта копия не установлена установщиком. Чтобы убрать её, удалите её папку.':
        'This copy was not installed by the installer. To remove it, delete its folder.',
    'ClaudeReset будет удалён с компьютера. ': 'ClaudeReset will be removed from the computer. ',
    'Сначала программа выключит защиту: Claude снова будет выходить в интернет напрямую, а Windows попросит разрешение. ':
        'The program switches the protection off first: Claude will go out directly again, and Windows will ask for permission. ',
    'Копии памяти и отчёты останутся в папке ниже — удалите её сами, если они не нужны.':
        'Memory copies and reports stay in the folder below — delete it yourself if you do not need them.',
    'Ярлыки и запись в «Приложениях»': 'Shortcuts and the Apps entry', 'Папка программы': 'The program folder',
    'ClaudeReset удалён': 'ClaudeReset is uninstalled', 'Окно закроется, папка программы удалится через несколько секунд.':
        'The window closes and the program folder is removed in a few seconds.',
    'Удаление остановлено': 'Uninstall stopped',
    'Защиту выключить не удалось, поэтому программа не удалена: иначе Claude мог остаться без сети. Попробуйте ещё раз или выключите защиту на шаге 2.':
        'The protection could not be switched off, so the program was not removed: otherwise Claude could stay offline. Try again or switch the protection off in step 2.',
}

# Problem texts are shown with a fixed second sentence.
for _reason in ('Прокси выходит в интернет с другого адреса, чем вы подтвердили.', 'Прокси не отвечает.',
                'Не удалось проверить, через какой адрес выходит прокси.', 'Прокси изменился или остановлен.',
                'Настройки прокси не прошли проверку.', 'Сохранённый адрес выхода изменился.',
                'Защита остановилась из-за ошибки наблюдения.', 'Защита остановилась из-за ошибки.',
                'Защита установлена, но сейчас не работает.'):
    EN[_reason + ' Напрямую Claude не выйдет — так задумано.'] = EN[_reason] + ' Claude will not go out directly — this is intended.'

# Lines with a measured value, translated by ui_text.tr_text.
PATTERNS = [(r'Время без реле: ([\d.]+) с\.', 'Time without the relay: {} s.')]
