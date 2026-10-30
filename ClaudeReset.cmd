@echo off
setlocal
chcp 65001 >nul
rem ClaudeReset from source. The first run prepares the project Python environment (.venv).
set "ROOT=%~dp0"
if exist "%ROOT%.venv\Scripts\pythonw.exe" goto run
echo ClaudeReset: первый запуск. Готовим окружение Python, это нужно один раз и займёт 1-3 минуты.
echo Нужен интернет. Окно закроется само, когда всё будет готово.
set "PY="
where py >nul 2>nul && py -3.12 -c "import tkinter" >nul 2>nul && set "PY=py -3.12"
if not defined PY where python >nul 2>nul && python -c "import sys, tkinter; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)" >nul 2>nul && set "PY=python"
if not defined PY goto nopython
%PY% -m venv "%ROOT%.venv" || goto fail
"%ROOT%.venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r "%ROOT%requirements-lock.txt" || goto fail
:run
start "" "%ROOT%.venv\Scripts\pythonw.exe" "%ROOT%src\launcher.py"
exit /b 0
:nopython
echo Не найден Python 3.12.
echo Установите его с https://www.python.org/downloads/ - Windows installer 64-bit,
echo при установке отметьте "Add python.exe to PATH". Затем запустите ClaudeReset.cmd снова.
pause
exit /b 1
:fail
echo Не получилось подготовить окружение. Проверьте интернет и запустите ClaudeReset.cmd снова.
if exist "%ROOT%.venv" rmdir /s /q "%ROOT%.venv"
pause
exit /b 1
