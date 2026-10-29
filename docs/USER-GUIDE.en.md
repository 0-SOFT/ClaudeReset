# ClaudeReset guide

Version 1.0.0. The program has been checked by automated tests on temporary profiles; it has not yet been run for real on users' computers.

## How to open

Install the program with `ClaudeReset-1.0.0-setup.exe` ("Install", no administrator rights needed) and open it from the ClaudeReset shortcut on the desktop or in the Start menu. The window has a menu on the left: "Home", "Step 1 · Reset", "Step 2 · Proxy", "Help". Opening the window changes nothing on the computer. Everything takes two steps, in order: reset first, then the proxy. After both steps, open Claude and sign in with a new account.

The window opens in Russian by default. The ENGLISH button at the top of the left menu switches it to English (and РУССКИЙ back); the choice is remembered. The same is under Help → Appearance.

## Step 1. Reset

The reset erases everything Claude keeps on the computer: sign-in, history, settings and Claude's saved passwords in Windows. The programs themselves stay installed.

1. Choose what to keep. "Erase everything, keep memory" puts back your notes and instructions for Claude Code (CLAUDE.md files). "Erase everything" keeps nothing.
2. On the Claude website, sign out of the old account on all devices and revoke Claude Code access. The "Copy address" buttons put the link on the clipboard: paste it into the browser where you are signed in to the old account. Then tick "Done". The reset does not start without it.
3. Close Chrome and Edge if you also want to sign out of claude.ai in the browsers (the "Browsers" box is ticked by default).
4. Click "Check and clean". The program shows what it found and how much space it takes. It does everything that is safe by itself: closes Claude Desktop and Claude Code, stops the Cowork service, saves a copy of your Cowork work and a copy of your Claude Code commands, agents and settings.
5. If the program says "For you to do", do it — usually close VS Code, where Claude Code runs; the program does not close your editor. The window checks again every few seconds and continues by itself.
6. Confirm by typing ERASE. This cannot be undone.
7. At the end the program shows the result: whether everything in the checked folders is erased, whether the memory is back, whether the Claude Desktop device key was reset and whether you are signed out of claude.ai in the browsers. The device key is reset only for verified Desktop versions; for another version the result says so. The "Check by hand" list is what the program does not touch.

"Only show what is found" changes nothing.

## Step 2. Proxy and protection

The protection lets Claude reach the internet only through your proxy. Other programs work as usual. If the proxy stops answering, Claude stays offline and does not go out directly — this is intended.

1. The top of the page shows the state: "Protection is on", "Protection is off", "Protection is paused" or "Claude is offline now". Next to it is one button that fixes the current problem: check the proxy again, accept a new exit address, restart the protection or resume it.
2. Choose the proxy type: SOCKS5, HTTP or VLESS (profile file). Enter the server address, port, username and password — your proxy provider gives them to you. The password is stored only on this computer, encrypted.
3. If Claude Code inside VS Code should also go through the proxy, tick "Also protect Claude Code inside VS Code". After switching on, reload the VS Code window: Ctrl+Shift+P → "Reload Window", then /resume.
4. Click "Check and switch on protection". The program checks the connection, the sign-in and the address Claude will use on the internet, and shows that address. Confirm it, read what the protection does not cover and click "Switch on protection". Windows asks for permission — click "Yes".
5. To change the proxy while the protection is on, enter the new details and click "Check and apply the new proxy". "Switch protection off" gives Claude direct internet access again and removes the saved proxy.
6. After a program update, click "Update the protection after a program update".

## Help

"Save report" saves a file for whoever helps you. It contains no passwords, proxy addresses or user name. "Language and time zone" compares the Windows settings with the proxy's country (DE, TR or GB) and opens the right settings; the program itself does not change them.

"Appearance": the window theme — as in Windows, light or dark — and the language — as in Windows, Русский or English; the choice is remembered. Keys: Tab moves to the next button, Enter presses it, Space or Enter on a choice card selects it, Alt+1…4 open Home, Reset, Proxy and Help; in a confirmation window Enter confirms and Esc cancels.

"Uninstall ClaudeReset" (only in the installed program) switches the protection off first if it is on, then removes the program, its shortcuts and its Apps entry. Memory copies stay; the window shows their folder. "Settings → Apps → ClaudeReset → Uninstall" does the same. Confirm by typing DELETE.

## Specialist mode

The button at the bottom of the menu opens the earlier window with every tool of the program in tabs: selective reset, separate device-key and Cowork plans, filter checks, logs. It is in Russian; the Russian guide describes it.
