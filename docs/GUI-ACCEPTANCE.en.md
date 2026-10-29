# ClaudeReset limits

ClaudeReset 1.0.0. This is an honest list of what the program does not do and what has not been checked.

## Reset

- The program erases the Claude Desktop and Claude Code folders from a fixed list, Claude's saved passwords in Windows and, if you choose it, the claude.ai sign-in in Chrome and Edge (cookies and IndexedDB). "Nothing is left in the checked folders" means exactly those places, not the whole computer.
- Browser cache, Local Storage, Session Storage, Service Worker and Cache Storage of claude.ai are not cleaned automatically: remove the site data in the browser settings.
- The program does not touch your projects, environment variables, WSL, Docker or SSH.
- The Claude Desktop device key is reset only for verified Desktop versions. For another version the reset result says plainly that the key was not reset.
- The program does not check the server: you sign out on all devices and revoke access on the Claude website yourself and tick that you did.
- The program does not close VS Code or browsers for you: you close them, the window waits.
- If the Cowork service cannot be stopped without administrator rights, the reset stops and asks you to do it by hand.

## Proxy and protection

- The protection covers only the own connections of Claude Desktop, Claude Code in the terminal and, if you switch it on, Claude Code in VS Code. It does not change other programs, the shared browser or the network of the whole computer.
- If the proxy does not answer or the exit address changes, Claude stays offline: it does not go out directly. This is intended.
- The protection does not cover: requests through the Windows DNS system service, the Cowork guest machine, interaction with other programs and some helper processes. The window shows this list before switching on.
- There is no backup proxy: when the proxy fails, Claude waits until you fix or change it.
- Switching the protection on and off asks for Windows permission (UAC).

## Not checked

- The program has been checked by automated tests on temporary profiles with replaced system calls. Reset and protection have not been run on users' real computers.
- The installer is not signed: Windows shows "Windows protected your PC".
- What Claude Desktop sends about time zone, language, hardware and the Windows user name has not been measured.
- Specialist mode is in Russian only.
