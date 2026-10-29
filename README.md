# ClaudeReset

**English** · [Русский](README.ru.md)

A Windows 10 and 11 program in two steps: **reset** everything Claude keeps on the computer, and **route** Claude to the internet only through your proxy. After that Claude sees you as a new user.

Free and open source. Made by [0-soft](https://0-soft.com).

The window opens in Russian by default. The **ENGLISH** button at the top of the left menu switches it to English (and **РУССКИЙ** back); the choice is remembered. The same is under Help → Appearance.

## Download and install

1. Download the latest **`ClaudeReset-…-setup.exe`** from the [Releases](../../releases/latest) page.
2. Run it and click **"Install"**. No administrator rights, Python or Git needed.
3. Windows may show "Windows protected your PC" — the installer is not signed. Click "More info" → "Run anyway".
4. Open ClaudeReset from the shortcut on the desktop or in the Start menu.

Without installing: download `ClaudeReset-…-windows-x64.zip`, unpack it and run `ClaudeReset.exe` inside.

## How to use

The window has two steps, in order.

**Step 1 · Reset.** Choose whether to keep your Claude Code memory (CLAUDE.md files), sign out of the old account on the Claude website and click "Check and clean". The program shows what it found, closes Claude by itself, saves copies of your files and, after you confirm by typing ERASE, erases the data.

**Step 2 · Proxy.** Enter the proxy address, port, username and password (SOCKS5, HTTP or a VLESS profile file) and click "Check and switch on protection". The program checks the proxy, shows the exit address and, after you agree, switches the protection on: Claude reaches the internet only through the proxy, other programs work as usual.

Then open Claude and sign in with a new account. Details: the [guide](docs/USER-GUIDE.en.md), which also opens in the window on the Help page. What the program does not do and what is not checked: [limits](docs/GUI-ACCEPTANCE.en.md).

## Uninstall

"Settings → Apps → ClaudeReset → Uninstall" or the "Uninstall ClaudeReset" button on the Help page. The program switches the protection off first if it is on.

## Licence

ClaudeReset's code is [MIT](LICENSE). The installer includes dissect.hypervisor and dissect.extfs under AGPL-3.0, so the program as an installer is conveyed under the AGPL-3.0; the complete source is this repository. Third-party components and their licences: [third_party/NOTICES.en.md](third_party/NOTICES.en.md).

## For developers

You need Python 3.12.

```
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
cd src
..\.venv\Scripts\python.exe -m pytest -q
```

From source the window starts with `ClaudeReset.cmd`. `.venv\Scripts\python.exe tools\build_bundle.py --out <empty folder>` builds the installer and the portable archive.

Layout: `src/claude_reset/shell.py` — the window; `reset_flow.py` and `proxy_flow.py` — the two steps; `brand.py` — the 0-soft look; `ui_text.py` and `ui_text_en.py` — the window's languages; `app.py` — specialist mode with every tool (Russian).
