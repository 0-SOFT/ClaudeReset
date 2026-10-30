# Developing ClaudeReset

**English** · [Русский](DEVELOPMENT.md)

## Environment

Windows 10 or 11 and Python 3.12 x64:

```
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

`requirements-lock.txt` holds the development and build tools; `requirements-runtime.txt` holds only what the
program needs while it runs (this goes into the installer). From source the window starts with `ClaudeReset.cmd`,
which creates `.venv` by itself on the first run.

## Tests

```
.venv\Scripts\python.exe -m ruff check src tools packaging
cd src
..\.venv\Scripts\python.exe -m pytest -q
```

About two to three minutes. Run them from `src`: from the repository root the tests that start child processes
fail. The tests create temporary profiles and use the real DPAPI of the current user, a hidden Tk window and test
junctions. Without the Windows symbolic-link privilege the link tests are skipped (2 tests). `ruff` (rules in `ruff.toml`)
checks import order and use and undefined names; the ratchet runs it too. System changes (UAC, protection, erasing) are replaced by test doubles;
the `abrupt_*` tests kill their own child process in the middle of a reset of a temporary profile and check the
recovery.

## Building the installer

```
.venv\Scripts\python.exe tools\build_bundle.py --out <empty folder>
```

The result is `ClaudeReset-<version>-setup.exe` and `ClaudeReset-<version>-windows-x64.zip`: a relocatable
CPython 3.12 with Tk (python-build-standalone, its hash in `packaging/bundle/python-lock.json`; downloaded during
the build), the packages from `requirements-runtime.txt`, the program, the prebuilt protection controller (built
with PyInstaller and checked against the manifest when protection is installed), a launcher with its icon and a
manifest with the SHA-256 of every file. The launcher and the installer are compiled with the C# compiler of the
.NET Framework (`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`). The installer is not signed.

## Package layout

`src/claude_reset` is split into layers. A module imports only its own layer and the layers below it; the ratchet
test checks this (`layer_violations` = 0) and that there are no import cycles.

| Layer | Packages | What is there |
|---|---|---|
| 0 | `errors`, `config` | Exceptions; immutable product constants (task names, ports, packages) |
| 1 | `windows`, `safeio` | All work with the OS: DLLs through `windows/api.Library` (each function's prototype declared once), processes — `windows/process`, PowerShell — `windows/powershell`, registry, Task Scheduler, WFP, DPAPI; safe paths and atomic writes |
| 2 | `model`, `layout` | Types and statuses (`Enum`, `dataclass`), identifiers and time (`model/ids`), strict JSON parsing; file locations (`Paths`) |
| 3 | `reset`, `network`, `backend`, `privacy`, `elevation` | Domains: reset and erasing; proxy, the L1 controller and its installation; the local backend; privacy observations; UAC requests with a durable claim |
| 4 | `services` | Scenarios for the windows and the command line: reset, proxy, protection, diagnostics, program setup |
| 5 | `ui`, `cli` | The main window: the frame `ui/shell.py` (theme, menu, page switching, background work, questions) and the pages in `ui/pages/` — `home.py`, `reset.py`, `proxy.py`, `help.py`; the specialist window (`--expert`): `ui/expert_window.py` and the tabs in `ui/expert/` — `wizard.py` (the wizard and the server steps), `analysis.py`, `cleanup.py`, `settings.py` (time zone, network and memory), `protection.py` (network and Windows protection), `connection.py`, `policy.py`, `diagnostics.py`; window texts (`ui/text`), the command line (`cli.py`) |

Rules:

- `ctypes`, `winreg` and `subprocess` are imported only in `windows/`; a new DLL function is first declared in the
  prototype table, then called through `Library`. A new program launch goes only through `windows/process.py`.
- Module constants are immutable (`MappingProxyType`, `frozenset`, `tuple`); `global` is not used.
- Words for people live in `ui/text`; the domains return statuses (`model/status`) and notes (`model/notes`).
  The window texts are keyed by their Russian original (`tr`); the English text is in `ui/text/en.py`.
- One statement per line; in rewritten modules, lines are at most 120 characters.

## Where each feature lives

Paths are relative to `src/claude_reset`. A window calls a scenario, a scenario calls domain modules, the domains
call the platform.

| What you change | Window | Scenario | Logic | Windows |
|---|---|---|---|---|
| Step 1 · Reset | `ui/pages/reset.py`, `ui/reset_flow.py`; specialist — `ui/expert/analysis.py`, `cleanup.py` | `services/reset.py` | `reset/cleanup.py` → `reset/execution.py` (journal, recovery) → `reset/planner.py`, `reset/discovery.py`; memory — `reset/memory.py`; separate areas — `reset/cowork.py`, `desktop_keys.py`, `browser_sites.py`, `customizations.py` | `windows/inventory.py` (processes and launch settings), `dpapi.py`, `cng.py`, `cleanup_actions.py` |
| Step 2 · Proxy | `ui/pages/proxy.py`, `ui/proxy_flow.py`; specialist — `ui/expert/connection.py` | `services/proxy.py` | `network/connections.py`, `probe.py`, `remote_backend.py`, `tunnel_transport.py` | — |
| L1 protection: check, switch on, switch off | the protection card — `ui/pages/proxy.py`, `ui/protection_panel.py`; specialist — `ui/expert/protection.py` | `services/protection.py` | `network/l1_check.py`, `l1_install.py`, `l1_remove.py`, `l1_consent.py`; the controller — `controller.py`, `gate_rules.py`, `strict_wfp.py`, `relay.py`, `autostart.py` | `windows/wfp_session.py`, `wfp.py`, `tasks.py` |
| UAC requests | — | — | `elevation/request.py`, `claims.py`, `launch.py` | `windows/runas.py`, `mutex.py` |
| The installed program and its removal | `ui/pages/help.py` (Help) | `services/program_setup.py` | — | `windows/registry.py` |
| Texts, language, theme | `ui/text/ru.py`, `ui/text/en.py`, `ui/brand.py`, `ui/settings.py`; the theme's styles — `Theme` in `ui/shell.py`, the choice — `ui/pages/help.py` | — | — | `windows/display.py` |
| Specialist mode, command line | `ui/expert_window.py` (the window), its tabs — `ui/expert/`; `cli.py` | — | — | — |

File and folder names of the program and of the Claude clients are in `layout.py`, shared constants (ports, tasks,
packages) in `config.py`, statuses and document shapes in `model/`.

## Vocabulary

- **L1** — the protection: WFP rules let Claude's processes reach the network only through a local relay, and the relay
  goes out through the user's proxy. Its **controller** (`network/controller.py`) is one process with administrator
  rights. Command-line options and the controller's state folder call it **strict guard** for historical reasons
  (`--strict-guard-*`, `layout.CONTROLLER = 'strict-guard'`): installed computers hold these names, so they stay.
- **Backend** — the local tunnel engine (sing-box for VLESS) or the remote proxy (`network/remote_backend.py`) the relay
  goes out through.
- **Reset** — the plan (`reset/planner.py`), its journaled execution (`reset/execution.py`) and the wipe of fixed
  locations (`reset/cleanup.py`); **memory** — the CLAUDE.md files the reset keeps and puts back (`reset/memory.py`).
- **Claim** — the durable record of an elevated step (`elevation/claims.py`): while it is open, no other change of the
  protection starts.
- `safeio.guarded` — a check that a path stays inside its approved root, not a network guard.

## Tools

`tools/` holds four files (`tools/README.md`): the installer build `build_bundle.py`, the architecture metrics
`architecture_metrics.py` and two parts of the program that installed computers run from this path —
`vscode_claude_proxy.py` and `l1_recovery_watch.py`.

## Tests and dependencies

A test does not replace a function of the package. A dependency that has to be replaced (PowerShell, Task Scheduler,
a DLL, the network, a dialog, an area of the program) comes in as a keyword parameter whose default is the real
function or object, bound in the signature (`run=powershell.run`); a class takes them in `__init__`, never as class
attributes. A parameter keeps `None` only when its default cannot exist when the function is defined (it depends on
another argument, or is read or created on each call), and says why on its line: `# None: <reason>`. A subsystem the
tests replace as a whole is a port class (`Probe`, `protection.L1`, `reset.Actions`, `Dialogs`, `Desktop`, `Deps`).
The test passes its own double. The doubles are `tests/scripted.py`
(`Scripted` answers from a table and records the calls; `Strict` rejects a call it has no answer for),
`tests/dialog_fakes.py`, `tests/proxy_fakes.py`, `tests/wfp_fakes.py`; the command line gets the test's folders
through environment variables (`tests/cli_env.py`). DPAPI in the tests is real, of the current user. `monkeypatch`
stays for time, environment and libraries; tests do not touch package names that start with `_`.

`tests/test_live_contracts.py` with `tests/golden/live_contracts.json` pins what already installed computers depend
on: the command-line options, the WFP filter keys, the stored document formats. Change them only on purpose
(`UPDATE_LIVE_CONTRACTS=1`).

## Architecture metrics

```
.venv\Scripts\python.exe tools\architecture_metrics.py --root .
.venv\Scripts\python.exe tools\architecture_metrics.py --root . --details
```

The first command prints the metrics (cycles, layer violations, modules with OS calls, complexity, long lines,
clones, test doubles, code size); the second also lists the places. `src/tests/test_architecture.py` is a ratchet:
each metric has a recorded limit and the test fails when the metric gets worse. When a metric improves, the limit is
lowered in the same commit. A window is a frame that composes its pages and tabs: no module is longer than 800 lines
(`modules_over_800_lines`) and no class has more than 30 methods (`largest_class_methods`).

## Forking

- **Names.** The product's own names are in `config.py` (tasks, packages, services, ports) and `layout.py`
  (folders). Names that already exist on installed computers are fixed for this product; a fork that installs next
  to it should choose its own. The identity package is described by `packaging/identity/AppxManifest.xml` (with
  `IdentityStub.cs`); `identity.msix` and `identity-stub.exe` are prebuilt from them with `makeappx` from the
  Windows SDK, and their SHA-256 are pinned in `network/package_isolation.py`. The installer's publisher, folder and
  uninstall entry are in `packaging/bundle/ClaudeResetSetup.cs`; the brand is `ui/brand.py`.
- **Licences.** ClaudeReset's own code is MIT. The installer and the portable archive include dissect.hypervisor
  and dissect.extfs under AGPL-3.0-or-later, so whoever distributes an installer built from a fork must offer the
  complete corresponding source of that fork.
  Details: `third_party/NOTICES.en.md`.
- **Platform.** The program is Windows-only by design: WFP, DPAPI, CNG, MSIX, Task Scheduler and UAC are its working
  tools, not incidental dependencies.
