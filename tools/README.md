# tools

| File | What it is |
|---|---|
| `build_bundle.py` | Builds the installer and the portable archive: `.venv\Scripts\python.exe tools\build_bundle.py --out <empty folder>`. Needs internet (the bundled CPython is downloaded and checked against `packaging/bundle/python-lock.json`) and the .NET Framework C# compiler. |
| `architecture_metrics.py` | Prints the architecture metrics as JSON (`--details` lists the places). `src/tests/test_architecture.py` keeps their limits. |
| `vscode_claude_proxy.py` | Part of the program: the installer bundles it. Points the Claude Code extension of the shared VS Code at the L1 relay or undoes it (`set`, `remove`, `status`). The L1 install runs it from this folder and the command line names this path. |
| `l1_recovery_watch.py` | Body of the optional `ClaudeReset L1 Recovery` task: once a minute it starts the verified L1 controller task again. Installed tasks keep its path, so it stays here. |

The maintainer's own tools (export of the public copy, release checks, scripts of the development computer) are
not part of this repository.
