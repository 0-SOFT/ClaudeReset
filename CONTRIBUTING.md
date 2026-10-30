# Contributing to ClaudeReset

Bug reports, fixes and improvements are welcome, in English or Russian.

## Reporting a problem

Open an issue with the bug template. Attach the report from the window: Help → **Save report**. It holds no
passwords, proxy addresses or user name. Security problems go through [SECURITY.md](SECURITY.md), not through issues.

## Changing the code

1. Windows 10 or 11 and Python 3.12 x64:

   ```
   py -3.12 -m venv .venv
   .venv\Scripts\python.exe -m pip install -r requirements-lock.txt
   ```

2. Before a pull request, all three must pass:

   ```
   .venv\Scripts\python.exe -m ruff check src tools packaging
   cd src
   ..\.venv\Scripts\python.exe -m pytest -q
   ```

   The tests take two to three minutes. `src/tests/test_architecture.py` is a ratchet over the architecture metrics:
   a change may keep or improve each metric; when it improves one, lower its limit in the same commit.

3. Read [docs/DEVELOPMENT.en.md](docs/DEVELOPMENT.en.md): the layers, where each feature lives and the rules. In
   short:
   - calls into Windows (`ctypes`, `winreg`, `subprocess`) only in `src/claude_reset/windows/`;
   - texts for people only in `src/claude_reset/ui/text/`; the logic returns statuses and notes;
   - a test does not patch a function of the package: the dependency comes in as a parameter;
   - names that exist on installed computers (`config.py`: tasks, packages, folders) and the command-line options
     are live contracts (`src/tests/test_live_contracts.py`); change them only on purpose, with a migration.

4. Tests replace UAC, the protection and erasing with doubles. If a change can only be verified on a real computer
   (UAC, WFP filters, a real proxy), say in the pull request what you checked and how.

## Licence of contributions

ClaudeReset's code is MIT. By sending a contribution you agree that it is published under the same licence.
