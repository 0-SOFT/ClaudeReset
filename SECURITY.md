# Security policy

## Reporting a vulnerability

Report it privately: on GitHub open **Security → Report a vulnerability** in this repository. Do not open a public
issue for it. Describe the version, the steps and what an attacker gains; never include real passwords or proxy
credentials.

## Supported versions

The latest release. Fixes go into a new release; older versions are not patched.

## What is in scope

ClaudeReset erases Claude's data, asks for administrator rights (UAC) to switch the protection on and off, and keeps
Windows Filtering Platform rules that let Claude reach the internet only through the user's proxy. Especially in scope:

- another program or user changing, removing or getting around the protection's rules, tasks or files;
- the program erasing or exposing data outside the locations it shows before erasing;
- proxy credentials, exit addresses, user names or paths leaking into reports, logs or saved files;
- an elevated step doing more than the operation the user confirmed.

Known limits of the protection are listed in [docs/GUI-ACCEPTANCE.en.md](docs/GUI-ACCEPTANCE.en.md); a report that
one of them can be closed is welcome too.
