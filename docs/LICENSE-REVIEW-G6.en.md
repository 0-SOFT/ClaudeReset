# Licences

ClaudeReset's own code is licensed under **MIT** (the LICENSE file). The program is free and its source is open.

The installer and the portable archive include dissect.hypervisor and dissect.extfs under AGPL-3.0, so the program in that form is conveyed under the terms of the AGPL-3.0; its complete source is the public repository. The installer carries only the packages the program needs while it runs (`requirements-runtime.txt`): dissect.* and defusedxml; pytest and PyInstaller are not included.

sing-box is not part of the installer: the engine is downloaded on the user's computer from its official releases page when VLESS is chosen. The portable Python (python-build-standalone) carries its own licence texts in `python/LICENSE.txt`. The window fonts are under the SIL Open Font License 1.1.

| Component | Licence |
|---|---|
| ClaudeReset | MIT |
| dissect.hypervisor 3.21, dissect.extfs 3.15 | AGPL-3.0-or-later |
| dissect.cstruct 4.7, dissect.util 3.24 | Apache-2.0 |
| defusedxml 0.7.1 | PSFL |
| CPython 3.12 (python-build-standalone) | PSF and the licences in python/LICENSE.txt |
| Onest, Cormorant Garamond, IBM Plex Mono | SIL OFL 1.1 |
| sing-box 1.14.4 (downloaded at run time, not shipped) | GPL-3.0-or-later |

The original licence texts follow unchanged.
