# Third-party components of ClaudeReset

- ClaudeReset's own code: MIT (the LICENSE file).
- The installer and the portable archive include a relocatable CPython 3.12 (python-build-standalone; its licences are in python/LICENSE.txt) and the packages from requirements-runtime.txt: dissect.hypervisor and dissect.extfs (AGPL-3.0-or-later), dissect.cstruct and dissect.util (Apache-2.0), defusedxml (PSFL). Because of the AGPL, the program in that form is conveyed under the terms of the AGPL-3.0; its complete corresponding source is the public repository https://github.com/0-SOFT/ClaudeReset. Whoever distributes an installer built from a fork must offer the complete corresponding source of that fork. Source archives of these packages are in third_party/sources.
- Window fonts, SIL Open Font License 1.1: Onest (The Onest Project Authors) and Cormorant Garamond (Cormorant Project Authors) as modified versions — static weights instanced from the Google Fonts variable files, subset to Latin and Cyrillic, renamed families (these fonts have no Reserved Font Names); IBM Plex Mono (IBM Corp., Reserved Font Name "Plex") unmodified. The fonts are loaded for the program's own window only and are not installed into Windows.
- sing-box 1.14.4: not shipped; when VLESS is chosen, the official Windows amd64 archive is downloaded on the user's computer and checked against third_party/sources/sing-box-lock.json. Licence: GPL-3.0-or-later with an additional condition on the name; the original texts are in licenses/sing-box-1.14.4.
- ClaudeReset's own code is not relicensed by these notices.

## Licences by folder

| Path | Licence |
|---|---|
| `src/`, `tools/`, `packaging/`, `examples/` | MIT (ClaudeReset), except the fonts below |
| `src/claude_reset/assets/fonts/` | SIL OFL 1.1; the licence text of each font lies next to it |
| `third_party/sources/` | each archive keeps the licence of its package |
| `third_party/licenses/` | original licence texts, unchanged |
