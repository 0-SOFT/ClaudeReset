# Лицензии

Собственный код ClaudeReset — **лицензия MIT** (файл LICENSE). Программа бесплатна, исходный код открыт.

Установщик и переносимый архив содержат dissect.hypervisor и dissect.extfs под AGPL-3.0, поэтому программа в этом виде распространяется на условиях AGPL-3.0; её полный исходный код — публичный репозиторий. В установщик входят только пакеты, нужные программе во время работы (`requirements-runtime.txt`): dissect.* и defusedxml; pytest и PyInstaller не входят.

sing-box в установщик не входит: движок скачивается на компьютере пользователя с официальной страницы выпусков при выборе VLESS. Переносимый Python (python-build-standalone) несёт свои тексты лицензий в `python/LICENSE.txt`. Шрифты окна — SIL Open Font License 1.1.

| Компонент | Лицензия |
|---|---|
| ClaudeReset | MIT |
| dissect.hypervisor 3.21, dissect.extfs 3.15 | AGPL-3.0-or-later |
| dissect.cstruct 4.7, dissect.util 3.24 | Apache-2.0 |
| defusedxml 0.7.1 | PSFL |
| CPython 3.12 (python-build-standalone) | PSF и лицензии в python/LICENSE.txt |
| Onest, Cormorant Garamond, IBM Plex Mono | SIL OFL 1.1 |
| sing-box 1.14.4 (скачивается во время работы, в комплект не входит) | GPL-3.0-or-later |

Ниже — оригинальные тексты лицензий без изменений.
