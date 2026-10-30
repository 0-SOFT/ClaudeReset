# Сторонние компоненты ClaudeReset

- Собственный код ClaudeReset: MIT (файл LICENSE).
- Установщик и переносимый архив включают переносимый CPython 3.12 (python-build-standalone; его лицензии в python/LICENSE.txt) и пакеты из requirements-runtime.txt: dissect.hypervisor и dissect.extfs (AGPL-3.0-or-later), dissect.cstruct и dissect.util (Apache-2.0), defusedxml (PSFL). Из-за AGPL программа в этом виде распространяется на условиях AGPL-3.0; полный соответствующий исходный код — публичный репозиторий https://github.com/0-SOFT/ClaudeReset. Тот, кто распространяет установщик, собранный из форка, обязан предоставить полный соответствующий исходный код этого форка. Архивы исходников этих пакетов лежат в third_party/sources.
- Шрифты окна, SIL Open Font License 1.1: Onest (The Onest Project Authors) и Cormorant Garamond (Cormorant Project Authors) в изменённом виде — статические начертания из вариативных файлов Google Fonts, подмножество латиница + кириллица, переименованные семейства (зарезервированных имён у этих шрифтов нет); IBM Plex Mono (IBM Corp., зарезервированное имя «Plex») без изменений. Шрифты подключаются только для окна программы и в Windows не устанавливаются.
- sing-box 1.14.4: в комплект не входит; при выборе VLESS официальный архив Windows amd64 скачивается на компьютере пользователя и сверяется с third_party/sources/sing-box-lock.json. Лицензия: GPL-3.0-or-later с дополнительным условием об имени; оригинальные тексты — в licenses/sing-box-1.14.4.
- Собственный код ClaudeReset этими уведомлениями не перелицензируется.

## Лицензии по папкам

| Путь | Лицензия |
|---|---|
| `src/`, `tools/`, `packaging/`, `examples/` | MIT (ClaudeReset), кроме шрифтов ниже |
| `src/claude_reset/assets/fonts/` | SIL OFL 1.1; текст лицензии каждого шрифта лежит рядом с ним |
| `third_party/sources/` | каждый архив сохраняет лицензию своего пакета |
| `third_party/licenses/` | оригинальные тексты лицензий без изменений |
