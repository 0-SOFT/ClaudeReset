# Пакет изоляции ClaudeReset.NetworkIsolation

Минимальный неподписанный MSIX, который даёт процессам идентичность пакета `ClaudeReset.NetworkIsolation_79st3xwgefr0c`. Запреты L1 привязаны к этой идентичности, а процессы, запущенные внутри пакета (`ClaudeResetRun.exe`), и их потомки её наследуют.

- `AppxManifest.xml` и `IdentityStub.cs` — исходники: единственное приложение `IsolatedTools` с пустой точкой входа, ничего не запускает, не читает файлы и не обращается к сети.
- `identity.msix` — собран из них 24 октября 2026 на первом ПК (makeappx из Windows SDK build tools). Неподписан.
- `identity-stub.exe` — заглушка из `IdentityStub.cs`.
- Хеши SHA-256 закреплены в `src/claude_reset/package_isolation.py`; регистрация отказывает при любом расхождении.
- Регистрация: `launcher.py --l1-package-register` (один UAC), удаление: `--l1-package-remove` (один UAC). Режим разработчика и сертификаты не меняются.
