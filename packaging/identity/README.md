# Пакет изоляции ClaudeReset.NetworkIsolation

Минимальный неподписанный MSIX, который даёт процессам идентичность пакета `ClaudeReset.NetworkIsolation_79st3xwgefr0c`. Запреты L1 привязаны к этой идентичности, а процессы, запущенные внутри пакета (`ClaudeResetRun.exe`), и их потомки её наследуют.

- `AppxManifest.xml` и `IdentityStub.cs` — исходники: единственное приложение `IsolatedTools` с пустой точкой входа, ничего не запускает, не читает файлы и не обращается к сети.
- `identity.msix` — собран из них 24 октября 2026 (makeappx из Windows SDK build tools). Неподписан. Значки (`Assets\*.png`), на которые ссылается манифест, лежат внутри него.
- `identity-stub.exe` — заглушка из `IdentityStub.cs`.
- Хеши SHA-256 закреплены в `src/claude_reset/network/package_isolation.py`; регистрация отказывает при любом расхождении.
- Регистрация: `launcher.py --l1-package-register` (один UAC), удаление: `--l1-package-remove` (один UAC). Режим разработчика и сертификаты не меняются.

## Пересборка (для форка)

Нужен Windows SDK (`makeappx.exe`). На ПК сопровождающего этот рецепт после 24 октября 2026 не повторялся.

```
makeappx unpack /p identity.msix /d layout /nv
rem правка layout\AppxManifest.xml: Identity Name и Publisher форка
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:winexe /out:identity-stub.exe IdentityStub.cs
copy /y identity-stub.exe layout\identity-stub.exe
makeappx pack /d layout /p identity.msix /nv /o
```

Затем в `src/claude_reset/network/package_isolation.py` — новые `MSIX_SHA256`, `STUB_SHA256` и `PUBLISHER`, в
`src/claude_reset/config.py` — `OWNED_PACKAGE_NAME` и `OWNED_PACKAGE` (семейство пакета считает Windows из имени и
издателя: `Get-AppxPackage` после регистрации).

## Rebuilding (for a fork)

The Windows SDK (`makeappx.exe`) is needed. The maintainer has not repeated this recipe since 24 October 2026.

1. `makeappx unpack /p identity.msix /d layout /nv` — the icons the manifest names are inside the package.
2. Set the fork's `Identity Name` and `Publisher` in `layout\AppxManifest.xml`.
3. Compile the stub with the .NET Framework C# compiler (`csc /target:winexe /out:identity-stub.exe IdentityStub.cs`)
   and copy it into `layout`.
4. `makeappx pack /d layout /p identity.msix /nv /o`.
5. Put the new `MSIX_SHA256`, `STUB_SHA256` and `PUBLISHER` into `src/claude_reset/network/package_isolation.py` and
   the new `OWNED_PACKAGE_NAME` and `OWNED_PACKAGE` into `src/claude_reset/config.py` (Windows derives the package
   family from the name and publisher; `Get-AppxPackage` shows it after registration).
