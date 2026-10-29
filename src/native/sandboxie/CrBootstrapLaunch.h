// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <windows.h>
#include <wchar.h>
#include <string.h>

// The runtime directory still requires protected installation and verification.
// This builder removes caller-controlled startup data; it is not an ACL attestor.
class CrBootstrapLaunch {
    WCHAR application_[MAX_PATH] = {};
    WCHAR command_[MAX_PATH + 2] = {};
    WCHAR directory_[MAX_PATH] = {};
    WCHAR environment_[2048] = {};
    SIZE_T used_ = 0;
    STARTUPINFOW startup_ = {};
    bool Add(const WCHAR* key, const WCHAR* value) {
        SIZE_T a = wcslen(key), b = wcslen(value);
        if (used_ + a + b + 3 > ARRAYSIZE(environment_)) return false;
        memcpy(environment_ + used_, key, a * sizeof(WCHAR)); used_ += a;
        environment_[used_++] = L'=';
        memcpy(environment_ + used_, value, b * sizeof(WCHAR)); used_ += b;
        environment_[used_++] = 0; environment_[used_] = 0;
        return true;
    }
public:
    static bool LocalDirectory(const WCHAR* path) {
        if (!path) return false;
        SIZE_T len = wcsnlen(path, MAX_PATH);
        if (len < 3 || len >= MAX_PATH || path[1] != L':' || path[2] != L'\\' ||
            !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))) return false;
        SIZE_T component = 3;
        for (SIZE_T i = 3; i <= len; ++i) {
            WCHAR c = path[i];
            if (c == L':' || c == L'/' || c == L'"' || (c && c < 32)) return false;
            if (c == L'\\' || !c) {
                if (i == component || path[i - 1] == L'.' || path[i - 1] == L' ') return false;
                component = i + 1;
            }
        }
        return true;
    }
    bool Initialize(const WCHAR* trustedHome) {
        if (!LocalDirectory(trustedHome)) { SetLastError(ERROR_BAD_PATHNAME); return false; }
        const WCHAR suffix[] = L"\\SandboxieRpcSs.exe";
        if (wcslen(trustedHome) + ARRAYSIZE(suffix) > ARRAYSIZE(application_)) {
            SetLastError(ERROR_BUFFER_OVERFLOW); return false;
        }
        WCHAR windows[MAX_PATH] = {}, system32[MAX_PATH] = {}, temp[MAX_PATH] = {};
        UINT length = GetSystemWindowsDirectoryW(windows, ARRAYSIZE(windows));
        if (!length || length + 10 >= MAX_PATH || !LocalDirectory(windows)) {
            SetLastError(ERROR_BAD_PATHNAME); return false;
        }
        wcscpy(application_, trustedHome); wcscat(application_, suffix);
        wcscpy(directory_, trustedHome);
        wcscpy(command_, L"\""); wcscat(command_, application_); wcscat(command_, L"\"");
        wcscpy(system32, windows); wcscat(system32, L"\\System32");
        wcscpy(temp, windows); wcscat(temp, L"\\Temp");
        WCHAR drive[] = { windows[0], L':', 0 };
        used_ = 0; ZeroMemory(environment_, sizeof(environment_));
        if (!Add(L"Path", system32) || !Add(L"SystemDrive", drive) ||
            !Add(L"SystemRoot", windows) || !Add(L"TEMP", temp) || !Add(L"TMP", temp) || !Add(L"windir", windows)) {
            SetLastError(ERROR_BUFFER_OVERFLOW); return false;
        }
        ZeroMemory(&startup_, sizeof(startup_)); startup_.cb = sizeof(startup_);
        return true;
    }
    const WCHAR* Application() const { return application_; }
    WCHAR* Command() { return command_; }
    const WCHAR* Directory() const { return directory_; }
    WCHAR* Environment() { return environment_; }
    STARTUPINFOW* Startup() { return &startup_; }
};
