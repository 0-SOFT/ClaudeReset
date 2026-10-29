// SPDX-License-Identifier: GPL-3.0-or-later
#include "CrBootstrapSecurity.h"
#include "CrBootstrapLaunch.h"
#include <cstdio>
#include <cwchar>
#include <vector>
#include <string>

static int checks;
static bool Check(bool value, const char* what) {
    ++checks;
    if (!value) std::fprintf(stderr, "%s (error %lu)\n", what, GetLastError());
    return value;
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && !wcscmp(argv[1], L"--owned-child")) {
        WCHAR marker[64], actualPath[MAX_PATH], windows[MAX_PATH];
        if (GetEnvironmentVariableW(L"CR_UNTRUSTED_BOOTSTRAP", marker, 64)) return 11;
        if (!GetEnvironmentVariableW(L"Path", actualPath, MAX_PATH)) return 12;
        if (!GetSystemWindowsDirectoryW(windows, MAX_PATH)) return 13;
        wcscat(windows, L"\\System32");
        return _wcsicmp(actualPath, windows) ? 14 : 0;
    }
    wchar_t path[32768];
    if (!GetModuleFileNameW(NULL, path, 32768)) return 1;
    std::wstring command = L"\"" + std::wstring(path) + L"\" --owned-child";
    std::vector<wchar_t> buffer(command.begin(), command.end()); buffer.push_back(0);
    CrBootstrapSecurity security;
    if (!Check(security.Initialize(), "initialize descriptors")) return 1;
    // These variables exist only in this test process, never in the user's shell.
    SetEnvironmentVariableW(L"CR_UNTRUSTED_BOOTSTRAP", L"must-not-reach-child");
    SetEnvironmentVariableW(L"Path", L"Z:\\untrusted");
    CrBootstrapLaunch launch;
    std::wstring home = path; home.resize(home.find_last_of(L'\\'));
    if (!Check(launch.Initialize(home.c_str()), "initialize canonical bootstrap")) return 1;
    bool ok = true;
    for (const WCHAR* invalid : {L"\\\\server\\share", L"Z:relative", L"C:\\path\\..\\home",
            L"C:\\path\\.\\home", L"C:\\path\\home ", L"C:\\path:stream", L"C:/path", L"C:\\path\"bad"})
        ok &= Check(!CrBootstrapLaunch::LocalDirectory(invalid), "reject ambiguous launch directory");
    ok &= Check(std::wstring(launch.Application()) == home + L"\\SandboxieRpcSs.exe", "fixed application path");
    ok &= Check(launch.Startup()->dwFlags == 0 && !launch.Startup()->hStdInput &&
        !launch.Startup()->lpDesktop, "startup data not inherited from client");
    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!Check(CreateProcessW(path, buffer.data(), security.Process(), security.Thread(),
            FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            launch.Environment(), launch.Directory(), &si, &pi), "create owned child")) return 1;
    const DWORD processMasks[] = {PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_CREATE_PROCESS,
        PROCESS_SET_INFORMATION, WRITE_DAC, WRITE_OWNER, PROCESS_SUSPEND_RESUME};
    const DWORD threadMasks[] = {THREAD_SET_CONTEXT, THREAD_SET_INFORMATION,
        THREAD_SET_THREAD_TOKEN, THREAD_IMPERSONATE, THREAD_DIRECT_IMPERSONATION,
        THREAD_SUSPEND_RESUME, WRITE_DAC, WRITE_OWNER};
    for (DWORD mask : processMasks) {
        SetLastError(0); HANDLE h = OpenProcess(mask, FALSE, pi.dwProcessId); DWORD error = GetLastError();
        ok &= Check(!h && error == ERROR_ACCESS_DENIED, "process denied before first instruction");
        if (h) CloseHandle(h);
    }
    for (DWORD mask : threadMasks) {
        SetLastError(0); HANDLE h = OpenThread(mask, FALSE, pi.dwThreadId); DWORD error = GetLastError();
        ok &= Check(!h && error == ERROR_ACCESS_DENIED, "initial thread denied before first instruction");
        if (h) CloseHandle(h);
    }
    HANDLE hp = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
    HANDLE ht = OpenThread(SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION, FALSE, pi.dwThreadId);
    ok &= Check(hp && ht, "limited process and thread query retained");
    if (hp) CloseHandle(hp); if (ht) CloseHandle(ht);
    // Only the creator's retained original handle is used to resume. No rights
    // are added to a client handle and no foreign process is inspected/modified.
    ok &= Check(ResumeThread(pi.hThread) == 1, "creator resumes owned child");
    DWORD wait = WaitForSingleObject(pi.hProcess, 5000);
    ok &= Check(wait == WAIT_OBJECT_0, "child exits normally");
    DWORD code = 999; GetExitCodeProcess(pi.hProcess, &code);
    ok &= Check(code == 0, "child exit success");
    if (wait != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    std::printf("{\"passed\":%s,\"checks\":%d,\"before_first_instruction\":true,"
        "\"future_threads_verified\":false,\"create_process_as_user_verified\":false,"
        "\"caller_environment_excluded\":true,"
        "\"production_clients_permitted\":false}\n", ok ? "true" : "false", checks);
    return ok ? 0 : 1;
}
