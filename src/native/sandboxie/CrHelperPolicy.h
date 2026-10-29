// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

enum { CR_HELPER_NONE = 0, CR_HELPER_RPCSS = 1, CR_HELPER_DCOM = 2 };

static int CrHelperNameEquals(const wchar_t* value, const wchar_t* expected) {
    if (!value) return 0;
    while (*value && *expected) {
        wchar_t c = *value++;
        if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
        if (c != *expected++) return 0;
    }
    return *value == 0 && *expected == 0;
}

static unsigned char CrHelperImageRole(int homeImage, const wchar_t* name) {
    if (!homeImage) return CR_HELPER_NONE;
    if (CrHelperNameEquals(name, L"sandboxierpcss.exe")) return CR_HELPER_RPCSS;
    if (CrHelperNameEquals(name, L"sandboxiedcomlaunch.exe")) return CR_HELPER_DCOM;
    return CR_HELPER_NONE;
}

static int CrHelperCreationAllowed(int strict, int homeImage, unsigned char role,
        int actualServiceCreator, int actualRpcssCreator, int boundaryReady) {
    if (!strict) return 1;
    if (!boundaryReady) return 0;
    if (!homeImage) return role == CR_HELPER_NONE;
    // An arbitrary executable in the runtime directory must never inherit its
    // LSA exception. Direct launch of even a correctly named helper is denied.
    return (role == CR_HELPER_RPCSS && actualServiceCreator) ||
           (role == CR_HELPER_DCOM && actualRpcssCreator);
}

static unsigned long CrHelperFilterAccess(unsigned long access, int entireProcess) {
    // Only the flags documented as modifiable by ObRegisterCallbacks. In
    // particular this does NOT claim to remove WRITE_DAC/WRITE_OWNER/VM_READ.
    const unsigned long process = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD |
        PROCESS_DUP_HANDLE | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION |
        PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    const unsigned long thread = THREAD_DIRECT_IMPERSONATION | THREAD_IMPERSONATE |
        THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION |
        THREAD_SET_THREAD_TOKEN | THREAD_SUSPEND_RESUME | THREAD_TERMINATE;
    return access & ~(entireProcess ? process : thread);
}
