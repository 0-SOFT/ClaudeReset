// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <windows.h>
#include <sddl.h>

// Explicit creation-time ACLs close the interval before API_START_PROCESS.
// This does not protect future threads or replacement tokens: the driver must
// enforce those boundaries before production admission is possible.
class CrBootstrapSecurity {
    PSECURITY_DESCRIPTOR process_ = NULL;
    PSECURITY_DESCRIPTOR thread_ = NULL;
    SECURITY_ATTRIBUTES processAttributes_ = {};
    SECURITY_ATTRIBUTES threadAttributes_ = {};
public:
    CrBootstrapSecurity() = default;
    CrBootstrapSecurity(const CrBootstrapSecurity&) = delete;
    CrBootstrapSecurity& operator=(const CrBootstrapSecurity&) = delete;
    ~CrBootstrapSecurity() {
        if (thread_) LocalFree(thread_);
        if (process_) LocalFree(process_);
    }
    bool Initialize() {
        if (process_ || thread_) { SetLastError(ERROR_INVALID_STATE); return false; }
        // OWNER RIGHTS suppresses implicit owner WRITE_DAC; a mere AU ACE does not.
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;0x00101000;;;OW)(A;;0x00101000;;;AU)",
                SDDL_REVISION_1, &process_, NULL)) return false;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;0x00100800;;;OW)(A;;0x00100800;;;AU)",
                SDDL_REVISION_1, &thread_, NULL)) return false;
        processAttributes_ = { sizeof(SECURITY_ATTRIBUTES), process_, FALSE };
        threadAttributes_ = { sizeof(SECURITY_ATTRIBUTES), thread_, FALSE };
        return true;
    }
    LPSECURITY_ATTRIBUTES Process() { return &processAttributes_; }
    LPSECURITY_ATTRIBUTES Thread() { return &threadAttributes_; }
};
