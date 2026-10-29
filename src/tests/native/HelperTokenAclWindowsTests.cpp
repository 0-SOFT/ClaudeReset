// SPDX-License-Identifier: GPL-3.0-or-later
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <vector>
extern "C" NTSYSAPI NTSTATUS NTAPI RtlCreateAcl(PACL, ULONG, ULONG);
extern "C" NTSYSAPI NTSTATUS NTAPI RtlAddAccessAllowedAce(PACL, ULONG, ACCESS_MASK, PSID);
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif
#include "CrHelperTokenAcl.h"
static unsigned checks;
static void Check(bool value, const char* label) {
    ++checks; if (!value) { std::fprintf(stderr, "%s error=%lu\n", label, GetLastError()); ExitProcess(1); }
}
int main() {
    HANDLE source = nullptr, token = nullptr;
    Check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &source), "query own token");
    Check(DuplicateTokenEx(source, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &token),
        "create private duplicate; never change current token");
    CloseHandle(source);
    DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> user(size);
    Check(GetTokenInformation(token, TokenUser, user.data(), size, &size), "read private token owner");
    ULONG storage[64] = {};
    auto acl = (PACL)storage;
    Check(CrHelperBuildTokenAcl(acl, sizeof(storage)), "build identical kernel/user ACL");
    Check(IsValidAcl(acl) && acl->AceCount == 3, "ACL structure");
    ULONG small[2] = {};
    Check(!CrHelperBuildTokenAcl((PACL)small, sizeof(small)), "short allocation fails closed");
    SECURITY_DESCRIPTOR sd;
    Check(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION), "descriptor init");
    Check(SetSecurityDescriptorOwner(&sd, ((TOKEN_USER*)user.data())->User.Sid, FALSE), "set owner");
    Check(SetSecurityDescriptorGroup(&sd, ((TOKEN_USER*)user.data())->User.Sid, FALSE), "set group");
    Check(SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE), "set DACL");
    Check(SetKernelObjectSecurity(token, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &sd),
        "apply ACL to private duplicated token object");
    const DWORD readFlags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    GetKernelObjectSecurity(token, readFlags, nullptr, 0, &size);
    std::vector<BYTE> readback(size);
    Check(GetKernelObjectSecurity(token, readFlags, readback.data(), size, &size), "read back token ACL");
    PACL actual = nullptr; BOOL present, defaulted;
    Check(GetSecurityDescriptorDacl(readback.data(), &present, &actual, &defaulted) && present && actual &&
        actual->AceCount == 3, "read back ACE count");
    for (DWORD access : std::vector<DWORD>{TOKEN_QUERY, READ_CONTROL, TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY,
            TOKEN_IMPERSONATE, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, WRITE_DAC, WRITE_OWNER,
            MAXIMUM_ALLOWED}) {
        GENERIC_MAPPING mapping = {TOKEN_READ, TOKEN_WRITE, TOKEN_EXECUTE, TOKEN_ALL_ACCESS};
        ULONG privileges[128] = {}; DWORD privilegeSize = sizeof(privileges), granted = 0; BOOL permitted = FALSE;
        Check(AccessCheck(readback.data(), token, access, &mapping, (PRIVILEGE_SET*)privileges, &privilegeSize, &granted, &permitted),
            "Windows evaluates ACL");
        bool queryOnly = access == TOKEN_QUERY || access == READ_CONTROL || access == MAXIMUM_ALLOWED;
        Check(!!permitted == queryOnly, "owner cannot acquire modifying rights");
        Check((granted & ~(TOKEN_QUERY | READ_CONTROL)) == 0, "including MAXIMUM_ALLOWED no token mutation rights");
    }
    CloseHandle(token);
    std::printf("{\"passed\":true,\"checks\":%u,\"private_duplicate_only\":true,"
        "\"live_helper_token_changed\":false,\"kernel_runtime_verified\":false}\n", checks);
}
