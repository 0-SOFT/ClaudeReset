// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
// Uses the documented RTL ACL routines, also exported by ntdll for native tests.
// Include the platform type/function declarations before this header.
static BOOLEAN CrHelperBuildTokenAcl(PACL acl, ULONG capacity) {
    SID systemSid = {SID_REVISION, 1, SECURITY_NT_AUTHORITY, {SECURITY_LOCAL_SYSTEM_RID}};
    SID ownerRights = {SID_REVISION, 1, SECURITY_CREATOR_SID_AUTHORITY, {4}};
    SID authenticatedUsers = {SID_REVISION, 1, SECURITY_NT_AUTHORITY, {SECURITY_AUTHENTICATED_USER_RID}};
    return NT_SUCCESS(RtlCreateAcl(acl, capacity, ACL_REVISION)) &&
        NT_SUCCESS(RtlAddAccessAllowedAce(acl, ACL_REVISION, TOKEN_ALL_ACCESS, &systemSid)) &&
        NT_SUCCESS(RtlAddAccessAllowedAce(acl, ACL_REVISION, TOKEN_QUERY | READ_CONTROL, &ownerRights)) &&
        NT_SUCCESS(RtlAddAccessAllowedAce(acl, ACL_REVISION, TOKEN_QUERY | READ_CONTROL, &authenticatedUsers));
}
