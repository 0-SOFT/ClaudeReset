// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "CrHelperTokenAcl.h"

// Apply only to the new restricted token returned by Token_Restrict. Never
// change a borrowed parent/service token or the owner's interactive token.
static BOOLEAN CrHelperProtectPrimaryToken(PROCESS* proc, void* original, void* restricted) {
    ULONG aclStorage[64];
    SECURITY_DESCRIPTOR descriptor;
    HANDLE tokenHandle = NULL;
    NTSTATUS status;
    if (!proc->cr_strict_broker || !proc->cr_helper_role) return TRUE;
    if (!restricted || restricted == original ||
            !CrHelperBuildTokenAcl((PACL)aclStorage, sizeof(aclStorage))) return FALSE;
    status = RtlCreateSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(status)) status = RtlSetDaclSecurityDescriptor(&descriptor, TRUE, (PACL)aclStorage, FALSE);
    if (!NT_SUCCESS(status)) return FALSE;
    status = ObOpenObjectByPointer(restricted, OBJ_KERNEL_HANDLE, NULL, WRITE_DAC,
        *SeTokenObjectType, KernelMode, &tokenHandle);
    if (!NT_SUCCESS(status)) return FALSE;
    status = ZwSetSecurityObject(tokenHandle, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &descriptor);
    ZwClose(tokenHandle);
    return NT_SUCCESS(status);
}

// Token_FilterDacl normally broadens the current process/thread DACL during
// privilege dropping. Keep the creation-time ACLs of strict bootstrap helpers.
static BOOLEAN CrHelperPreserveObjectDacl(void) {
    KIRQL irql;
    PROCESS* current = Process_Find(PsGetCurrentProcessId(), &irql);
    BOOLEAN preserve = current && current->cr_strict_broker && current->cr_helper_role;
    ExReleaseResourceLite(Process_ListLock);
    KeLowerIrql(irql);
    return preserve;
}
