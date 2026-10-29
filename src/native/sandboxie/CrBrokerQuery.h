// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
// Private read-only protocol with CrBrokerWindows.h. The service holds a live
// process handle across this query. Any record, including a terminated or host
// injection record, requires broker restrictions. Never consult mutable config.
static NTSTATUS CrBrokerQuery(PROCESS *caller, HANDLE pid, ULONG64 *output) {
    KIRQL irql;
    PROCESS *target;
    ULONG64 classification;
    PEPROCESS processObject;
    NTSTATUS status;
    // GUI proxy is a separate unboxed process. This read-only classification
    // grants no mutation authority to its caller.
    if (caller)
        return STATUS_ACCESS_DENIED;
    if (!pid || IS_ARG_CURRENT_PROCESS(pid)) return STATUS_INVALID_CID;
    status = PsLookupProcessByProcessId(pid, &processObject);
    if (!NT_SUCCESS(status)) return status;
    target = Process_Find(pid, &irql);
    // The exit notification removes the map record before final object teardown.
    // Check the exit flag while still holding the map lock: absence alone is not
    // proof of an unboxed process. This API is already used by upstream thread.c.
    classification = (target || PsGetProcessExitProcessCalled(processObject)) ? 0x43524202 : 0x43524201;
    ExReleaseResourceLite(Process_ListLock);
    KeLowerIrql(irql);
    ObDereferenceObject(processObject);
    __try {
        ProbeForWrite(output, sizeof(ULONG64), sizeof(ULONG64));
        *output = classification;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}
