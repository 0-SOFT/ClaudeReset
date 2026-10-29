// SPDX-License-Identifier: GPL-3.0-or-later
// Included after the upstream driver declarations, not a user-mode component.
#pragma once
#include "CrHelperPolicy.h"

static BOOLEAN CrHelperCallerStrict(HANDLE callerId) {
    KIRQL irql;
    PROCESS* caller = Process_Find(callerId, &irql);
    BOOLEAN strict = caller && caller->cr_strict_broker;
    ExReleaseResourceLite(Process_ListLock);
    KeLowerIrql(irql);
    return strict;
}

// Caller holds Process_ListLock; compare account as well as box/session.
static BOOLEAN CrHelperSameBox(const PROCESS* a, const PROCESS* b) {
    return a && b && a->box && b->box && a->box->sid && b->box->sid &&
        a->box->session_id == b->box->session_id &&
        _wcsicmp(a->box->name, b->box->name) == 0 &&
        _wcsicmp(a->box->sid, b->box->sid) == 0;
}

// Called before the legacy same-box/self/DisableObjectFilter shortcuts. Both
// the active caller and the receiving process of a duplication are checked.
static ACCESS_MASK CrHelperHandleAccess(HANDLE targetId, HANDLE requesterId,
        ACCESS_MASK access, BOOLEAN entireProcess) {
    KIRQL irql;
    BOOLEAN filter = FALSE;
    PROCESS* target;
    PROCESS* requester;
    if (!targetId || !requesterId || targetId == requesterId) return access;
    target = Process_Find(targetId, &irql);
    // Process_Find holds the shared map lock until the matching release below.
    requester = (PROCESS*)map_get(&Process_Map, requesterId);
    if (target && target->cr_strict_broker && target->cr_helper_role &&
            requester && requester->box && !requester->bHostInject) {
        // RpcSs needs the initial DcomLaunch handles to complete bootstrap.
        // This exception is a stored creation-time role, never a current name.
        filter = !(requester->cr_strict_broker &&
            requester->cr_helper_role == CR_HELPER_RPCSS &&
            target->cr_helper_role == CR_HELPER_DCOM &&
            !requester->terminated && CrHelperSameBox(requester, target));
    }
    ExReleaseResourceLite(Process_ListLock);
    KeLowerIrql(irql);
    return filter ? CrHelperFilterAccess(access, entireProcess) : access;
}

// The upstream same-box token wrapper returns the saved unrestricted token.
// Restrict the request BEFORE that wrapper can open it, including MAXIMUM_ALLOWED.
static BOOLEAN CrHelperTokenAccessAllowed(HANDLE targetId, HANDLE requesterId, ACCESS_MASK access) {
    if (!(access & ~(TOKEN_QUERY | READ_CONTROL))) return TRUE;
    return CrHelperHandleAccess(targetId, requesterId, PROCESS_CREATE_THREAD, TRUE) != 0;
}

static BOOLEAN CrHelperTokenSettingsSafe(PROCESS* child) {
    static const WCHAR* unsafe[] = {L"OriginalToken", L"UnfilteredToken", L"UnrestrictedToken",
        L"ReplicateToken", L"UnstrippedToken", L"KeepTokenIntegrity", L"RunRpcssAsSystem", L"RunServicesAsSystem"};
    ULONG i;
    if (!child->cr_strict_broker) return TRUE;
    if (!Conf_Get_Boolean(child->box->name, L"DropAdminRights", 0, FALSE)) return FALSE;
    for (i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); ++i)
        if (Conf_Get_Boolean(child->box->name, unsafe[i], 0, FALSE)) return FALSE;
    return TRUE;
}

// Called with the exclusive process-map lock held, before low-level injection
// or return from the create notification. Service-created RpcSs is still
// suspended at API_START_PROCESS and has explicit creation-time object ACLs.
static BOOLEAN CrHelperAdmitProcess(PROCESS* child, HANDLE callerId, HANDLE parentId,
        BOOLEAN inheritedStrict, BOOLEAN hostInject) {
    PROCESS* creator = (PROCESS*)map_get(&Process_Map, callerId);
    BOOLEAN serviceCreator = Api_ServiceProcessId && callerId == Api_ServiceProcessId &&
        parentId == Api_ServiceProcessId;
    BOOLEAN rpcssCreator = creator && !creator->terminated && !creator->bHostInject &&
        creator->cr_strict_broker && creator->cr_helper_role == CR_HELPER_RPCSS &&
        callerId == parentId && CrHelperSameBox(creator, child);
    unsigned char role = CrHelperImageRole(child->image_sbie, child->image_name);
    child->cr_strict_broker = child->cr_strict_broker || inheritedStrict;
    if (!CrHelperCreationAllowed(child->cr_strict_broker, child->image_sbie, role,
            serviceCreator, rpcssCreator, Obj_CallbackInstalled &&
            Driver_OsVersion >= DRIVER_WINDOWS_7 && !hostInject &&
            !child->bAppCompartment && !child->disable_object_flt &&
            CrHelperTokenSettingsSafe(child))) return FALSE;
    child->cr_helper_role = child->cr_strict_broker ? role : CR_HELPER_NONE;
    return TRUE;
}
