// SPDX-License-Identifier: GPL-3.0-or-later
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <map>
#include <string>
#include <initializer_list>

using KIRQL = unsigned char;
struct BOX { ULONG session_id; const wchar_t* name; const wchar_t* sid; };
struct PROCESS {
    BOX* box; BOOLEAN cr_strict_broker; UCHAR cr_helper_role;
    BOOLEAN bHostInject; ULONG terminated; BOOLEAN image_sbie;
    const wchar_t* image_name; BOOLEAN bAppCompartment; BOOLEAN disable_object_flt;
    HANDLE pid; void* primary_token; void* threads_lock;
};
static std::map<HANDLE, PROCESS*> Process_Map;
static int lockDepth, calls, assertions;
static void* Process_ListLock;
static HANDLE Api_ServiceProcessId = (HANDLE)100;
static BOOLEAN Obj_CallbackInstalled = TRUE;
static ULONG Driver_OsVersion = 10;
#define DRIVER_WINDOWS_7 7
#define _FX
static void Require(bool ok, const char* message) {
    ++assertions; if (!ok) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
static PROCESS* map_get(std::map<HANDLE,PROCESS*>* map, HANDLE id) {
    Require(lockDepth > 0, "map lookup without held lock");
    auto i = map->find(id); return i == map->end() ? nullptr : i->second;
}
static PROCESS* Process_Find(HANDLE id, KIRQL* irql) {
    ++lockDepth; *irql = 0; return map_get(&Process_Map, id);
}
static void ExReleaseResourceLite(void*) { Require(lockDepth >= 1, "unbalanced lock"); --lockDepth; }
static void KeLowerIrql(KIRQL) {}
static std::map<std::wstring, BOOLEAN> config = {{L"DropAdminRights", TRUE}};
static BOOLEAN Conf_Get_Boolean(const wchar_t*, const wchar_t* name, int, BOOLEAN fallback) {
    auto i = config.find(name); return i == config.end() ? fallback : i->second;
}
#include "CrHelperDriver.h"

using PEPROCESS = void*;
struct FakeThread { HANDLE processId; };
using PETHREAD = FakeThread*;
static int processType, threadType, otherType;
static void* processTypePointer = &processType;
static void* threadTypePointer = &threadType;
static void** PsProcessType = &processTypePointer;
static void** PsThreadType = &threadTypePointer;
enum { OB_OPERATION_HANDLE_CREATE = 1, OB_OPERATION_HANDLE_DUPLICATE = 2, OB_PREOP_SUCCESS = 0 };
using OB_PREOP_CALLBACK_STATUS = int;
struct Params {
    struct { ACCESS_MASK DesiredAccess; } CreateHandleInformation;
    struct { ACCESS_MASK DesiredAccess; PEPROCESS TargetProcess; } DuplicateHandleInformation;
};
struct PreInfo { int KernelHandle; int Operation; Params* Parameters; void* ObjectType; void* Object; };
using POB_PRE_OPERATION_INFORMATION = PreInfo*;
static HANDLE currentPid = (HANDLE)200;
static HANDLE PsGetCurrentProcessId() { return currentPid; }
static HANDLE PsGetProcessId(PEPROCESS p) { return (HANDLE)p; }
static HANDLE PsGetThreadProcessId(PETHREAD t) { return t->processId; }
static PEPROCESS PsGetThreadProcess(PETHREAD t) { return t->processId; }
static PEPROCESS PsGetThreadProcess(void* t) { return ((PETHREAD)t)->processId; }
static void DbgPrint(const char*) {}
static ACCESS_MASK Thread_CheckObject_CommonEx(HANDLE, PEPROCESS, ACCESS_MASK access, BOOLEAN, BOOLEAN) {
    ++calls; return access; // models the upstream same-box/disable-filter shortcut
}
#include "HelperObjectCallbackUnderTest.inc"

// Real extracted token wrapper bodies. Object manager, identity and SEH input
// probing are test doubles; these are NOT live kernel syscall tests.
using NTSTATUS = LONG;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define STATUS_NO_TOKEN ((NTSTATUS)0xc000007c)
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define DRIVER_WINDOWS_VISTA 6
#define UserMode 1
#define TOKEN_DENIED_ACCESS_MASK ~(STANDARD_RIGHTS_READ | GENERIC_READ | SYNCHRONIZE | TOKEN_QUERY | TOKEN_QUERY_SOURCE)
static void* tokenTypePointer;
static void** SeTokenObjectType = &tokenTypePointer;
static std::map<void*, int> references;
static int tokenOpens, switched, kernelCloses;
static bool tokenOpenFails, tokenSetFails;
static void* lastTokenObject;
static SECURITY_INFORMATION lastSecurityFlags;
static bool referenceFails;
static void ProbeForWrite(void*, SIZE_T, ULONG) {}
static NTSTATUS ObReferenceObjectByHandle(HANDLE h, ACCESS_MASK, void*, int, void** out, void*) {
    if (referenceFails) return STATUS_ACCESS_DENIED;
    *out = h; ++references[h]; return STATUS_SUCCESS;
}
static void ObReferenceObject(void* p) { ++references[p]; }
static void ObDereferenceObject(void* p) { --references[p]; }
static NTSTATUS ObOpenObjectByPointer(void* object, int, void*, ACCESS_MASK, void*, int, HANDLE* out) {
    ++tokenOpens; lastTokenObject = object;
    if (tokenOpenFails) return STATUS_ACCESS_DENIED;
    *out = (HANDLE)900; return STATUS_SUCCESS;
}
static PROCESS* Thread_FindAndInitProcess(PROCESS*, void* object, KIRQL* irql) {
    return Process_Find(object, irql);
}
static NTSTATUS Thread_GetKernelHandleForUserHandle(HANDLE* out, HANDLE h) { *out = h; return STATUS_SUCCESS; }
static NTSTATUS ZwOpenProcessToken(HANDLE, ACCESS_MASK, HANDLE* out) { ++tokenOpens; *out = (HANDLE)900; return STATUS_SUCCESS; }
static void ZwClose(HANDLE) { ++kernelCloses; }
static NTSTATUS Thread_OpenThreadToken_SwitchToken(void* newToken, void**, BOOLEAN*, BOOLEAN*, SECURITY_IMPERSONATION_LEVEL*) {
    switched += newToken ? 1 : -1; return STATUS_SUCCESS;
}
struct THREAD { void* token_object; BOOLEAN token_CopyOnOpen; BOOLEAN token_EffectiveOnly;
    SECURITY_IMPERSONATION_LEVEL token_ImpersonationLevel; };
static THREAD fakeThread = {(void*)800, FALSE, FALSE, SecurityImpersonation};
static void ExAcquireResourceExclusiveLite(void*, BOOLEAN) { ++lockDepth; }
static HANDLE PsGetThreadId(void* t) { return t; }
static THREAD* Thread_GetOrCreate(PROCESS*, HANDLE, BOOLEAN) { return &fakeThread; }
static NTSTATUS Thread_OpenThreadToken_OpenHandle(void*, BOOLEAN, BOOLEAN, SECURITY_IMPERSONATION_LEVEL,
        ACCESS_MASK, HANDLE* out, void*) { ++tokenOpens; *out = (HANDLE)900; return STATUS_SUCCESS; }
static NTSTATUS ZwOpenThreadToken(HANDLE, ACCESS_MASK, BOOLEAN, HANDLE* out) { ++tokenOpens; *out = (HANDLE)900; return STATUS_SUCCESS; }
#include "HelperProcessTokenUnderTest.inc"
#include "HelperThreadTokenUnderTest.inc"
extern "C" NTSYSAPI NTSTATUS NTAPI RtlCreateAcl(PACL, ULONG, ULONG);
extern "C" NTSYSAPI NTSTATUS NTAPI RtlAddAccessAllowedAce(PACL, ULONG, ACCESS_MASK, PSID);
extern "C" NTSYSAPI NTSTATUS NTAPI RtlCreateSecurityDescriptor(PSECURITY_DESCRIPTOR, ULONG);
extern "C" NTSYSAPI NTSTATUS NTAPI RtlSetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN);
#define OBJ_KERNEL_HANDLE 0x200
#define KernelMode 0
static NTSTATUS ZwSetSecurityObject(HANDLE, SECURITY_INFORMATION flags, PSECURITY_DESCRIPTOR descriptor) {
    lastSecurityFlags = flags;
    PACL acl; BOOL present, defaulted;
    Require(GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) && present && acl->AceCount == 3,
        "kernel token wrapper applies the tested ACL");
    return tokenSetFails ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}
#include "CrHelperTokenDriver.h"

static bool Admit(PROCESS& process, HANDLE caller, HANDLE parent, BOOLEAN inherited = FALSE, BOOLEAN inject = FALSE) {
    Require(lockDepth == 0, "admit initially unlocked"); ++lockDepth;
    bool allowed = CrHelperAdmitProcess(&process, caller, parent, inherited, inject);
    --lockDepth; return allowed;
}
static ACCESS_MASK Open(HANDLE objectPid, bool thread, bool duplicate = false,
        HANDLE recipient = (HANDLE)200, int kernel = 0, ACCESS_MASK mask = 0x1fffff) {
    Params params = {}; params.CreateHandleInformation.DesiredAccess = mask;
    params.DuplicateHandleInformation.DesiredAccess = mask;
    params.DuplicateHandleInformation.TargetProcess = recipient;
    FakeThread t = { objectPid };
    PreInfo info = { kernel, duplicate ? 2 : 1, &params, thread ? *PsThreadType : *PsProcessType,
        thread ? (void*)&t : (void*)objectPid };
    Obj_PreOperationCallback(nullptr, &info);
    Require(lockDepth == 0, "callback releases lock");
    return duplicate ? params.DuplicateHandleInformation.DesiredAccess : params.CreateHandleInformation.DesiredAccess;
}

int main() {
    BOX box = {1, L"Fixture", L"S-1-5-21-1"}, otherAccount = {1, L"Fixture", L"S-1-5-21-2"};
    PROCESS client = {&box, TRUE, 0, FALSE, 0, FALSE, L"client.exe", FALSE, FALSE};
    PROCESS rpcss = {&box, TRUE, 0, FALSE, 0, TRUE, L"SandboxieRpcSs.exe", FALSE, FALSE};
    PROCESS dcom = {&box, TRUE, 0, FALSE, 0, TRUE, L"SandboxieDcomLaunch.exe", FALSE, FALSE};
    Process_Map[(HANDLE)200] = &client;
    Process_Map[(HANDLE)300] = &rpcss;
    Process_Map[(HANDLE)400] = &dcom;
    client.pid = (HANDLE)200; rpcss.pid = (HANDLE)300; dcom.pid = (HANDLE)400;
    client.primary_token = (void*)701; rpcss.primary_token = (void*)702; dcom.primary_token = (void*)703;
    Require(CrHelperCallerStrict((HANDLE)200), "actual caller strict snapshot before parent selection");
    Require(!CrHelperCallerStrict(Api_ServiceProcessId), "unboxed caller not classified as client");
    Require(!Admit(rpcss, (HANDLE)200, (HANDLE)200), "client direct RpcSs denied");
    Require(!Admit(rpcss, (HANDLE)200, Api_ServiceProcessId), "spoofed service parent denied");
    Require(Admit(rpcss, Api_ServiceProcessId, Api_ServiceProcessId), "actual service RpcSs admitted");
    Require(rpcss.cr_helper_role == CR_HELPER_RPCSS, "stored RpcSs role");
    Require(!Admit(dcom, (HANDLE)200, (HANDLE)300), "spoofed RpcSs parent denied");
    Require(Admit(dcom, (HANDLE)300, (HANDLE)300), "actual RpcSs Dcom admitted");
    dcom.box = &otherAccount;
    Require(!Admit(dcom, (HANDLE)300, (HANDLE)300), "other account same box name denied");
    dcom.box = &box;
    Require(!Admit(dcom, Api_ServiceProcessId, Api_ServiceProcessId), "service cannot arbitrarily bootstrap Dcom");
    PROCESS unknown = rpcss; unknown.image_name = L"Start.exe";
    Require(!Admit(unknown, Api_ServiceProcessId, Api_ServiceProcessId), "other runtime executable denied");
    PROCESS lookalike = client; lookalike.image_name = L"SandboxieRpcSs.exe";
    Require(Admit(lookalike, (HANDLE)200, (HANDLE)200) && lookalike.cr_helper_role == 0, "copied helper is ordinary client");
    for (const wchar_t* name : {L"SandboxieRpcSs.exe.evil", L"SandboxieRpcSs.exe ", L"dir\\SandboxieRpcSs.exe", L"", (const wchar_t*)nullptr})
        Require(CrHelperImageRole(TRUE, name) == 0, "exact basename required");
    Require(CrHelperImageRole(TRUE, L"SANDBOXIERPCSS.EXE") == 1, "case insensitive canonical name");
    PROCESS descendant = client; descendant.cr_strict_broker = FALSE;
    Require(Admit(descendant, (HANDLE)200, (HANDLE)200, TRUE) && descendant.cr_strict_broker,
        "descendant inherits strict even after config removed");
    Obj_CallbackInstalled = FALSE;
    Require(!Admit(client, (HANDLE)200, (HANDLE)200), "no callback no admission");
    Obj_CallbackInstalled = TRUE;
    Require(!Admit(client, (HANDLE)200, (HANDLE)200, FALSE, TRUE), "host inject no admission");
    for (const wchar_t* setting : {L"OriginalToken", L"UnfilteredToken", L"UnrestrictedToken", L"ReplicateToken",
            L"UnstrippedToken", L"KeepTokenIntegrity", L"RunRpcssAsSystem", L"RunServicesAsSystem"}) {
        config[setting] = TRUE;
        Require(!Admit(client, (HANDLE)200, (HANDLE)200), "unsafe token mode no admission");
        config.erase(setting);
    }
    config[L"DropAdminRights"] = FALSE;
    Require(!Admit(client, (HANDLE)200, (HANDLE)200), "rights dropping required");
    config[L"DropAdminRights"] = TRUE;
    client.disable_object_flt = TRUE;
    Require(!Admit(client, (HANDLE)200, (HANDLE)200), "disabled filter no admission");
    for (DWORD access : std::initializer_list<DWORD>{TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY, TOKEN_IMPERSONATE,
            TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, WRITE_DAC, WRITE_OWNER,
            MAXIMUM_ALLOWED, GENERIC_ALL, TOKEN_ALL_ACCESS}) {
        Require(!CrHelperTokenAccessAllowed((HANDLE)300, (HANDLE)200, access), "client helper token privilege denied");
        Require(CrHelperTokenAccessAllowed((HANDLE)300, (HANDLE)300, access), "helper own token unchanged");
        Require(CrHelperTokenAccessAllowed((HANDLE)999, (HANDLE)200, access), "unrelated token delegated to upstream");
    }
    Require(CrHelperTokenAccessAllowed((HANDLE)300, (HANDLE)200, TOKEN_QUERY | READ_CONTROL), "read-only token query allowed");
    FakeThread helperThread = {(HANDLE)300};
    for (DWORD access : std::initializer_list<DWORD>{TOKEN_DUPLICATE, TOKEN_ADJUST_DEFAULT, WRITE_DAC, MAXIMUM_ALLOWED}) {
        HANDLE out = nullptr; tokenOpens = 0;
        Require(Thread_OpenProcessToken_Common(&client, (HANDLE)300, access, &out) == STATUS_ACCESS_DENIED,
            "actual process token wrapper denies");
        Require(!out && !tokenOpens && lockDepth == 0, "process denial before token open and without lock leak");
        for (BOOLEAN asSelf : {FALSE, TRUE}) {
            Require(Thread_OpenThreadToken_Common(&client, &helperThread, access, asSelf, &out) == STATUS_ACCESS_DENIED,
                "actual thread token wrapper denies");
            Require(!out && !tokenOpens && switched == 0 && lockDepth == 0,
                "thread denial restores impersonation and lock");
        }
        for (const auto& ref : references) Require(ref.second == 0, "denial releases object references");
    }
    HANDLE queryToken = nullptr; tokenOpens = 0;
    Require(Thread_OpenProcessToken_Common(&client, (HANDLE)300, TOKEN_QUERY, &queryToken) == STATUS_SUCCESS &&
        tokenOpens == 1 && queryToken, "actual wrapper retains read-only token query");
    queryToken = nullptr; tokenOpens = 0;
    Require(Thread_OpenThreadToken_Common(&client, &helperThread, TOKEN_QUERY, TRUE, &queryToken) == STATUS_SUCCESS &&
        tokenOpens == 1 && queryToken && switched == 0 && lockDepth == 0, "thread token read-only query releases nested locks");
    referenceFails = true; queryToken = nullptr; tokenOpens = 0;
    Require(Thread_OpenThreadToken_Common(&client, &helperThread, TOKEN_QUERY, TRUE, &queryToken) == STATUS_ACCESS_DENIED &&
        tokenOpens == 0 && !queryToken && switched == 0, "invalid thread handle restores impersonation");
    Require(Thread_OpenProcessToken_Common(&client, (HANDLE)300, TOKEN_QUERY, &queryToken) == STATUS_ACCESS_DENIED &&
        tokenOpens == 0 && !queryToken, "invalid process handle denied before token access");
    referenceFails = false;
    for (const auto& ref : references) Require(ref.second == 0, "query releases references");
    Require(!CrHelperPreserveObjectDacl(), "ordinary client DACL handling unchanged");
    currentPid = (HANDLE)300;
    Require(CrHelperPreserveObjectDacl(), "helper initial object ACLs preserved during token filtering");
    Require(!CrHelperProtectPrimaryToken(&rpcss, (void*)701, (void*)701), "never alter borrowed original token");
    Require(!CrHelperProtectPrimaryToken(&rpcss, (void*)701, nullptr), "null token refused");
    tokenOpens = kernelCloses = 0;
    Require(CrHelperProtectPrimaryToken(&rpcss, (void*)701, (void*)702), "new helper primary token protected");
    Require(lastTokenObject == (void*)702 && tokenOpens == 1 && kernelCloses == 1 &&
        lastSecurityFlags == (DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION), "private token and protected ACL only");
    tokenOpenFails = true;
    Require(!CrHelperProtectPrimaryToken(&rpcss, (void*)701, (void*)702), "token open failure prevents admission");
    tokenOpenFails = false; tokenSetFails = true; kernelCloses = 0;
    Require(!CrHelperProtectPrimaryToken(&rpcss, (void*)701, (void*)702) && kernelCloses == 1,
        "token ACL failure closes kernel handle and prevents admission");
    tokenSetFails = false; currentPid = (HANDLE)200;
    // Even if an existing client's option is inconsistent, callback filtering is first.
    for (bool thread : {false, true}) {
        DWORD deny = thread ? (THREAD_SET_CONTEXT | THREAD_SET_THREAD_TOKEN | THREAD_DIRECT_IMPERSONATION |
            THREAD_IMPERSONATE | THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE) :
            (PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
             PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE);
        Require((Open((HANDLE)300, thread) & deny) == 0, "same box dangerous open denied");
        Require((Open((HANDLE)300, thread, true) & deny) == 0, "client duplication denied");
        currentPid = Api_ServiceProcessId;
        Require((Open((HANDLE)300, thread, true) & deny) == 0, "service duplicate into client filtered");
        Require(Open((HANDLE)300, thread) == 0x1fffff, "unboxed service own handles preserved");
        currentPid = (HANDLE)300;
        Require(Open((HANDLE)300, thread) == 0x1fffff, "helper self handles preserved");
        Require((Open((HANDLE)300, thread, true) & deny) == 0, "self duplicate into client filtered before self shortcut");
        Require(Open((HANDLE)400, thread) == 0x1fffff, "verified RpcSs can bootstrap Dcom");
        dcom.box = &otherAccount;
        Require((Open((HANDLE)400, thread) & deny) == 0, "helper exemption does not cross account");
        dcom.box = &box;
        currentPid = (HANDLE)200;
        Require(Open((HANDLE)300, thread, false, (HANDLE)200, 1) == 0x1fffff, "kernel handles untouched");
        Require(Open((HANDLE)999, thread) == 0x1fffff, "unrelated process untouched");
        Require(Open((HANDLE)300, thread, false, (HANDLE)200, 0, WRITE_DAC) == WRITE_DAC,
            "unsupported standard right not falsely declared filtered");
        for (unsigned bit = 0; bit < 32; ++bit) {
            DWORD access = DWORD(1) << bit;
            Require((Open((HANDLE)300, thread, false, (HANDLE)200, 0, access) & ~access) == 0, "never adds rights");
        }
    }
    std::printf("{\"passed\":true,\"assertions\":%d,\"kernel_identity_stubs\":true,"
        "\"kernel_runtime_verified\":false,\"production_clients_permitted\":false}\n", assertions);
}
