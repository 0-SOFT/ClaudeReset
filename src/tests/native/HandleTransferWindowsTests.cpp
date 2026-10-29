// SPDX-License-Identifier: GPL-3.0-or-later
// Actual Windows handle transfer, with identity/box predicates stubbed only for
// our own suspended child. This is not a service/driver attestation test.
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
static DWORD childPid;
static bool CrIsStrictSandbox(ULONG pid){return pid==GetCurrentProcessId();}
static ULONG64 SbieApi_QueryProcessInfo(HANDLE pid,ULONG){return (ULONG_PTR)pid==childPid?1:0;}
class PipeServer{public:static ULONG GetCallerProcessId(){return GetCurrentProcessId();}};
class ProcessServer{public:BOOL RunSandboxedDupAndCloseHandles(HANDLE,BOOL,ULONG,PROCESS_INFORMATION*,PROCESS_INFORMATION*);};
#include "HandleTransferUnderTest.inc"
typedef LONG(NTAPI* QueryObject)(HANDLE,ULONG,void*,ULONG,ULONG*);
static DWORD access(HANDLE handle){
    ULONG data[14]={0},returned=0;
    auto query=(QueryObject)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryObject");
    if(!query || query(handle,0,data,sizeof(data),&returned)!=0)return 0;
    return data[1];
}
int main(int argc,char**){
    if(argc>1){Sleep(200);return 0;}
    WCHAR exe[MAX_PATH],command[MAX_PATH+32];
    if(!GetModuleFileNameW(NULL,exe,MAX_PATH))return 2;
    swprintf(command,MAX_PATH+32,L"\"%ls\" child",exe);
    STARTUPINFOW startup={sizeof(startup)};PROCESS_INFORMATION child={},received={};
    if(!CreateProcessW(exe,command,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,NULL,&startup,&child))return 3;
    childPid=child.dwProcessId;
    ProcessServer service;
    if(!service.RunSandboxedDupAndCloseHandles(GetCurrentProcess(),FALSE,0,&child,&received))return 4;
    DWORD processMask=access(received.hProcess),threadMask=access(received.hThread);
    bool masks=processMask==(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION) &&
               threadMask==(SYNCHRONIZE|THREAD_QUERY_LIMITED_INFORMATION);
    bool exited=WaitForSingleObject(received.hProcess,10000)==WAIT_OBJECT_0;
    CloseHandle(received.hThread);CloseHandle(received.hProcess);
    printf("{\"passed\":%s,\"process_access\":%lu,\"thread_access\":%lu,\"child_exited\":%s,"
           "\"identity_predicates_stubbed\":true,\"installed_service_test\":false}\n",
           masks&&exited?"true":"false",processMask,threadMask,exited?"true":"false");
    return masks&&exited?0:5;
}
