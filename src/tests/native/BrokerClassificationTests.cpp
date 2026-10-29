// SPDX-License-Identifier: GPL-3.0-or-later
// Real classifier bodies, modeled Win32/driver boundary; no installed runtime.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
using ULONG=uint32_t; using ULONG64=uint64_t; using ULONG_PTR=uintptr_t;
using HANDLE=void*; using NTSTATUS=uint32_t; using KIRQL=int;
struct PROCESS { bool terminated; };
const ULONG SYNCHRONIZE=0x100000, PROCESS_QUERY_LIMITED_INFORMATION=0x1000;
const ULONG WAIT_TIMEOUT=258, WAIT_FAILED=0xffffffff, FALSE=0;
const NTSTATUS STATUS_ACCESS_DENIED=0xc0000022, STATUS_INVALID_CID=0xc000000b, STATUS_SUCCESS=0;
static void check(bool yes){if(!yes){fprintf(stderr,"classifier assertion failed\n");exit(3);}}
static bool openOk; static ULONG waits[2]; static unsigned waitCalls,opens,closes,queries;
static ULONG64 classification;
static HANDLE OpenProcess(ULONG access,ULONG inherit,ULONG pid){
 check(access==(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION)&&!inherit&&pid==123);
 ++opens;return openOk?(HANDLE)123:nullptr;
}
static ULONG WaitForSingleObject(HANDLE h,ULONG timeout){check(h==(HANDLE)123&&!timeout&&waitCalls<2);return waits[waitCalls++];}
static bool CloseHandle(HANDLE h){check(h==(HANDLE)123);++closes;return true;}
static ULONG64 SbieApi_QueryProcessInfo(HANDLE h,ULONG type){check(h==(HANDLE)123&&type==0x63726270);++queries;return classification;}
#include "BrokerClassifierUnderTest.inc"
using PEPROCESS=void*;
static bool lookupOk,exitCalled;
static unsigned lookups,dereferences;
#define NT_SUCCESS(s) ((int32_t)(s)>=0)
static NTSTATUS PsLookupProcessByProcessId(HANDLE pid,PEPROCESS* out){check(pid==(HANDLE)123);++lookups;if(!lookupOk)return STATUS_INVALID_CID;*out=(void*)456;return 0;}
static bool PsGetProcessExitProcessCalled(PEPROCESS p){check(p==(void*)456);return exitCalled;}
static void ObDereferenceObject(PEPROCESS p){check(p==(void*)456);++dereferences;}
static int Process_ListLock, locked,finds,probes; static PROCESS* targetRecord;
#define IS_ARG_CURRENT_PROCESS(p) ((p)==(HANDLE)-1)
static PROCESS* Process_Find(HANDLE pid,KIRQL* irql){check(pid==(HANDLE)123&&!locked);++finds;locked=1;*irql=7;return targetRecord;}
static void ExReleaseResourceLite(int){check(locked==1);locked=0;}
static void KeLowerIrql(KIRQL irql){check(irql==7&&!locked);}
static void ProbeForWrite(void* p,size_t size,size_t align){check(p&&size==8&&align==8&&!locked);++probes;}
#define __try try
#define __except(x) catch(...)
#define EXCEPTION_EXECUTE_HANDLER 1
static NTSTATUS GetExceptionCode(){return STATUS_ACCESS_DENIED;}
#include "CrBrokerQuery.h"
int main(){
 unsigned serviceChecks=0,driverChecks=0;
 for(bool opened:{false,true})for(ULONG first:{0u,WAIT_TIMEOUT,WAIT_FAILED})
 for(ULONG last:{0u,WAIT_TIMEOUT,WAIT_FAILED})for(ULONG64 value:{0ull,0x43524201ull,0x43524202ull,1ull,0xffffffffffffffffull}){
  openOk=opened;waits[0]=first;waits[1]=last;classification=value;
  waitCalls=opens=closes=queries=0;
  bool result=CrIsStrictSandbox(123);
  bool expected=!(opened&&first==WAIT_TIMEOUT&&last==WAIT_TIMEOUT&&value==0x43524201);
  check(result==expected&&opens==1&&closes==(opened?1u:0u));
  check(queries==(opened&&first==WAIT_TIMEOUT?1u:0u));++serviceChecks;
 }
 PROCESS live{false},terminated{true};
 for(PROCESS* caller:{(PROCESS*)nullptr,&live})for(bool lookup:{false,true})
 for(bool exiting:{false,true})for(HANDLE pid:{(HANDLE)nullptr,(HANDLE)-1,(HANDLE)123})
 for(PROCESS* record:{(PROCESS*)nullptr,&live,&terminated}){
  lookupOk=lookup;exitCalled=exiting;targetRecord=record;lookups=dereferences=0;
  finds=probes=locked=0;ULONG64 result=0xdeadbeef;
  NTSTATUS status=CrBrokerQuery(caller,pid,&result);
  bool role=!caller;
  bool valid=pid==(HANDLE)123;
  if(!role)check(status==STATUS_ACCESS_DENIED);
  else if(!valid||!lookup)check(status==STATUS_INVALID_CID);
  else check(status==0&&result==((record||exiting)?0x43524202ull:0x43524201ull));
  check(!locked&&finds==(role&&valid&&lookup?1:0)&&probes==finds);
  check(lookups==(role&&valid?1u:0u)&&dereferences==(unsigned)finds);
  if(!role||!valid||!lookup)check(result==0xdeadbeef);
  ++driverChecks;
 }
 printf("{\"service_cases\":%u,\"driver_cases\":%u,\"installed\":false,\"production_clients_permitted\":false}\n",serviceChecks,driverChecks);
}
