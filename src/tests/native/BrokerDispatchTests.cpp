// SPDX-License-Identifier: GPL-3.0-or-later
// Exercises the actual patched QueueCallbackSlave2 body with deterministic IPC
// transport stubs. This is not an installed-service or client-compatibility test.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <wchar.h>
#include "CrBrokerPolicy.h"
typedef uint32_t ULONG;typedef uintptr_t ULONG_PTR;typedef void* HANDLE;
const ULONG STATUS_SUCCESS=0,STATUS_END_OF_FILE=0xc0000011,
    STATUS_INVALID_SYSTEM_SERVICE=0xc000001c,STATUS_NOT_SAME_DEVICE=0xc00000d4,STATUS_ACCESS_DENIED=0xc0000022;
const ULONG GUI_INIT_PROCESS=1,GUI_KILL_JOB=32,GUI_MAX_REQUEST_CODE=34;
const unsigned MAX_RPL_BUF_SIZE=256;
static ULONG callerThreadId=7;
static bool strictMode=true;static ULONG requestCode=0,requestLength=4,replyCode=0,calls=0;
static bool CrIsStrictSandbox(ULONG pid){return strictMode && pid==123;}
static ULONG SbieDll_QueueGetReq(const wchar_t*,ULONG* pid,void*,ULONG* id,void** data,ULONG* len){
    *pid=123;*id=1;*data=&requestCode;*len=requestLength;return 0;
}
static ULONG SbieDll_QueuePutRpl(const wchar_t*,ULONG,void* data,ULONG){replyCode=*(ULONG*)data;return 0;}
static void SbieDll_FreeMem(void*){}
static ULONG SbieApi_QueryProcess(HANDLE,void*,void*,void*,ULONG* session){if(session)*session=1;return 0;}
struct MSG_HEADER{ULONG length;union{ULONG msgid;ULONG status;};};
struct PORT_MESSAGE{};
struct CLIENT_TLS_DATA{HANDLE PortHandle;PORT_MESSAGE* PortMessage;};
static bool TlsSetValue(ULONG,void*){return true;}
static void RevertToSelf(){}
static ULONG GetExceptionCode(){return STATUS_ACCESS_DENIED;}
static MSG_HEADER reply;
struct SPipeTarget{void* context;MSG_HEADER*(*handler)(void*,MSG_HEADER*);};
class PipeServer {
public:
    ULONG m_TlsIndex=0;std::map<ULONG,SPipeTarget> m_Targets;
    static ULONG GetCallerProcessId(){return 123;}
    static ULONG GetCallerThreadId(){return callerThreadId;}
    MSG_HEADER* AllocShortMsg(ULONG status){reply.length=8;reply.status=status;return &reply;}
    MSG_HEADER* CallTarget(MSG_HEADER*,HANDLE,PORT_MESSAGE*);
};
#define USE_NEW_LPC_IMPL
#define __try try
#define __except(x) catch(...)
#include "PipeDispatchUnderTest.inc"
#undef __try
#undef __except
static MSG_HEADER* handler(void*,MSG_HEADER*){++calls;reply.status=0;return &reply;}
typedef wchar_t WCHAR;
const ULONG STATUS_INVALID_PARAMETER=0xc000000d;
const unsigned QUEUE_NAME_MAXLEN=64,MSGID_QUEUE_CREATE=0x1e01,MSGID_QUEUE_GETREQ=0x1e02,
    MSGID_QUEUE_PUTRPL=0x1e03,MSGID_QUEUE_PUTREQ=0x1e04,MSGID_QUEUE_GETRPL=0x1e05,
    MSGID_QUEUE_STARTUP=0x1e06,MSGID_QUEUE_NOTIFICATION=0x1eff;
struct QUEUE_GETRPL_REQ{MSG_HEADER h;WCHAR queue_name[64];};
static MSG_HEADER* shortReply(ULONG status){reply.status=status;return &reply;}
#define SHORT_REPLY(x) shortReply(x)
class QueueServer {
public:
    static MSG_HEADER* Handler(void*,MSG_HEADER*);
    MSG_HEADER* StartupHandler(MSG_HEADER*,HANDLE){++calls;return shortReply(0);}
    void NotifyHandler(HANDLE){++calls;}
    MSG_HEADER* CreateHandler(MSG_HEADER*,HANDLE){++calls;return shortReply(0);}
    MSG_HEADER* GetReqHandler(MSG_HEADER*,HANDLE){++calls;return shortReply(0);}
    MSG_HEADER* PutRplHandler(MSG_HEADER*,HANDLE){++calls;return shortReply(0);}
    MSG_HEADER* PutReqHandler(MSG_HEADER*,HANDLE){++calls;return shortReply(0);}
    MSG_HEADER* GetRplHandler(MSG_HEADER*,HANDLE){++calls;return shortReply(0);}
};
#include "QueueDispatchUnderTest.inc"
typedef ULONG DWORD;typedef int BOOL;
#define TRUE 1
#define FALSE 0
const ULONG ERROR_PROCESS_ABORTED=1067,STANDARD_RIGHTS_READ=0x20000,SYNCHRONIZE=0x100000,
    PROCESS_VM_READ=0x10,PROCESS_QUERY_INFORMATION=0x400,PROCESS_QUERY_LIMITED_INFORMATION=0x1000,
    THREAD_GET_CONTEXT=8,THREAD_QUERY_INFORMATION=0x40,THREAD_SUSPEND_RESUME=2,
    THREAD_QUERY_LIMITED_INFORMATION=0x800,DUPLICATE_SAME_ACCESS=2,CREATE_SUSPENDED=4;
struct PROCESS_INFORMATION{HANDLE hProcess,hThread;DWORD dwProcessId,dwThreadId;};
static DWORD lastError=0,duplicated[2]={0},duplicateFlags[2]={0};static unsigned duplicateCount=0,resumed=0,terminated=0,closed=0;
static bool targetBoxed=true,duplicateOk=true;
static void SetLastError(DWORD error){lastError=error;}
static DWORD GetLastError(){return lastError;}
static HANDLE GetCurrentProcess(){return (HANDLE)-1;}
static ULONG SbieApi_QueryProcessInfo(HANDLE,ULONG){return targetBoxed?1:0;}
static BOOL DuplicateHandle(HANDLE,HANDLE,HANDLE,HANDLE* result,DWORD desired,BOOL,DWORD flags){
    duplicated[duplicateCount]=desired;duplicateFlags[duplicateCount++]=flags;*result=(HANDLE)55;return duplicateOk;
}
static DWORD ResumeThread(HANDLE){++resumed;return 0;}
static BOOL TerminateProcess(HANDLE,DWORD){++terminated;return TRUE;}
static BOOL CloseHandle(HANDLE){++closed;return TRUE;}
class ProcessServer{public:BOOL RunSandboxedDupAndCloseHandles(HANDLE,BOOL,ULONG,PROCESS_INFORMATION*,PROCESS_INFORMATION*);};
#include "HandleTransferUnderTest.inc"
class GuiServer {
public:
    struct SlaveArgs {ULONG pid,req_len,rpl_len;void* req_buf;void* rpl_buf;};
    typedef ULONG(GuiServer::*SlaveFunc)(SlaveArgs*);
    SlaveFunc m_SlaveFuncs[GUI_MAX_REQUEST_CODE];
    const wchar_t* m_QueueName=L"fixture";ULONG m_SessionId=1;
    GuiServer(){for(auto &f:m_SlaveFuncs)f=&GuiServer::Invoke;}
    ULONG Invoke(SlaveArgs*){++calls;return 0;}
    void ReportError2336(int,int,ULONG){}
    bool QueueCallbackSlave2();
};
#include "GuiDispatchUnderTest.inc"
static unsigned assertions=0;
static void check(bool ok){++assertions;if(!ok){fprintf(stderr,"assertion %u failed\n",assertions);exit(1);}}
int main(){
    unsigned allowed=0;for(unsigned i=0;i<65536;++i)if(CrPipeAllowed(i))++allowed;
    check(allowed==10);
    check(!CrSpawnAllowed(-123,123,L"python.exe script.py",0));
    check(CrSpawnAllowed(-123,123,L"*RPCSS*",0));
    for(const wchar_t* cmd:{L"*COMSRV*",L"*RPCSS*x",L"*DCOM*",L"*",L""})check(!CrSpawnAllowed(-123,123,cmd,0));
    check(!CrSpawnAllowed(-123,123,nullptr,0));
    check(!CrSpawnAllowed(0,123,L"python.exe",0));
    check(!CrSpawnAllowed(-456,123,L"python.exe",0));
    check(!CrSpawnAllowed(123,123,L"python.exe",0));
    check(!CrSpawnAllowed(0,0,L"python.exe",0));
    check(!CrSpawnAllowed(-123,123,L"python.exe",0x40000));
    check(!CrSpawnAllowed(-123,123,L"\\\\server\\share\\app.exe",0));
    check(!CrSpawnAllowed(-123,123,L"\"\\\\server\\share\\app.exe\"",0));
    check(!CrSpawnAllowed(-123,123,L"Z:\\app.exe",0));
    check(!CrSpawnAllowed(-123,123,L"*RPCSS*",CREATE_SUSPENDED));
    for(unsigned bit=0;bit<32;++bit) {
        unsigned flag=1u<<bit;
        check(CrSpawnAllowed(-123,123,L"*RPCSS*",flag)==((flag & ~(0x08000000u|0x400u))==0));
    }
    ProcessServer process;PROCESS_INFORMATION input={(HANDLE)1,(HANDLE)2,900,901},output={};
    strictMode=true;targetBoxed=true;duplicateCount=0;resumed=0;closed=0;
    check(process.RunSandboxedDupAndCloseHandles((HANDLE)3,FALSE,0,&input,&output));
    check(duplicateCount==2 && duplicated[0]==(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION));
    check(duplicated[1]==(SYNCHRONIZE|THREAD_QUERY_LIMITED_INFORMATION));
    check(duplicateFlags[0]==0 && duplicateFlags[1]==0 && resumed==1 && closed==2);
    check(output.dwProcessId==900 && output.dwThreadId==901);
    targetBoxed=false;duplicateCount=0;terminated=0;
    check(!process.RunSandboxedDupAndCloseHandles((HANDLE)3,TRUE,0,&input,&output));
    check(duplicateCount==0 && terminated==1);
    strictMode=false;duplicateCount=0;resumed=0;
    check(process.RunSandboxedDupAndCloseHandles((HANDLE)3,TRUE,0,&input,&output));
    check(duplicateCount==2 && resumed==1);
    targetBoxed=true;duplicateCount=0;
    check(process.RunSandboxedDupAndCloseHandles((HANDLE)3,FALSE,0,&input,&output));
    check(duplicateFlags[0]==DUPLICATE_SAME_ACCESS && duplicateFlags[1]==DUPLICATE_SAME_ACCESS);
    for(unsigned id=0x1e01;id<=0x1e05;++id){
        check(CrQueueAllowed(id,L"RPCSS_SXS",10,1));
        check(!CrQueueAllowed(id,L"RPCSS_SXSx",11,1));
        check(!CrQueueAllowed(id,L"RPCSS_SXS",9,1));
        check(!CrQueueAllowed(id,L"*RPCSS_SXS",11,1));
        check(!CrQueueAllowed(id,L"../RPCSS_SXS",13,1));
        check(CrQueueAllowed(id,L"*GUIPROXY_00000001",19,1)==(id>=0x1e04));
    }
    for(unsigned id:{0x1a01u,0x1b02u,0x1c03u,0x1506u,0x1301u,0x1811u,0x1e10u,0x1f01u,0xffffffffu})check(!CrPipeAllowed(id));
    check(CrGuiQueueAllowed(L"*GUIPROXY_00000001",19,1));
    check(!CrGuiQueueAllowed(L"*GUIPROXY_00000002",19,1));
    check(!CrGuiQueueAllowed(L"*GUIPROXY_00000001x",20,1));
    check(!CrGuiQueueAllowed(L"*USERPROXY_0000001",19,1));
    check(!CrGuiQueueAllowed(nullptr,19,1));
    check(!CrGuiQueueAllowed(L"*GUIPROXY_00000001",18,1));
    QueueServer qserver;QUEUE_GETRPL_REQ qrequest={};qrequest.h.length=sizeof(qrequest);
    for(const WCHAR* name:{L"RPCSS_SXS",L"*GUIPROXY_00000001",L"*GUIPROXY_00000002",L"*USERPROXY_00000001",L"RPCSS_SXSx",L""}){
        wcscpy(qrequest.queue_name,name);
        for(unsigned id=0x1e01;id<=0x1e06;++id){
            qrequest.h.msgid=id;strictMode=true;calls=0;
            MSG_HEADER* output=qserver.Handler(&qserver,&qrequest.h);
            const bool allowed=CrQueueAllowed(id,name,64,1);
            check(calls==(allowed?1u:0u));check(output && output->status==(allowed?0u:STATUS_ACCESS_DENIED));
        }
    }
    qrequest.h.msgid=MSGID_QUEUE_NOTIFICATION;calls=0;
    check(qserver.Handler(&qserver,&qrequest.h)->status==STATUS_ACCESS_DENIED && calls==0);
    qrequest.h.length=sizeof(MSG_HEADER);callerThreadId=0;calls=0;
    check(qserver.Handler(&qserver,&qrequest.h)==nullptr && calls==1);
    callerThreadId=7;
    qrequest.h.msgid=MSGID_QUEUE_CREATE;
    for(qrequest.h.length=0;qrequest.h.length<sizeof(MSG_HEADER)+64*sizeof(WCHAR);++qrequest.h.length){
        calls=0;check(qserver.Handler(&qserver,&qrequest.h)->status==STATUS_INVALID_PARAMETER && calls==0);
    }
    qrequest.h.length=sizeof(qrequest);wcscpy(qrequest.queue_name,L"*USERPROXY_00000001");
    strictMode=false;calls=0;check(qserver.Handler(&qserver,&qrequest.h)->status==0 && calls==1);
    PipeServer pipe;
    for(unsigned id:{0x1201u,0x1205u,0x1a01u,0x1b02u,0x1c03u,0x1506u,0x1301u,0x1811u,0x1e10u,0xde01u}){
        pipe.m_Targets[id&0xffffff00]={nullptr,handler};MSG_HEADER input;input.length=8;input.msgid=id;
        calls=0;strictMode=true;MSG_HEADER* output=pipe.CallTarget(&input,nullptr,nullptr);
        check(calls==(CrPipeAllowed(id)?1u:0u));check(output->status==(CrPipeAllowed(id)?0u:STATUS_ACCESS_DENIED));
        calls=0;strictMode=false;output=pipe.CallTarget(&input,nullptr,nullptr);check(calls==1 && output->status==0);
    }
    for(bool strict:{false,true}){
        strictMode=strict;calls=0;MSG_HEADER notification{8,MSGID_QUEUE_NOTIFICATION};
        pipe.m_Targets[0x1e00]={nullptr,handler};
        MSG_HEADER* output=pipe.CallTarget(&notification,nullptr,nullptr);
        check(calls==0&&output&&output->status==STATUS_INVALID_SYSTEM_SERVICE);
    }
    GuiServer server;
    for(requestCode=0;requestCode<40;++requestCode){
        calls=0;replyCode=0;requestLength=4;strictMode=true;
        check(server.QueueCallbackSlave2());check(calls==(requestCode==2?1u:0u));
        if(requestCode!=2)check(replyCode!=0);
    }
    // Actual send/post handler (including its DDE shortcut) cannot be reached.
    requestCode=19;strictMode=true;calls=0;server.QueueCallbackSlave2();check(calls==0 && replyCode==STATUS_ACCESS_DENIED);
    // Untargeted callers retain the existing dispatch path.
    strictMode=false;calls=0;server.QueueCallbackSlave2();check(calls==1);
    for(requestLength=0;requestLength<4;++requestLength){calls=0;server.QueueCallbackSlave2();check(calls==0);}
    printf("{\"passed\":true,\"assertions\":%u,\"installed_service_test\":false}\n",assertions);
}
