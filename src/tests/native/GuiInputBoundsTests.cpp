// SPDX-License-Identifier: GPL-3.0-or-later
// Compile actual prepared handler bodies with bounded, in-memory API stubs.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cwchar>
using ULONG=uint32_t;using DWORD=uint32_t;using UINT=uint32_t;using BYTE=unsigned char;
using WCHAR=wchar_t;using HANDLE=void*;using LPVOID=void*;using BOOL=int;
const ULONG STATUS_SUCCESS=0,STATUS_INFO_LENGTH_MISMATCH=1,STATUS_INVALID_PARAMETER=2,
    STATUS_UNSUCCESSFUL=3,STATUS_ACCESS_DENIED=4,STATUS_INSUFFICIENT_RESOURCES=5;
const UINT RIDI_DEVICENAME=0x20000007;const ULONG MAX_RPL_BUF_SIZE=32768;
const int TRUE=1,FALSE=0,ERROR_SUCCESS=0,THREAD_QUERY_LIMITED_INFORMATION=0x800,HEAP_GENERATE_EXCEPTIONS=4;
struct GUI_GET_RAW_INPUT_DEVICE_INFO_REQ {ULONG msgid;uint64_t hDevice;UINT uiCommand;BOOL unicode,hasData;UINT cbSize;};
struct GUI_GET_RAW_INPUT_DEVICE_INFO_RPL {ULONG retval,error;UINT cbSize;BOOL hasData;};
struct GUI_WND_HOOK_REGISTER_REQ {ULONG msgid;uintptr_t hthread,hproc;};
struct GUI_WND_HOOK_REGISTER_RPL {ULONG status;};
struct SlaveArgs {void* req_buf;void* rpl_buf;ULONG req_len,rpl_len,pid;};
struct WND_HOOK {ULONG pid;uintptr_t hthread,hproc;int HookCount;BOOL isWoW64;WND_HOOK* next;};
struct LIST {WND_HOOK* head=nullptr;};
static int lockDepth=0,rawCalls=0,closedHandles=0;static bool threadExists=true,allocationFails=false;
static DWORD threadOwner=41;static void* _Kernel32=nullptr;
static void check(bool value){if(!value){std::fprintf(stderr,"check failed\n");std::exit(1);}}
void EnterCriticalSection(int*){++lockDepth;}
void LeaveCriticalSection(int*){--lockDepth;check(lockDepth>=0);}
HANDLE OpenThread(DWORD,BOOL,uintptr_t){return threadExists?(void*)1:nullptr;}
DWORD Owner(HANDLE){return threadOwner;}
void* GetProcAddress(void*,const char*){return (void*)&Owner;}
using P_GetProcessIdOfThread=DWORD(*)(HANDLE);
BOOL CloseHandle(HANDLE){++closedHandles;return TRUE;}
HANDLE GetProcessHeap(){return (void*)1;}
void* HeapAlloc(HANDLE,ULONG,size_t size){return allocationFails?nullptr:std::calloc(1,size);}
BOOL HeapFree(HANDLE,ULONG,void* value){std::free(value);return TRUE;}
BOOL IsProcessWoW64(HANDLE){return FALSE;}
void* List_Head(LIST* list){return list->head;}
void* List_Next(WND_HOOK* hook){return hook->next;}
void List_Insert_After(LIST* list,WND_HOOK*,WND_HOOK* hook){hook->next=list->head;list->head=hook;}
void List_Remove(LIST* list,WND_HOOK* hook){check(list->head==hook);list->head=hook->next;}
void SetLastError(ULONG){}
ULONG GetLastError(){return 0;}
ULONG GetRawInputDeviceInfoW(HANDLE,UINT,LPVOID,UINT*){++rawCalls;return 0;}
ULONG GetRawInputDeviceInfoA(HANDLE,UINT,LPVOID,UINT*){++rawCalls;return 0;}
struct GuiServer {int m_SlavesLock=0;LIST m_WndHooks;
    ULONG GetRawInputDeviceInfoSlave(SlaveArgs*);ULONG WndHookRegisterSlave(SlaveArgs*);};
#include "RawInputUnderTest.inc"
#include "WndHookUnderTest.inc"

int main(int argc,char** argv){
    check(sizeof(WCHAR)==2);
    GuiServer server;
    alignas(8) BYTE request[MAX_RPL_BUF_SIZE]={},reply[MAX_RPL_BUF_SIZE]={};
    SlaveArgs args{request,reply,sizeof(GUI_GET_RAW_INPUT_DEVICE_INFO_REQ)+8,0,41};
    auto* req=(GUI_GET_RAW_INPUT_DEVICE_INFO_REQ*)request;
    if(argc==1){
    req->hasData=TRUE;req->unicode=TRUE;req->uiCommand=RIDI_DEVICENAME;
    for(UINT count:{UINT(0x80000001),UINT(0xffffffff),UINT(20000)}){
        req->cbSize=count;rawCalls=0;
        check(server.GetRawInputDeviceInfoSlave(&args)==STATUS_INVALID_PARAMETER && rawCalls==0);
    }
    req->cbSize=4;rawCalls=0;
    check(server.GetRawInputDeviceInfoSlave(&args)==STATUS_SUCCESS && rawCalls==1);
    check(args.rpl_len==sizeof(GUI_GET_RAW_INPUT_DEVICE_INFO_RPL)+8);
    args.req_len=sizeof(GUI_GET_RAW_INPUT_DEVICE_INFO_REQ)+1;rawCalls=0;
    check(server.GetRawInputDeviceInfoSlave(&args)==STATUS_INFO_LENGTH_MISMATCH && rawCalls==0);
    req->hasData=FALSE;args.req_len=MAX_RPL_BUF_SIZE;
    check(server.GetRawInputDeviceInfoSlave(&args)==STATUS_SUCCESS);
    check(args.rpl_len==sizeof(GUI_GET_RAW_INPUT_DEVICE_INFO_RPL));
    }
    auto* hook=(GUI_WND_HOOK_REGISTER_REQ*)request;
    hook->hthread=7;hook->hproc=9;args.req_len=sizeof(*hook);
    threadExists=false;
    check(server.WndHookRegisterSlave(&args)==STATUS_UNSUCCESSFUL && lockDepth==0);
    threadExists=true;threadOwner=42;
    check(server.WndHookRegisterSlave(&args)==STATUS_ACCESS_DENIED && lockDepth==0 && closedHandles==1);
    threadOwner=41;allocationFails=true;
    check(server.WndHookRegisterSlave(&args)==STATUS_INSUFFICIENT_RESOURCES && lockDepth==0);
    allocationFails=false;
    check(server.WndHookRegisterSlave(&args)==STATUS_SUCCESS && lockDepth==0 && server.m_WndHooks.head);
    hook->hthread=0;hook->hproc=0;
    check(server.WndHookRegisterSlave(&args)==STATUS_SUCCESS && lockDepth==0 && !server.m_WndHooks.head);
    std::puts("{\"passed\":true,\"groups\":8,\"live_service_called\":false}");
}
