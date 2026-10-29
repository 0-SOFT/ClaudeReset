// Complete extracted callback install/uninstall/state functions; modeled DDIs.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define _FX
#define _Inout_
#define _In_
#define TRUE true
#define FALSE false
#define NT_SUCCESS(x) ((x)>=0)
#define DbgPrint(...) ((void)0)
#define _Analysis_assume_lock_not_held_(x) ((void)0)
#define FWPM_SERVICE_RUNNING 4
#define FWPM_SERVICE_STOP_PENDING 3
#define FWPM_SESSION_FLAG_DYNAMIC 1
#define RPC_C_AUTHN_WINNT 10
#define InterlockedExchange(p,v) (*(p)=(v))
#define InterlockedCompareExchange(p,v,e) (*(p))
typedef bool BOOLEAN;typedef int NTSTATUS;typedef int FWPM_SERVICE_STATE;typedef unsigned long DWORD;
typedef unsigned long ULONG;typedef unsigned UINT32;
typedef struct {int flags;} FWPM_SESSION;typedef struct {int unused;} UNICODE_STRING;
enum {STATUS_SUCCESS=0,STATUS_FWP_CALLOUT_NOT_FOUND=-2,STATUS_DEVICE_BUSY=-3};
static bool WFP_Enabled=true;
static volatile long WFP_CallbacksReady=0;
static void*WFP_engine_handle=NULL,*WFP_InitLock=(void*)1;
static unsigned WFP_send_callout_id_v4,WFP_send_callout_id_v6,WFP_recv_callout_id_v4,WFP_recv_callout_id_v6;
static bool WFP_send_callout_id_v4_owned=false,WFP_send_callout_id_v6_owned=false,WFP_recv_callout_id_v4_owned=false,WFP_recv_callout_id_v6_owned=false;
static uint64_t WFP_send_filter_id_v4,WFP_send_filter_id_v6,WFP_recv_filter_id_v4,WFP_recv_filter_id_v6;
static int WPF_SEND_CALLOUT_GUID_V4,WPF_SEND_CALLOUT_GUID_V6,WPF_RECV_CALLOUT_GUID_V4,WPF_RECV_CALLOUT_GUID_V6;
static int FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWPM_LAYER_ALE_AUTH_CONNECT_V6,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
static int stage=0,failure=0,shared=0,exclusive=0,critical=0,state=4,unregistered=0;
static bool transaction=false,early_ready=false;
static bool registered[5]={false};static unsigned next_id=0,failed_unregister=99;
static int operation(void){stage++;if(WFP_CallbacksReady)early_ready=true;return stage==failure?-1:0;}
static int FwpmBfeStateGet(void){return state;}
static int FwpmEngineOpen(void*a,int b,void*c,FWPM_SESSION*d,void**p){int status=operation();if(!status)*p=(void*)2;return status;}
static int FwpmTransactionBegin(void*p,int flags){int status=operation();if(!status)transaction=true;return status;}
static int WFP_RegisterSubLayer(void){return operation();}
static int WFP_RegisterCallout(const int*a,const int*b,unsigned*c,uint64_t*d
#ifdef TEST_OWNERSHIP
 ,BOOLEAN*owned
#endif
){
 int status=operation();*c=++next_id;registered[*c]=true;
#ifdef TEST_OWNERSHIP
 *owned=true;
#endif
 return status; // Failure models successful kernel registration followed by failed management add.
}
static int FwpmTransactionCommit(void*p){int status=operation();if(!status)transaction=false;return status;}
static int FwpmTransactionAbort(void*p){transaction=false;return 0;}
static int FwpsCalloutUnregisterById(unsigned id){
 if(id==failed_unregister)return STATUS_DEVICE_BUSY;
 if(id>=5||!registered[id])return STATUS_FWP_CALLOUT_NOT_FOUND;
 registered[id]=false;unregistered++;return 0;
}
static int FwpmEngineClose(void*p){WFP_engine_handle=NULL;return 0;}
static void KeEnterCriticalRegion(void){critical++;}
static void KeLeaveCriticalRegion(void){critical--;}
static void ExAcquireResourceSharedLite(void*p,bool wait){shared++;}
static void ExAcquireResourceExclusiveLite(void*p,bool wait){exclusive++;}
static void ExReleaseResourceLite(void*p){}
static BOOLEAN WFP_Install_Callbacks(void);
static void WFP_Uninstall_Callbacks(void);
#include "WfpCallbacksUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char**argv){
 if(argc!=2)return 2;
 failure=atoi(argv[1]);
 if(failure==10){
   failure=0;CHECK(WFP_Install_Callbacks());failed_unregister=1;WFP_Uninstall_Callbacks();
   CHECK(!WFP_CallbacksReady&&WFP_send_callout_id_v4_owned&&WFP_send_callout_id_v4==1&&registered[1]);
   int before=stage;CHECK(!WFP_Install_Callbacks());CHECK(stage==before);
   failed_unregister=99;WFP_Uninstall_Callbacks();
   CHECK(!WFP_send_callout_id_v4_owned&&!registered[1]);return 0;
 }
 if(failure==11||failure==12){
   WFP_send_callout_id_v4=failure==11?0:3;WFP_send_callout_id_v4_owned=true;
   registered[0]=failure==11;WFP_Uninstall_Callbacks();
   CHECK(!WFP_send_callout_id_v4_owned&&!registered[0]);return 0;
 }
 if(failure==9){
   WFP_state_changed(NULL,FWPM_SERVICE_RUNNING);
   CHECK(exclusive==1&&shared==0&&critical==0);
   WFP_state_changed(NULL,FWPM_SERVICE_STOP_PENDING);
   CHECK(exclusive==2&&shared==0&&critical==0);return 0;
 }
 bool result=WFP_Install_Callbacks();
 if(failure){
   CHECK(!result);CHECK(!WFP_CallbacksReady&&!WFP_engine_handle&&!transaction);
   for(unsigned i=0;i<5;i++)CHECK(!registered[i]);
   CHECK(!WFP_send_callout_id_v4&&!WFP_send_callout_id_v6&&!WFP_recv_callout_id_v4&&!WFP_recv_callout_id_v6);
 }
 else{
   CHECK(result&&WFP_CallbacksReady&&!transaction&&!early_ready);
   int before=stage;CHECK(WFP_Install_Callbacks());CHECK(stage==before);
   WFP_Uninstall_Callbacks();CHECK(!WFP_CallbacksReady&&!WFP_engine_handle);
   CHECK(unregistered==4);
 }
 return 0;
}
