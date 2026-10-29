// Exact extracted driver function, deterministic kernel/BFE stubs only.
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define _FX
#define TRUE true
#define FALSE false
#define NT_SUCCESS(x) ((x)>=0)
#define FWPM_SERVICE_RUNNING 4
#define DbgPrint(...) ((void)0)
typedef bool BOOLEAN;typedef int NTSTATUS;
typedef long LONG;
static volatile LONG WFP_CallbacksReady=0;
#define InterlockedCompareExchange(p,v,e) (*(p))
static bool WFP_Enabled=false;
static void *WFP_engine_handle=NULL,*WFP_InitLock=NULL,*WFP_state_handle=NULL,*Api_DeviceObject=NULL;
static int WFP_Processes=0,state=4,loads=0,unloads=0,locks=0,subscriptions=0;
static bool allocate=true,subscribe=true,callbacks=true;
static void map_resize(int*p,int size){}
static bool Mem_GetLockResource(void**p,bool unused){if(allocate)*p=(void*)1;return allocate;}
static void Mem_FreeLockResource(void**p){*p=NULL;}
static void WFP_state_changed(void){}
static int FwpmBfeStateSubscribeChanges(void*p,void(*callback)(void),void*c,void**handle){
 if(!subscribe)return -1;subscriptions++;*handle=(void*)2;return 0;
}
static int FwpmBfeStateGet(void){return state;}
static void KeEnterCriticalRegion(void){}static void KeLeaveCriticalRegion(void){}
static void ExAcquireResourceSharedLite(void*p,bool unused){locks++;}
static void ExAcquireResourceExclusiveLite(void*p,bool unused){locks++;}
static void ExReleaseResourceLite(void*p){locks--;}
static bool WFP_Install_Callbacks(void){loads++;if(callbacks){WFP_engine_handle=(void*)3;WFP_CallbacksReady=1;}return callbacks;}
static void WFP_Unload(void){
 if(locks){fprintf(stderr,"cleanup under callback lock\n");return;}
 unloads++;WFP_Enabled=false;WFP_CallbacksReady=0;WFP_engine_handle=NULL;WFP_InitLock=NULL;WFP_state_handle=NULL;subscriptions=0;
}
#include "WfpLoadUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char**argv){
 if(argc!=2)return 2;
 if(!strcmp(argv[1],"allocation"))allocate=false;
 else if(!strcmp(argv[1],"subscription"))subscribe=false;
 else if(!strcmp(argv[1],"callbacks"))callbacks=false;
 else if(!strcmp(argv[1],"bfe-stopped"))state=0;
 else if(!strcmp(argv[1],"enabled-without-callbacks")){
   WFP_Enabled=true;CHECK(!WFP_Load());CHECK(loads==0);return 0;
 }else if(!strcmp(argv[1],"enabled-bfe-stopped")){
   WFP_Enabled=true;WFP_engine_handle=(void*)3;state=0;CHECK(!WFP_Load());return 0;
 }else if(!strcmp(argv[1],"engine-before-commit")){
   WFP_Enabled=true;WFP_engine_handle=(void*)3;CHECK(!WFP_Load());return 0;
 }else return 2;
 CHECK(!WFP_Load());CHECK(!WFP_Enabled);CHECK(!WFP_InitLock&&!WFP_state_handle&&!WFP_engine_handle);
 CHECK(locks==0&&subscriptions==0);
 allocate=true;subscribe=true;callbacks=true;state=4;
 CHECK(WFP_Load());CHECK(WFP_Enabled&&WFP_engine_handle&&WFP_InitLock&&subscriptions==1);
 int before=loads;CHECK(WFP_Load());CHECK(loads==before&&subscriptions==1);
 return 0;
}
