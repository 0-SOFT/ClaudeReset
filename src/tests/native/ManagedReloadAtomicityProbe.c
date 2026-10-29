// Diagnostic composition of actual publication and reload code, not acceptance.
// Parser, kernel locks, callbacks and dependent subsystems remain modeled.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#define _FX
#define TRUE true
#define FALSE false
#define NT_SUCCESS(x) ((x)>=0)
typedef unsigned long ULONG;
typedef long LONG,NTSTATUS;
typedef uint64_t ULONG64;
typedef bool BOOLEAN;
typedef int KIRQL;
typedef struct {int unused;} PROCESS;
typedef struct {int identity;} POOL;
typedef struct {POOL *pool;long use_count;unsigned generation;} CONF_DATA;
enum {STATUS_SUCCESS=0,STATUS_ACCESS_DENIED=-1,STATUS_OPERATION_IN_PROGRESS=-3,
 STATUS_UNSUCCESSFUL=-6,STATUS_DEVICE_NOT_READY=-7,STATUS_INVALID_PARAMETER=-8};
enum {APC_LEVEL=1,SVC_CONFIG_UPDATED=1,DRIVER_WINDOWS_VISTA=6};
#include "ManagedApiFlags.h"
static ULONG Driver_OsVersion=10;
static uintptr_t Api_ServiceProcessId=20;
static uintptr_t PsGetCurrentProcessId(void){return 20;}
static bool MyIsCallerMyServiceProcess(void){return true;}
static NTSTATUS KphVerifyCurrentProcess(void){return 0;}
static POOL old_pool={1},candidate_pool={2};
static CONF_DATA Conf_Data={&old_pool,0,1};
static void *Conf_Lock;
static bool ready=true,fail_wfp=false,drop_after_publish=false,locked=false;
BOOLEAN WFP_Enabled=true,Obj_CallbackInstalled=true;
static unsigned reads=0,old_freed=0,candidate_freed=0,notices=0;
BOOLEAN WFP_IsReady(void){return ready;}
static void KeRaiseIrql(int level,KIRQL *prior){*prior=0;}
static void KeLowerIrql(KIRQL prior){}
static void ExAcquireResourceExclusiveLite(void *lock,bool wait){locked=true;}
static void ExReleaseResourceLite(void *lock){locked=false;}
static void ZwYieldExecution(void){Conf_Data.use_count=0;}
static void Pool_Delete(POOL *pool){
 if(pool==&old_pool)old_freed++;
 if(pool==&candidate_pool)candidate_freed++;
}
#include "ManagedPublicationUnderTest.inc"
static NTSTATUS Conf_Read(ULONG session,BOOLEAN require_ready){
 reads++;
 CONF_DATA candidate={&candidate_pool,0,2};
 NTSTATUS status=Publish(candidate,require_ready);
 if(drop_after_publish)ready=false;
 return status;
}
static NTSTATUS MyValidateCertificate(void){return 0;}
static long compare_exchange(volatile long*p,long value,long expected){long old=*p;if(old==expected)*p=value;return old;}
#define InterlockedCompareExchange(p,v,e) compare_exchange((volatile long*)(p),(v),(e))
#define InterlockedExchange(p,v) (*(p)=(v))
static BOOLEAN Conf_Get_Boolean(void *box,const wchar_t *key,int index,BOOLEAN fallback){return true;}
BOOLEAN WFP_Load(void){return !fail_wfp;}
void WFP_Unload(void){WFP_Enabled=false;}
static BOOLEAN Obj_Load_Filter(void){Obj_CallbackInstalled=true;return true;}
static void Obj_Unload_Filter(void){Obj_CallbackInstalled=false;}
void Syscall_Update_Config(void){}
static void Api_SendServiceMessage(int kind,size_t length,ULONG *pid){notices++;}
#include "ManagedReloadUnderTest.inc"
int main(int argc,char **argv){
 if(argc!=2)return 2;
 ULONG64 args[3]={0,0,SBIE_CONF_FLAG_RECONFIGURE};
 if(!strcmp(argv[1],"before-publication"))ready=false;
 else if(!strcmp(argv[1],"wfp-after-publication"))fail_wfp=true;
 else if(!strcmp(argv[1],"plain-after-publication")){args[2]=0;drop_after_publish=true;}
 else if(strcmp(argv[1],"ready"))return 2;
 NTSTATUS status=Conf_Api_Reload(NULL,args);
 bool failed_with_changed_policy=!NT_SUCCESS(status)&&Conf_Data.generation!=1;
 printf("{\"status\":%ld,\"generation\":%u,\"reads\":%u,\"old_pool_freed\":%u,"
        "\"candidate_pool_freed\":%u,\"notices\":%u,\"failed_with_changed_policy\":%s}\n",
        status,Conf_Data.generation,reads,old_freed,candidate_freed,notices,
        failed_with_changed_policy?"true":"false");
 return locked?4:failed_with_changed_policy?3:0;
}
