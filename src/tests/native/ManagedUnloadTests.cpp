// Complete extracted unload API with modeled kernel/service identities only.
#include <cstdint>
#include <cstdio>
#define _FX
#define TRUE true
#define FALSE false
#define NT_SUCCESS(x) ((x)>=0)
using BOOLEAN=bool;using ULONG64=uint64_t;using NTSTATUS=long;using KIRQL=int;
constexpr NTSTATUS STATUS_SUCCESS=0,STATUS_ACCESS_DENIED=-1,STATUS_CONNECTION_IN_USE=-2;
constexpr int APC_LEVEL=1,MSG_CANNOT_UNLOAD_DRIVER=1;
struct PROCESS {uintptr_t pid=7;};
struct DRIVER_OBJECT {void(*DriverUnload)(DRIVER_OBJECT*)=nullptr;};
static DRIVER_OBJECT object,*Driver_Object=&object;
static bool Process_ReadyToSandbox=true,Driver_FullUnload=false;
static bool service_identity=false,signed_identity=false,api_free=true,unloaded=false;
static uintptr_t current_pid=10,Api_ServiceProcessId=20;
static int mutations=0;
static void*Process_ListLock=nullptr;
static struct {unsigned nnodes=0;} Process_Map;
static uintptr_t PsGetCurrentProcessId(){return current_pid;}
static bool MyIsCallerMyServiceProcess(){return service_identity;}
static NTSTATUS KphVerifyCurrentProcess(){return signed_identity?0:-1;}
static void KeMemoryBarrier(){mutations++;}
static void KeRaiseIrql(int,KIRQL*){mutations++;}static void KeLowerIrql(KIRQL){mutations++;}
static void ExAcquireResourceExclusiveLite(void*,bool){mutations++;}static void ExReleaseResourceLite(void*){mutations++;}
static bool Api_Disable(){mutations++;return api_free;}
static void Log_MsgP0(int,uintptr_t){}
static void SbieDrv_DriverUnload(DRIVER_OBJECT*){mutations++;unloaded=true;}
#include "ManagedUnloadUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d case %u: %s\n",__LINE__,checks,#x);return 1;}}while(0)
int main(){
 unsigned checks=0;PROCESS sandbox;
 for(unsigned boxed=0;boxed<2;boxed++)
 for(unsigned pid=0;pid<3;pid++)
 for(unsigned registered=0;registered<2;registered++)
 for(unsigned identity=0;identity<2;identity++)
 for(unsigned signature=0;signature<2;signature++)
 for(unsigned busy=0;busy<2;busy++)
 for(unsigned available=0;available<2;available++)
 for(unsigned ready=0;ready<2;ready++){
   current_pid=pid==0?0:pid==1?10:20;Api_ServiceProcessId=registered?20:0;
   service_identity=identity;signed_identity=signature;Process_Map.nnodes=busy;api_free=available;
   Process_ReadyToSandbox=ready;Driver_FullUnload=false;object.DriverUnload=nullptr;mutations=0;unloaded=false;
   bool trusted=!boxed&&pid==2&&registered&&identity&&signature;
   auto status=Driver_Api_Unload(boxed?&sandbox:nullptr,nullptr);
   if(!trusted){
     CHECK(status==STATUS_ACCESS_DENIED&&mutations==0&&Process_ReadyToSandbox==bool(ready));
     CHECK(!unloaded&&!Driver_FullUnload&&!object.DriverUnload);
   }else if(busy||!available){
     CHECK(status==STATUS_CONNECTION_IN_USE&&Process_ReadyToSandbox==bool(ready));
     CHECK(!unloaded&&!Driver_FullUnload&&!object.DriverUnload);
   }else{
     CHECK(status==0&&!Process_ReadyToSandbox&&unloaded&&Driver_FullUnload);
     CHECK(object.DriverUnload==SbieDrv_DriverUnload);
   }
   checks++;
 }
 printf("{\"unload_authorization_lifecycle_checks\":%u}\n",checks);return 0;
}
