#include <cstdint>
#include <cstdio>
#include <cstring>
#define _FX
#define NT_SUCCESS(x) ((x)>=0)
using NTSTATUS=long;using ULONG64=uint64_t;using ULONG_PTR=uintptr_t;using HANDLE=void*;using KIRQL=int;
struct PROCESS{};
constexpr NTSTATUS STATUS_SUCCESS=0,STATUS_ACCESS_DENIED=-1,STATUS_INVALID_SIGNATURE=-2,STATUS_INVALID_HANDLE=-3;
constexpr int UserMode=0,KernelMode=1;
static bool identity=false,signed_identity=false,bypass=false,valid=true;
static unsigned references=0,releases=0,mutations=0;static int access_mode=-1;
static void*Api_ServicePortObject=(void*)22,*Api_ServiceProcessId=(void*)11,*port_type=(void*)3;
static void**LpcPortObjectType=&port_type;
static bool MyIsCallerMyServiceProcess(){return identity;}
static bool MyIsCallerSigned(){return signed_identity||bypass;}
static NTSTATUS KphVerifyCurrentProcess(){return signed_identity?0:-1;}
static void*PsGetCurrentProcessId(){return (void*)7;}
static NTSTATUS ObReferenceObjectByHandle(HANDLE,int,void*,int mode,void**result,void*){
 references++;access_mode=mode;if(!valid)return STATUS_INVALID_HANDLE;*result=(void*)44;return 0;
}
static KIRQL Api_EnterCriticalSection(){mutations++;return 0;}
static void Api_LeaveCriticalSection(KIRQL){mutations++;}
static void*InterlockedExchangePointer(void**target,void*value){mutations++;void*old=*target;*target=value;return old;}
static void ObDereferenceObject(void*){releases++;}
#include "ManagedServicePortUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d case %u: %s\n",__LINE__,checks,#x);return 1;}}while(0)
int main(int argc,char**argv){
 unsigned checks=0;PROCESS boxed;
 if(argc==2&&!strcmp(argv[1],"--handle-only")){
   identity=signed_identity=true;ULONG64 args[3]={0,8,0};
   CHECK(Api_SetServicePort(nullptr,args)==0&&access_mode==UserMode);return 0;
 }
 for(unsigned box=0;box<2;box++)for(unsigned who=0;who<2;who++)
 for(unsigned sign=0;sign<2;sign++)for(unsigned developer=0;developer<2;developer++)
 for(unsigned handle=0;handle<3;handle++){
   identity=who;signed_identity=sign;bypass=developer;valid=handle!=2;
   references=releases=mutations=0;access_mode=-1;Api_ServicePortObject=(void*)22;Api_ServiceProcessId=(void*)11;
   ULONG64 args[3]={0,handle?8u:0u,0};bool authorized=!box&&who&&sign;
   auto status=Api_SetServicePort(box?&boxed:nullptr,args);
   auto expected=box||!who?STATUS_ACCESS_DENIED:!sign?STATUS_INVALID_SIGNATURE:!valid?STATUS_INVALID_HANDLE:0;
   CHECK(status==expected);
   if(status){
     CHECK(!mutations&&!releases&&Api_ServicePortObject==(void*)22&&Api_ServiceProcessId==(void*)11);
     CHECK(references==(authorized&&handle?1u:0u));
   }else{
     CHECK(mutations==4&&releases==1&&Api_ServiceProcessId==(void*)7);
     CHECK(Api_ServicePortObject==(handle?(void*)44:nullptr));
   }
   if(references)CHECK(access_mode==UserMode);
   checks++;
 }
 identity=true;signed_identity=false;bypass=true;
 CHECK(Api_SetServicePort(nullptr,nullptr)==STATUS_INVALID_SIGNATURE);
 CHECK(Api_SetServicePort(&boxed,nullptr)==STATUS_ACCESS_DENIED);
 printf("{\"service_port_authorization_checks\":%u}\n",checks);return 0;
}
