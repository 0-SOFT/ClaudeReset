// Complete extracted C reload function; kernel operations are counted stubs.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdbool.h>
#define _FX
#define TRUE true
#define FALSE false
#define NT_SUCCESS(x) ((x)>=0)
typedef unsigned long ULONG;typedef long LONG;typedef uint64_t ULONG64;
typedef bool BOOLEAN;typedef long NTSTATUS;typedef int KIRQL;
typedef struct {int unused;} PROCESS;typedef struct {int unused;} POOL;
enum { STATUS_SUCCESS=0,STATUS_ACCESS_DENIED=-1,STATUS_NOT_IMPLEMENTED=-2,
 STATUS_OPERATION_IN_PROGRESS=-3,STATUS_OBJECT_NAME_NOT_FOUND=-4,STATUS_OBJECT_PATH_NOT_FOUND=-5,
 STATUS_UNSUCCESSFUL=-6,STATUS_DEVICE_NOT_READY=-7,STATUS_INVALID_PARAMETER=-8 };
#include "ManagedApiFlags.h"
enum { APC_LEVEL=1,SVC_CONFIG_UPDATED=1,DRIVER_WINDOWS_VISTA=6 };
static ULONG Driver_OsVersion=10;
static uintptr_t Api_ServiceProcessId=20;
static uintptr_t PsGetCurrentProcessId(){return 20;}
static bool MyIsCallerMyServiceProcess(){return true;}
static NTSTATUS KphVerifyCurrentProcess(){return 0;}
static NTSTATUS read_status=0,cert_status=0,nested_status=0;
static unsigned reads=0,certs=0,notices=0,wfp_calls=0,obj_calls=0,syscalls=0;
static bool nested=false,wfp_ok=true,obj_ok=true,ready=true,drop_object=false,drop_ready=false;
BOOLEAN WFP_Enabled=true,Obj_CallbackInstalled=true;
BOOLEAN WFP_IsReady(void){return ready;}
static NTSTATUS Conf_Api_Reload(PROCESS*,ULONG64*);
#ifdef TEST_MANAGED_PUBLICATION
static NTSTATUS Conf_Read(ULONG session,BOOLEAN require_ready){
 if(!require_ready)return STATUS_INVALID_PARAMETER;
#else
static NTSTATUS Conf_Read(ULONG session){
#endif
 reads++;
 if(drop_object)Obj_CallbackInstalled=false;
 if(drop_ready)ready=false;
 if(nested){nested=false;ULONG64 args[3]={0,0,0};nested_status=Conf_Api_Reload(NULL,args);}
 return read_status;
}
static NTSTATUS MyValidateCertificate(){certs++;return cert_status;}
static long compare_exchange(volatile long*p,long value,long expected){long old=*p;if(old==expected)*p=value;return old;}
#define InterlockedCompareExchange(p,v,e) compare_exchange((volatile long*)(p),(v),(e))
#define InterlockedExchange(p,v) (*(p)=(v))
static BOOLEAN Conf_Get_Boolean(void*,const wchar_t*,int,BOOLEAN){return true;}
BOOLEAN WFP_Load(){wfp_calls++;if(wfp_ok)WFP_Enabled=true;return wfp_ok;}
void WFP_Unload(){wfp_calls++;WFP_Enabled=false;}
static BOOLEAN Obj_Load_Filter(){obj_calls++;if(obj_ok)Obj_CallbackInstalled=true;return obj_ok;}
static void Obj_Unload_Filter(){obj_calls++;Obj_CallbackInstalled=false;}
void Syscall_Update_Config(){syscalls++;}
static void Api_SendServiceMessage(int,size_t,ULONG*){notices++;}
typedef struct {void *func_key_size;int(*func_match_key)();int(*func_hash_key)();} Map;
static int str_map_match(){return 0;}static int str_map_hash(){return 0;}
static POOL pool;
static struct {POOL*pool;int sections;Map sections_map;bool home;void*path;int encoding;} Conf_Data={&pool,0,{0},true,&pool,1};
static void*Conf_Lock=NULL;
static void KeRaiseIrql(int,KIRQL*){}static void KeLowerIrql(KIRQL){}
static void ExAcquireResourceExclusiveLite(void*,bool){}static void ExReleaseResourceLite(void*){}
static void List_Init(int*){}static void map_init(Map*,void*){}static void map_resize(Map*,int){}
static void Pool_Delete(POOL*){}
#include "ManagedReloadUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char**argv){
 if(argc!=2)return 2;
 ULONG64 args[3]={0,0,SBIE_CONF_FLAG_RECONFIGURE};
 if(!strcmp(argv[1],"read-error")){
   read_status=STATUS_ACCESS_DENIED;
   CHECK(Conf_Api_Reload(NULL,args)==STATUS_ACCESS_DENIED);
   CHECK(reads==1&&wfp_calls==0&&obj_calls==0&&syscalls==0&&notices==0);
   read_status=STATUS_OBJECT_NAME_NOT_FOUND;
   CHECK(Conf_Api_Reload(NULL,args)==STATUS_OBJECT_NAME_NOT_FOUND);
   CHECK(Conf_Data.pool==&pool&&Conf_Data.path==&pool);
 }else if(!strcmp(argv[1],"concurrency")){
   nested=true;CHECK(Conf_Api_Reload(NULL,args)==0);
   CHECK(nested_status==STATUS_OPERATION_IN_PROGRESS&&reads==1&&notices==1);
 }else if(!strcmp(argv[1],"wfp-failure")){
   wfp_ok=false;CHECK(Conf_Api_Reload(NULL,args)==STATUS_UNSUCCESSFUL);
   CHECK(wfp_calls==1&&obj_calls==0&&syscalls==0&&notices==0);
 }else if(!strcmp(argv[1],"object-failure")){
   obj_ok=false;drop_object=true;CHECK(Conf_Api_Reload(NULL,args)==STATUS_UNSUCCESSFUL);
   CHECK(wfp_calls==1&&obj_calls==1&&syscalls==0&&notices==0);
 }else if(!strcmp(argv[1],"enabled-not-ready")){
   WFP_Enabled=true;wfp_ok=false;
   CHECK(Conf_Api_Reload(NULL,args)==STATUS_UNSUCCESSFUL);
   CHECK(wfp_calls==1&&obj_calls==0&&syscalls==0&&notices==0);
 }else if(!strcmp(argv[1],"plain-wfp-lost")||!strcmp(argv[1],"plain-object-lost")){
   args[2]=0;
   drop_ready=!strcmp(argv[1],"plain-wfp-lost");drop_object=!drop_ready;
   CHECK(Conf_Api_Reload(NULL,args)==STATUS_DEVICE_NOT_READY);
   CHECK(reads==1&&wfp_calls==0&&obj_calls==0&&syscalls==0&&notices==0);
   drop_ready=false;drop_object=false;ready=true;Obj_CallbackInstalled=true;
   CHECK(Conf_Api_Reload(NULL,args)==STATUS_SUCCESS);CHECK(reads==2&&notices==1);
 }else if(!strcmp(argv[1],"plain-wfp-not-ready")){
   args[2]=0;ready=false;CHECK(Conf_Api_Reload(NULL,args)==STATUS_DEVICE_NOT_READY);
   CHECK(reads==0&&wfp_calls==0&&obj_calls==0&&notices==0);
 }else if(!strcmp(argv[1],"plain-object-not-ready")){
   args[2]=0;Obj_CallbackInstalled=false;CHECK(Conf_Api_Reload(NULL,args)==STATUS_DEVICE_NOT_READY);
   CHECK(reads==0&&wfp_calls==0&&obj_calls==0&&notices==0);
 }else if(!strcmp(argv[1],"invalid-flags")){
   unsigned cases=0;
   for(unsigned bit=0;bit<64;bit++){
     if(bit==0||bit==31)continue;
     args[2]=(ULONG64)1<<bit;
     CHECK(Conf_Api_Reload(NULL,args)==STATUS_INVALID_PARAMETER);cases++;
   }
   ULONG64 bad[]={SBIE_CONF_FLAG_RECONFIGURE|(ULONG64)SBIE_CONF_FLAG_RELOAD_CERT,0xffffffffULL,UINT64_MAX};
   for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
     args[2]=bad[i];CHECK(Conf_Api_Reload(NULL,args)==STATUS_INVALID_PARAMETER);cases++;
   }
   CHECK(cases==65&&reads==0&&certs==0&&wfp_calls==0&&obj_calls==0&&syscalls==0&&notices==0);
 }else if(!strcmp(argv[1],"certificate")){
   args[2]=SBIE_CONF_FLAG_RELOAD_CERT;cert_status=STATUS_ACCESS_DENIED;
   CHECK(Conf_Api_Reload(NULL,args)==STATUS_ACCESS_DENIED);
   CHECK(certs==1&&reads==0&&wfp_calls==0&&obj_calls==0&&notices==0);
 }else return 2;
 // All paths above must release the whole-reload lock for the next valid call.
 read_status=0;wfp_ok=true;obj_ok=true;ready=true;drop_object=false;Obj_CallbackInstalled=true;args[2]=SBIE_CONF_FLAG_RECONFIGURE;
 CHECK(Conf_Api_Reload(NULL,args)==0);
 CHECK(WFP_Enabled&&Obj_CallbackInstalled);
 printf("{\"reload_%s_passed\":true}\n",argv[1]);return 0;
}
