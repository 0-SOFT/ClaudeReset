// Actual extracted Conf_Read publication block; modeled kernel lock/lifetime.
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define _FX
#define TRUE true
#define FALSE false
#define NT_SUCCESS(s) ((s)>=0)
typedef bool BOOLEAN;typedef long NTSTATUS;typedef int KIRQL;
enum {STATUS_SUCCESS=0,STATUS_DEVICE_NOT_READY=-7,APC_LEVEL=1};
typedef struct {int id;} POOL;
typedef struct {POOL *pool;long use_count;int generation;} CONF_DATA;
static POOL old_pool={1},candidate_pool={2};
static CONF_DATA Conf_Data={&old_pool,0,1};
static void *Conf_Lock;
static bool ready=true,Obj_CallbackInstalled=true,locked=false,drop_wfp=false;
static unsigned locks=0,releases=0,yields=0,deletes=0,bad=0;
static POOL *deleted;
BOOLEAN WFP_IsReady(void){if(!locked)bad++;return ready;}
static void KeRaiseIrql(int level,KIRQL *prior){*prior=0;}
static void KeLowerIrql(KIRQL prior){}
static void ExAcquireResourceExclusiveLite(void *lock,bool wait){if(locked)bad++;locked=true;locks++;}
static void ExReleaseResourceLite(void *lock){if(!locked)bad++;locked=false;releases++;}
static void ZwYieldExecution(void){
 if(locked)bad++;yields++;Conf_Data.use_count=0;
 if(drop_wfp)ready=false;else Obj_CallbackInstalled=false;
}
static void Pool_Delete(POOL *pool){if(locked)bad++;deletes++;deleted=pool;}
#include "ManagedPublicationUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char **argv){
 if(argc!=2)return 2;
 bool startup=!strcmp(argv[1],"startup"),success=startup||!strcmp(argv[1],"ready");
 if(!strcmp(argv[1],"wfp-lost"))ready=false;
 else if(!strcmp(argv[1],"object-lost"))Obj_CallbackInstalled=false;
 else if(!strcmp(argv[1],"waiting-wfp-lost")){Conf_Data.use_count=1;drop_wfp=true;}
 else if(!strcmp(argv[1],"waiting-object-lost"))Conf_Data.use_count=1;
 else if(startup){ready=false;Obj_CallbackInstalled=false;}
 else if(!success)return 2;
 CONF_DATA candidate={&candidate_pool,0,2};
 NTSTATUS status=Publish(candidate,!startup);
 CHECK(status==(success?STATUS_SUCCESS:STATUS_DEVICE_NOT_READY));
 CHECK(Conf_Data.pool==(success?&candidate_pool:&old_pool));
 CHECK(Conf_Data.generation==(success?2:1));
 CHECK(deletes==1&&deleted==(success?&old_pool:&candidate_pool));
 CHECK(!locked&&!bad&&locks==releases&&locks==1+yields);
 printf("{\"publication_%s_passed\":true}\n",argv[1]);return 0;
}
