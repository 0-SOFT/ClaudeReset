// Exact registration function: ownership begins after FwpsCalloutRegister1.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define NT_SUCCESS(x) ((x)>=0)
#define TRUE true
#define STATUS_SUCCESS 0
#define STATUS_INVALID_HANDLE -1
#define STATUS_DEVICE_BUSY -2
#define FWP_ACTION_CALLOUT_TERMINATING 1
#define FWP_UINT8 1
typedef int NTSTATUS;typedef int GUID;typedef unsigned UINT32;typedef uint64_t UINT64;typedef bool BOOLEAN;
typedef struct {GUID calloutKey;void(*classifyFn)(void);void(*notifyFn)(void);void(*flowDeleteFn)(void);} FWPS_CALLOUT1;
typedef struct {const char*name,*description;} DISPLAY;
typedef struct {DISPLAY displayData;GUID calloutKey,applicableLayer;int flags;} FWPM_CALLOUT;
typedef struct {DISPLAY displayData;struct {int type;GUID calloutKey;}action;GUID subLayerKey;struct{int type,uint8;}weight;int numFilterConditions;GUID layerKey;} FWPM_FILTER;
static const char*WFP_CALLOUT_NAME="callout",*WFP_CALLOUT_DESCRIPTION="callout",*WFP_FILTER_NAME="filter",*WFP_FILTER_DESCRIPTION="filter";
static GUID WFP_SUBLAYER_GUID=1;
static void*WFP_engine_handle=(void*)1,*Api_DeviceObject=NULL;
static int stage=0,failure=0;static unsigned assigned=0;
static void WFP_classify(void){}static void WFP_notify(void){}static void WFP_flow_delete(void){}
static int operation(void){return ++stage==failure?-1:0;}
static int FwpsCalloutRegister1(void*p,FWPS_CALLOUT1*c,UINT32*id){int status=operation();if(!status)*id=assigned;return status;}
static int FwpmCalloutAdd(void*p,FWPM_CALLOUT*c,void*s,void*id){return operation();}
static int FwpmFilterAdd(void*p,FWPM_FILTER*f,void*s,UINT64*id){return operation();}
#include "WfpRegisterUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char**argv){
 if(argc!=2)return 2;int mode=atoi(argv[1]);failure=mode;
 GUID key=0,layer=0;UINT32 id=100;UINT64 filter=0;BOOLEAN owned=false;
 if(failure==4){owned=true;failure=0;}
#ifdef TEST_OWNERSHIP
 NTSTATUS result=WFP_RegisterCallout(&key,&layer,&id,&filter,&owned);
#else
 NTSTATUS result=WFP_RegisterCallout(&key,&layer,&id,&filter);
#endif
 if(mode==4){CHECK(stage==0&&result==STATUS_DEVICE_BUSY&&id==100);return 0;}
 if(failure==1){CHECK(result<0);CHECK(!owned&&id==100);}
 else {CHECK(owned&&id==0);CHECK(failure?result<0:result==0);}
 return 0;
}
