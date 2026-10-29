// Extracted service-registration cleanup with deterministic lock interleavings.
// This is not a kernel scheduling or installed-driver acceptance test.
#include <cstdio>
#include <cstring>
using HANDLE=void*;using KIRQL=int;
#define _FX
static void *Api_ServicePortObject=(void*)22,*Api_ServiceProcessId=(void*)11;
static bool locked=false,replace_on_enter=false,clear_on_enter=false;
static unsigned enters=0,leaves=0,releases=0,null_releases=0,locked_releases=0;
static void *released=nullptr;
static KIRQL Api_EnterCriticalSection(){
    enters++;
    if(replace_on_enter){Api_ServicePortObject=(void*)44;Api_ServiceProcessId=(void*)33;}
    if(clear_on_enter){Api_ServicePortObject=nullptr;Api_ServiceProcessId=nullptr;}
    locked=true;return 0;
}
static void Api_LeaveCriticalSection(KIRQL){leaves++;locked=false;}
static void* InterlockedExchangePointer(void**target,void*value){void*old=*target;*target=value;return old;}
static void ObDereferenceObject(void*value){
    releases++;released=value;if(!value)null_releases++;if(locked)locked_releases++;
}
#include "ManagedServiceResetUnderTest.inc"
static void reset(HANDLE expected){
#ifdef CR_RESET_HAS_PID
    Api_ResetServiceProcess(expected);
#else
    Api_ResetServiceProcess();
#endif
}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char**argv){
    if(argc!=2)return 2;
    if(!strcmp(argv[1],"replacement")){
        replace_on_enter=true;reset((void*)11);
        CHECK(Api_ServiceProcessId==(void*)33&&Api_ServicePortObject==(void*)44);
        CHECK(releases==0);
    }else if(!strcmp(argv[1],"already-cleared")){
        clear_on_enter=true;reset((void*)11);
        CHECK(!Api_ServiceProcessId&&!Api_ServicePortObject&&releases==0);
    }else if(!strcmp(argv[1],"stale-empty-port")){
        Api_ServiceProcessId=(void*)33;Api_ServicePortObject=nullptr;reset((void*)11);
        CHECK(Api_ServiceProcessId==(void*)33&&!Api_ServicePortObject&&!releases);
    }else if(!strcmp(argv[1],"own")){
        reset((void*)11);
        CHECK(!Api_ServiceProcessId&&!Api_ServicePortObject&&releases==1&&released==(void*)22);
        CHECK(!locked_releases&&!null_releases);
        reset((void*)11);CHECK(releases==1);
    }else if(!strcmp(argv[1],"own-empty-port")){
        Api_ServicePortObject=nullptr;reset((void*)11);
        CHECK(!Api_ServiceProcessId&&!Api_ServicePortObject&&!releases);
    }else if(!strcmp(argv[1],"null-identity")){
        reset(nullptr);CHECK(Api_ServiceProcessId==(void*)11&&Api_ServicePortObject==(void*)22&&!releases);
    }else return 2;
    CHECK(enters==leaves&&!locked&&!null_releases);
    printf("{\"service_reset_%s\":true}\n",argv[1]);return 0;
}
