// Exact extracted command/launch guards; no client, driver or service starts.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
typedef uint32_t ULONG;
typedef int32_t LONG;
#define TRUE 1
#define FALSE 0
#include "../ManagedApiFlags.h"
static LONG api_status;
static unsigned calls,exit_code,continued;
static ULONG requested;
static bool disable_force_on_this_program;
static bool force_children_on_this_program;
LONG SbieApi_DisableForceProcess(ULONG *value,void*){++calls;requested=*value;return api_status;}
void ExitProcess(unsigned code){exit_code=code;}
int die(int code){return code;}
void command(const wchar_t *cmd){
#include "ManagedDisableCommandUnderTest.inc"
}
int launch(){
#include "ManagedDisableLaunchUnderTest.inc"
    ++continued;return 0;
}
const wchar_t *Eat_String(const wchar_t *value){return value+wcslen(value);}
bool parse_force_children(const wchar_t *cmd){
#include "ManagedForceChildrenOptionUnderTest.inc"
    return true;
}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed at %d\n",__LINE__);return 1;}}while(0)
int main(int argc,char**argv){
    if(argc!=2)return 2;
    if(!strcmp(argv[1],"force-option")){
        const wchar_t *options[]={L"force_children",L"fcp",L"FCP",L"other"};
        for(unsigned i=0;i<4;++i){
            force_children_on_this_program=false;exit_code=99;
            bool parsed=parse_force_children(options[i]);
            CHECK(!force_children_on_this_program && parsed==(i==3));
            CHECK(exit_code==(i==3?99:3));
        }
        printf("{\"force_children_option_checks\":4}\n");return 0;
    }
    const LONG statuses[]={0,0x103,LONG(0xC0000022u),LONG(0xC000009Au),LONG(0xC00000A3u)};
    unsigned cases=0;
    for(unsigned enabled=0;enabled<2;++enabled)for(LONG status:statuses){
        calls=continued=0;exit_code=99;requested=99;api_status=status;
        if(!strcmp(argv[1],"command")){
            command(enabled?L"disable_force":L"disable_force_off");
            CHECK(calls==1 && requested==enabled && exit_code==(status?3:0));
        }else{
            disable_force_on_this_program=enabled;
            int result=launch();
            CHECK(calls==enabled && result==(enabled&&status?3:0));
            CHECK(continued==(enabled&&status?0:1));
            if(enabled)CHECK(requested==DISABLE_JUST_THIS_PROCESS);
        }
        ++cases;
    }
    printf("{\"force_disable_%s_checks\":%u}\n",argv[1],cases);
    return 0;
}
