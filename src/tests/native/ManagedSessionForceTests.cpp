#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include "../ManagedApiFlags.h"
#define _FX
#define FALSE false
#define TRUE true
#define BOXNAME_COUNT 40
typedef int NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG64;
typedef uintptr_t HANDLE;
typedef wchar_t WCHAR;
typedef unsigned char UCHAR;
typedef int KIRQL;
struct PROCESS{};
#define PROCESS_TERMINATED ((PROCESS*)-1)
struct LARGE_INTEGER{long long QuadPart;};
struct SESSION{long long disable_force_time;} session;
template<class T>struct ARG{T val;};
struct API_DISABLE_FORCE_PROCESS_ARGS{ARG<ULONG*>set_flag,get_flag;};
const NTSTATUS STATUS_SUCCESS=0,STATUS_NOT_IMPLEMENTED=-1,STATUS_ACCESS_DENIED=-2,STATUS_INVALID_PARAMETER=-3;
static bool signed_caller,admin,current;
static unsigned probes,queries,lookups,inserts,unlocks;
bool MyIsCallerSigned(){return signed_caller;}
bool Session_CheckAdminAccess2(const WCHAR*){return admin;}
void ProbeForRead(void*,size_t,size_t){++probes;}
void ProbeForWrite(void*,size_t,size_t){++probes;}
bool Session_IsForceDisabled(int){++queries;return current;}
void KeQuerySystemTime(LARGE_INTEGER *p){p->QuadPart=999;}
HANDLE PsGetCurrentProcessId(){return 42;}
void Process_DfpInsert(PROCESS*,HANDLE){++inserts;}
SESSION *Session_Get(bool,int,KIRQL *irql){++lookups;*irql=0;return &session;}
void Session_Unlock(KIRQL){++unlocks;}
void Process_FcpInsert(HANDLE,const WCHAR*){++inserts;}
void memzero(void*p,size_t n){memset(p,0,n);}
#include "ManagedSessionForceUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed at %d\n",__LINE__);return 1;}}while(0)
void reset(){probes=queries=lookups=inserts=unlocks=0;session.disable_force_time=123;}
int main(int argc,char**argv){
    if(argc!=2)return 2;
    PROCESS proc;unsigned cases=0;
    if(!strcmp(argv[1],"children")){
        WCHAR name[]=L"ClaudeReset.Code";ULONG64 args[]={0,42,(ULONG64)(uintptr_t)name};
        for(unsigned sandbox=0;sandbox<2;++sandbox)for(unsigned signature=0;signature<2;++signature){
            reset();signed_caller=signature;
            CHECK(Session_Api_ForceChildren(sandbox?&proc:nullptr,args)==(sandbox?STATUS_NOT_IMPLEMENTED:STATUS_ACCESS_DENIED));
            CHECK(!probes&&!inserts);++cases;
        }
    }else if(!strcmp(argv[1],"mutation")){
        reset();signed_caller=admin=true;ULONG input=1;
        API_DISABLE_FORCE_PROCESS_ARGS args={{&input},{nullptr}};
        CHECK(Session_Api_DisableForce(nullptr,(ULONG64*)&args)==STATUS_ACCESS_DENIED);
        CHECK(!probes&&!lookups&&!inserts&&!unlocks&&session.disable_force_time==123);cases=1;
    }else{
        bool setters=!strcmp(argv[1],"setters");
        ULONG values[]={0,1,DISABLE_JUST_THIS_PROCESS};
        for(unsigned sandbox=0;sandbox<2;++sandbox)
        for(unsigned signature=0;signature<2;++signature)
        for(unsigned access=0;access<(setters?2u:1u);++access)
        for(unsigned value=0;value<(setters?3u:1u);++value)
        for(unsigned get=0;get<2;++get)
        for(unsigned state=0;state<2;++state){
            reset();signed_caller=signature;admin=access;current=state;
            ULONG input=values[value],output=99;
            API_DISABLE_FORCE_PROCESS_ARGS args={{setters?&input:nullptr},{get?&output:nullptr}};
            CHECK(Session_Api_DisableForce(sandbox?&proc:nullptr,(ULONG64*)&args)==
                (sandbox?STATUS_NOT_IMPLEMENTED:setters?STATUS_ACCESS_DENIED:STATUS_SUCCESS));
            bool query=!sandbox&&!setters&&get;
            CHECK(output==(query?state:99));CHECK(probes==unsigned(query)&&queries==unsigned(query));
            CHECK(!lookups&&!inserts&&!unlocks&&session.disable_force_time==123);++cases;
        }
    }
    printf("{\"session_force_%s_checks\":%u}\n",argv[1],cases);return 0;
}
