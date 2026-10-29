#include <cstdio>
#include <cstdint>
#include <cstring>
#define _FX
typedef int NTSTATUS;
typedef unsigned long ULONG;
typedef uint64_t ULONG64;
typedef int KIRQL;
const int STATUS_SUCCESS=0,STATUS_ACCESS_DENIED=-1,STATUS_NOT_IMPLEMENTED=-2;
const int STATUS_INVALID_PARAMETER=-3,STATUS_INVALID_INFO_CLASS=-4,STATUS_NOT_FOUND=-5;
struct PROCESS { bool ipc_allowSpoolerPrintToFile; bool AllowInternetAccess; } target;
#define PROCESS_TERMINATED ((PROCESS*)-1)
template<class T>struct ARG { T val; };
struct API_PROCESS_EXEMPTION_CONTROL_ARGS {
    ARG<uintptr_t> process_id; ARG<ULONG> action_id; ARG<ULONG*> set_flag,get_flag;
};
static bool signed_caller;
static int probes,finds,releases,lowers;
static int Process_ListLock;
bool MyIsCallerSigned(){return signed_caller;}
void ProbeForRead(void*,size_t,size_t){++probes;}
void ProbeForWrite(void*,size_t,size_t){++probes;}
PROCESS *Process_Find(uintptr_t id,KIRQL *irql){++finds;*irql=0;return id==42?&target:nullptr;}
void ExReleaseResourceLite(int){++releases;}
void KeLowerIrql(KIRQL){++lowers;}
#include "ManagedExemptionUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed at %d\n",__LINE__);return 1;}}while(0)
int main(int argc,char**argv){
    bool queries=argc==2 && !strcmp(argv[1],"--queries");
    unsigned cases=0;
    for(unsigned sandbox=0;sandbox<2;++sandbox)
    for(unsigned signature=0;signature<2;++signature)
    for(unsigned action=0;action<3;++action)
    for(unsigned initial=0;initial<2;++initial)
    for(unsigned value=0;value<2;++value){
        target={bool(initial),bool(initial)};signed_caller=signature;
        probes=finds=releases=lowers=0;
        ULONG input=value,output=99;
        API_PROCESS_EXEMPTION_CONTROL_ARGS args={{42},{action==0?ULONG('inet'):action==1?ULONG('splr'):ULONG('bad!')},{queries?nullptr:&input},{&output}};
        auto result=Api_ProcessExemptionControl(sandbox?&target:nullptr,(ULONG64*)&args);
        CHECK(target.AllowInternetAccess==bool(initial) && target.ipc_allowSpoolerPrintToFile==bool(initial));
        if(sandbox || !signature || !queries){
            CHECK(result==(sandbox?STATUS_NOT_IMPLEMENTED:STATUS_ACCESS_DENIED));
            CHECK(!probes && !finds && !releases && !lowers && output==99);
        }else{
            CHECK(result==(action==2?STATUS_INVALID_INFO_CLASS:STATUS_SUCCESS));
            CHECK(output==(action==2?0:initial));
            CHECK(probes==1 && finds==1 && releases==1 && lowers==1);
        }
        ++cases;
    }
    printf("{\"managed_exemption_%s_checks\":%u}\n",queries?"query":"setter",cases);
    return 0;
}
