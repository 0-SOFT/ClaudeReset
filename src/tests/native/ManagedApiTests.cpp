// Extracted entry authorization only. No real kernel identities or loaded driver.
#include <cstdint>
#include <cstdio>
#include <cstring>
#define _FX
using NTSTATUS = long;
using ULONG = unsigned long;
using ULONG64 = uint64_t;
using WCHAR = wchar_t;
struct PROCESS {};
constexpr NTSTATUS STATUS_SUCCESS=0, STATUS_ACCESS_DENIED=-1, STATUS_NOT_IMPLEMENTED=-2;
static uintptr_t current_pid=10, Api_ServiceProcessId=20;
static bool service_identity=false, signed_identity=false;
static ULONG leader=0;
static uintptr_t PsGetCurrentProcessId() { return current_pid; }
static bool MyIsCallerMyServiceProcess() { return service_identity; }
// Upstream convenience wrapper may bypass validation in developer/test modes.
static bool MyIsCallerSigned() { return true; }
static NTSTATUS KphVerifyCurrentProcess() { return signed_identity?STATUS_SUCCESS:STATUS_ACCESS_DENIED; }
#define NT_SUCCESS(value) ((value)>=0)
static ULONG Session_GetLeadSession(uintptr_t) { return leader; }
#include "ManagedApiUnderTest.inc"
int main(int argc,char**argv) {
    if(argc!=2) return 2;
    PROCESS sandbox;
    unsigned checks=0;
    bool reload=strcmp(argv[1],"reload")==0;
    for(unsigned boxed=0;boxed<2;boxed++)
    for(unsigned pid=0;pid<3;pid++)
    for(unsigned registered=0;registered<2;registered++)
    for(unsigned identity=0;identity<2;identity++)
    for(unsigned signature=0;signature<2;signature++)
    for(unsigned session=0;session<2;session++) {
        current_pid=pid==0?0:pid==1?10:20;
        Api_ServiceProcessId=registered?20:0;
        service_identity=identity; signed_identity=signature; leader=session?1:0;
        // Null arguments prove denial precedes all parameter access. The reload
        // continuation is a sentinel; its body is verified by the full build.
        auto actual=reload?Conf_Api_Reload(boxed?&sandbox:nullptr,nullptr):
                           Conf_Api_Update(boxed?&sandbox:nullptr,nullptr);
        bool allowed=reload&&!boxed&&registered&&pid==2&&identity&&signature;
        if(actual!=(allowed?STATUS_SUCCESS:STATUS_ACCESS_DENIED)) {
            fprintf(stderr,"check failed: %s authorization case %u\n",argv[1],checks);
            return 1;
        }
        checks++;
    }
    printf("{\"%s_authorization_checks\":%u}\n",argv[1],checks);
    return 0;
}
