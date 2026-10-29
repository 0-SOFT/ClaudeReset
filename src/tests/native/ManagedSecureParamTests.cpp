// Full extracted setter with modeled trust/registry and owned buffers only.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cstdint>
#define _FX
#define __try try
#define __except(...) catch(...)
typedef int NTSTATUS;
typedef uint64_t ULONG64;
typedef uint32_t ULONG;
typedef size_t SIZE_T;
typedef wchar_t WCHAR;
typedef unsigned char UCHAR;
struct PROCESS{};
template<class T>struct ARG{T val;};
struct API_SECURE_PARAM_ARGS{ARG<WCHAR*> param_name;ARG<UCHAR*> param_data;ARG<ULONG> param_size;};
const NTSTATUS STATUS_SUCCESS=0,STATUS_NOT_IMPLEMENTED=-1,STATUS_ACCESS_DENIED=-2,STATUS_INVALID_PARAMETER=-3;
static bool service_image,signed_image;
static uintptr_t Api_ServiceProcessId;
static int Driver_Pool;
static const WCHAR *Api_ParamPath=L"fixture";
static unsigned reads,probes,allocations,frees,writes;
static const WCHAR *expected_name;
bool MyIsCallerMyServiceProcess(){return service_image;}
bool MyIsCallerSigned(){return signed_image;}
SIZE_T checked_length(const WCHAR *value){++reads;return std::wcslen(value);}
#define wcslen checked_length
void ProbeForRead(void*,SIZE_T,size_t){++probes;}
struct Allocation{void *p;template<class T>operator T*()const{return static_cast<T*>(p);}};
Allocation Mem_Alloc(int,ULONG size){++allocations;return {malloc(size)};}
void Mem_Free(void *p,ULONG){++frees;free(p);}
NTSTATUS GetExceptionCode(){return -5;}
NTSTATUS SetRegValue(const WCHAR*,const WCHAR *name,UCHAR *data,ULONG size){
    if(wcscmp(name,expected_name)||size!=3||memcmp(data,"abc",3))return -4;
    ++writes;return STATUS_SUCCESS;
}
#include "ManagedSecureParamUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed at %d\n",__LINE__);return 1;}}while(0)
int main(){
    const WCHAR *names[]={L"CertBlockList",L"CertBlockListSig",L"CertBlocked",L"RandID"};
    unsigned cases=0,startup=0;
    for(unsigned sandbox=0;sandbox<2;++sandbox)
    for(unsigned identity=0;identity<2;++identity)
    for(unsigned signature=0;signature<2;++signature)
    for(unsigned registered=0;registered<2;++registered)
    for(const WCHAR *name:names){
        reads=probes=allocations=frees=writes=0;
        service_image=identity;signed_image=signature;Api_ServiceProcessId=registered?42:0;
        expected_name=name;UCHAR bytes[]={'a','b','c'};
        API_SECURE_PARAM_ARGS args={{const_cast<WCHAR*>(name)},{bytes},{3}};PROCESS proc;
        NTSTATUS result=Api_SetSecureParam(sandbox?&proc:nullptr,(ULONG64*)&args);
        bool allowed=!sandbox&&identity&&signature;
        CHECK(result==(sandbox?STATUS_NOT_IMPLEMENTED:allowed?STATUS_SUCCESS:STATUS_ACCESS_DENIED));
        if(allowed){
            CHECK(reads==1&&probes==2&&allocations==2&&frees==2&&writes==1);
            if(!registered)++startup;
        }else CHECK(!reads&&!probes&&!allocations&&!frees&&!writes);
        CHECK(!memcmp(bytes,"abc",3));++cases;
    }
    printf("{\"secure_param_role_checks\":%u,\"secure_param_startup_checks\":%u}\n",cases,startup);
    return 0;
}
