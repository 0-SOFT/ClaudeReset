#define UNICODE
#define _UNICODE
#include <windows.h>
#include <string>
#include <cstdio>
#include <cwchar>
#include <cstdlib>
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>
#define NT_SUCCESS(x) ((LONG)(x)>=0)
#define STATUS_INVALID_PARAMETER ((LONG)0xc000000d)
#define STATUS_OBJECT_NAME_NOT_FOUND ((LONG)0xc0000034)
#define STATUS_OBJECT_PATH_NOT_FOUND ((LONG)0xc000003a)
#define STATUS_SUCCESS 0
#define RTL_REGISTRY_ABSOLUTE 0
#define FILE_OPEN 1
#define MSG_CONF_NO_FILE 0
#define MSG_CONF_READ 0
struct UNICODE_STRING { USHORT Length, MaximumLength; WCHAR *Buffer; };
static LONG reg_result=0, open_result=0, query_result=0;
static std::wstring configured=L"C:\\private\\policy.ini", queried;
static std::wstring opened;
static int opens=0, deletes=0;
static bool odd=false;
static LONG GetRegString(int,const WCHAR*,const WCHAR*,UNICODE_STRING *value) {
    if(reg_result) return reg_result;
    if((configured.size()+1)*sizeof(WCHAR)>value->MaximumLength) return STATUS_INVALID_PARAMETER;
    wcscpy(value->Buffer,configured.c_str());
    value->Length=(USHORT)(configured.size()*sizeof(WCHAR)+(odd?1:0));
    return 0;
}
static void Pool_Delete(void*) { ++deletes; }
static LONG Stream_Open(void**,const WCHAR *path,int,int,int,int,int) {
    ++opens;opened=path;return open_result;
}
static void Log_Msg_Session(int,void*,void*,ULONG) {}
static void Log_Status_Ex_Session(int,int,LONG,WCHAR*,ULONG) {}
static void RtlStringCbPrintfW(WCHAR *p,ULONG bytes,const WCHAR *format,const WCHAR *base) {
    StringCbPrintfW(p,bytes,format,base);
}
static void Mem_Free(void*,ULONG) {}
#ifdef TEST_MANAGED_TEMPLATES
static LONG template_path(const WCHAR *Driver_HomePathDos) {
    WCHAR path[520]={};ULONG path_len=sizeof(path);void *pool=nullptr;
#include "ManagedTemplatesUnderTest.inc"
    opened=path;return 0;
}
#endif
static LONG driver_path() {
    WCHAR buffer[260]={},linenum_str[32]={};
    WCHAR *path=buffer;ULONG path_len=sizeof(buffer),path_home=0,session_id=0;
    void *pool=nullptr,*stream=nullptr;
    LONG status=0;
    const WCHAR *Driver_RegistryPath=L"registry",*Driver_HomePathDos=L"\\??\\C:\\home";
    const WCHAR *path_sandboxie=L"%s\\Sandboxie.ini",*SystemRoot=L"\\SystemRoot";
#include "ManagedDriverUnderTest.inc"
    return status;
}
static LONG SbieApi_QueryConfAsIs(void*,const WCHAR*,int,WCHAR *buffer,ULONG bytes) {
    if(query_result) return query_result;
    size_t n=bytes/sizeof(WCHAR);
    wcsncpy(buffer,queried.c_str(),n);
    return 0;
}
#define SANDBOXIE_INI L"Sandboxie.ini"
static bool SbieDll_RunFromHome(const WCHAR*,void*,STARTUPINFOW*,void*) {return false;}
class SbieIniServer {public:static bool GetIniPath(WCHAR**,BOOLEAN*);};
#include "ManagedServiceUnderTest.inc"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"check failed at %d\n",__LINE__);return 1;}}while(0)
int main() {
    reg_result=STATUS_OBJECT_NAME_NOT_FOUND;
    CHECK(driver_path()==reg_result && opens==0 && deletes==1);
    reg_result=0;open_result=STATUS_OBJECT_NAME_NOT_FOUND;deletes=0;
    CHECK(driver_path()==open_result && opens==1 && deletes==1);
    CHECK(opened==L"\\DosDevices\\Global\\C:\\private\\policy.ini");
    open_result=0;opens=0;
    CHECK(driver_path()==0 && opens==1);
    for(const WCHAR *bad:{L"",L"C:relative",L"\\??\\C:\\policy",L"\\\\server\\share",L"1:\\bad",L"C:/"}) {
        configured=bad;opens=0;
        CHECK(driver_path()==STATUS_INVALID_PARAMETER && opens==0);
    }
    configured=L"C:\\policy";odd=true;opens=0;
    CHECK(driver_path()==STATUS_INVALID_PARAMETER && opens==0);odd=false;
    configured=std::wstring(300,L'A');CHECK(driver_path()==STATUS_INVALID_PARAMETER);
    WCHAR *output=nullptr;BOOLEAN home=TRUE;
    queried=L"\\DosDevices\\Global\\C:\\private\\policy.ini";
    CHECK(SbieIniServer::GetIniPath(&output,&home) && !home);
    CHECK(std::wstring(output)==L"\\\\?\\GLOBALROOT\\DosDevices\\Global\\C:\\private\\policy.ini");
    HeapFree(GetProcessHeap(),0,output);
    for(const WCHAR *bad:{L"H",L"W",L"\\??\\C:\\policy",L"C:\\policy",L"\\DosDevices\\Global\\C:relative"}) {
        queried=bad;output=nullptr;
        CHECK(!SbieIniServer::GetIniPath(&output,&home) && !output);
    }
    queried=std::wstring(260,L'A');CHECK(!SbieIniServer::GetIniPath(&output,&home));
    query_result=1;CHECK(!SbieIniServer::GetIniPath(&output,&home));
    CHECK(!SbieIniServer::GetIniPath(nullptr,&home));
#ifdef TEST_MANAGED_TEMPLATES
    CHECK(template_path(L"\\??\\C:\\Program Files\\ClaudeReset\\Sandboxie\\x64")==0);
    CHECK(opened==L"\\DosDevices\\Global\\C:\\Program Files\\ClaudeReset\\Sandboxie\\x64\\Templates.ini");
    CHECK(template_path(L"C:\\ordinary")==STATUS_INVALID_PARAMETER);
    CHECK(template_path(L"\\??\\UNC\\server\\share")==STATUS_INVALID_PARAMETER);
    CHECK(template_path(L"\\??\\C:relative")==STATUS_INVALID_PARAMETER);
#endif
    puts("{\"managed_config_checks_passed\":true,\"installed\":false}");
    return 0;
}
