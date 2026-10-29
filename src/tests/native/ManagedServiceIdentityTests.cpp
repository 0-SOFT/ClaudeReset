#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>
#define _FX
#define TRUE true
#define FALSE false
#define SBIESVC_EXE L"SbieSvc.exe"
using BOOLEAN=bool;using ULONG=unsigned long;using ULONG_PTR=uintptr_t;using WCHAR=wchar_t;using SIZE_T=size_t;
struct UNICODE_STRING {unsigned short Length,MaximumLength;WCHAR*Buffer;};
static std::wstring home=L"\\Device\\HarddiskVolume3\\Program Files\\ClaudeReset\\Sandboxie\\x64",image;
static const WCHAR*Driver_HomePathNt=home.c_str();static ULONG Driver_HomePathNt_Len=ULONG(home.size());
static void*Driver_Pool=nullptr;static bool system_identity=true,found=true;static unsigned queries=0,frees=0;
static UNICODE_STRING name;
static bool MyIsCurrentProcessRunningAsLocalSystem(){return system_identity;}
static uintptr_t PsGetCurrentProcessId(){return 7;}
static void Process_GetProcessName(void*,ULONG,void**buffer,ULONG*length,WCHAR**leaf){
 queries++;*buffer=found?&name:nullptr;*length=sizeof(name);
 size_t offset=image.find_last_of(L'\\');*leaf=image.data()+(offset==std::wstring::npos?0:offset+1);
}
static void Mem_Free(void*,ULONG){frees++;}
#include "ManagedServiceIdentityUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d case %u: %s\n",__LINE__,checks,#x);return 1;}}while(0)
int main(){
 unsigned checks=0;
 std::vector<std::pair<std::wstring,bool>> cases={
  {home+L"\\SbieSvc.exe",true},{home+L"\\sbiesvc.EXE",true},
  {home+L"-extra\\SbieSvc.exe",false},{home+L"\\nested\\SbieSvc.exe",false},
  {home+L"SbieSvc.exe",false},{home+L"\\Other.exe",false},
  {home+L"\\SbieSvc.exe.bak",false},{home,false},{L"",false}};
 for(auto&row:cases)for(unsigned sys=0;sys<2;sys++)for(unsigned present=0;present<2;present++){
  image=row.first;system_identity=sys;found=present;queries=frees=0;
  name={static_cast<unsigned short>(image.size()*sizeof(WCHAR)),static_cast<unsigned short>((image.size()+1)*sizeof(WCHAR)),image.data()};
  CHECK(MyIsCallerMyServiceProcess()==(row.second&&sys&&present));
  CHECK(queries==sys&&frees==(sys&&present?1u:0u));checks++;
 }
 image=home+L"\\SbieSvc.exe";system_identity=true;found=true;
 name={static_cast<unsigned short>(image.size()*sizeof(WCHAR)-2),static_cast<unsigned short>((image.size()+1)*sizeof(WCHAR)),image.data()};
 CHECK(!MyIsCallerMyServiceProcess());checks++;
 name.Length=static_cast<unsigned short>(image.size()*sizeof(WCHAR)-1);CHECK(!MyIsCallerMyServiceProcess());checks++;
 name.Length=static_cast<unsigned short>(image.size()*sizeof(WCHAR));Driver_HomePathNt_Len=0;
 CHECK(!MyIsCallerMyServiceProcess());checks++;
 printf("{\"exact_service_identity_checks\":%u}\n",checks);return 0;
}
