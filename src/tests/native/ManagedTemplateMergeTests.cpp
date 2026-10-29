#include <windows.h>
#include <cwchar>
#include <cstdio>
#define _FX
typedef LONG NTSTATUS;
#define NT_SUCCESS(x) ((LONG)(x)>=0)
#define STATUS_SUCCESS 0
struct CONF_SECTION {const WCHAR *name;bool from_template;CONF_SECTION *next;};
struct CONF_SETTING {};
struct CONF_DATA {CONF_SECTION *sections;};
static const WCHAR *Conf_GlobalSettings=L"GlobalSettings";
static const WCHAR *Conf_DefaultTemplates=L"DefaultTemplates";
static const WCHAR *Conf_Template_=L"Template_";
static const WCHAR *Conf_UserSettings_=L"UserSettings_";
static CONF_SECTION global={L"GlobalSettings",false,nullptr};
static CONF_SECTION common={L"DefaultTemplates",true,nullptr};
static bool has_global=true;
static LONG global_result=0,box_result=0;
static int defaults=0,explicit_global=0,boxes=0;
static CONF_SECTION *Conf_Get_Section(CONF_DATA*,const WCHAR *name) {
    if(!wcscmp(name,Conf_GlobalSettings))return has_global?&global:nullptr;
    if(!wcscmp(name,Conf_DefaultTemplates))return &common;
    return nullptr;
}
static LONG Conf_Merge_Templates(CONF_DATA*,ULONG,CONF_SECTION*,CONF_SECTION *section,const WCHAR*) {
    if(section==&common){++defaults;return 0;}
    if(section==&global){++explicit_global;return global_result;}
    ++boxes;return box_result;
}
static CONF_SECTION *List_Head(CONF_SECTION **head){return *head;}
static CONF_SECTION *List_Next(CONF_SECTION *section){return section->next;}
#include "ManagedMergeUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed at %d\n",__LINE__);return 1;}}while(0)
int main(int argc,char**) {
    CONF_DATA data={nullptr};
    if(argc>1) {
        global_result=(LONG)0xc000000d;
        CHECK(Conf_Merge_AllTemplates(&data,0)==global_result);
        return 0;
    }
    CHECK(Conf_Merge_AllTemplates(&data,0)==0 && explicit_global==1 && defaults==0);
    global_result=(LONG)0xc000000d;
    CHECK(Conf_Merge_AllTemplates(&data,0)==global_result);
    global_result=0;
    CONF_SECTION box={L"ClaudeReset.Tools",false,nullptr};data.sections=&box;
    CHECK(Conf_Merge_AllTemplates(&data,0)==0 && boxes==1 && defaults==0);
    box_result=(LONG)0xc000000d;
    CHECK(Conf_Merge_AllTemplates(&data,0)==box_result);
    has_global=false;box_result=0;
    CHECK(Conf_Merge_AllTemplates(&data,0)==0 && defaults==0);
    puts("{\"implicit_defaults_disabled\":true,\"merge_errors_propagated\":true}");
    return 0;
}
