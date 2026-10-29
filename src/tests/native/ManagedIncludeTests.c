// Extracted include dispatcher and its actual Conf_Read status propagation.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#define _FX
#define FALSE false
#define NT_SUCCESS(x) ((x)>=0)
typedef unsigned long ULONG;typedef long NTSTATUS;typedef size_t SIZE_T;
enum {STATUS_SUCCESS=0,STATUS_INVALID_PARAMETER=-1,STATUS_OBJECT_NAME_NOT_FOUND=-2};
typedef struct Setting {struct Setting*next;const wchar_t*name,*value;} CONF_SETTING;
typedef struct {CONF_SETTING*settings_map;} CONF_SECTION;
typedef struct {CONF_SECTION*global;} CONF_DATA;
typedef struct {CONF_SETTING*next,*value;const wchar_t*key;} map_iter_t;
static const wchar_t*Conf_GlobalSettings=L"GlobalSettings",*Conf_ImportBox=L"IncludeBox";
static unsigned imports=0;
static CONF_SECTION*Conf_Get_Section(CONF_DATA*d,const wchar_t*n){return d->global;}
static map_iter_t map_key_iter(CONF_SETTING**map,const wchar_t*key){map_iter_t i={*map,NULL,key};return i;}
static bool map_next(CONF_SETTING**map,map_iter_t*i){
 while(i->next){i->value=i->next;i->next=i->next->next;if(!_wcsicmp(i->value->name,i->key))return true;}
 return false;
}
static NTSTATUS Conf_Import_Includes(CONF_DATA*d,ULONG s,const wchar_t*p){imports++;return -9;}
static NTSTATUS Conf_Import_Include(CONF_DATA*d,ULONG s,const wchar_t*p,bool wild){imports++;return -9;}
#include "ManagedIncludesUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char**argv){
 if(argc!=2)return 2;
 CONF_SETTING normal={NULL,L"NetworkEnableWFP",L"y"};
 CONF_SECTION global={&normal};CONF_DATA data={&global};
 CHECK(ReadIncludes(&data)==STATUS_SUCCESS&&imports==0);
 if(!strcmp(argv[1],"missing")){
   data.global=NULL;CHECK(ReadIncludes(&data)==STATUS_OBJECT_NAME_NOT_FOUND&&imports==0);
 }else if(!strcmp(argv[1],"include")){
   const wchar_t*paths[]={L"C:\\foreign.ini",L"C:\\foreign\\*",L"C:\\foreign\\",L"\\\\host\\share\\box.ini",L"\\??\\C:\\box.ini",L""};
   CONF_SETTING include={NULL,L"iNcLuDeBoX",NULL};normal.next=&include;
   for(unsigned i=0;i<sizeof(paths)/sizeof(paths[0]);i++){
     include.value=paths[i];CHECK(ReadIncludes(&data)==STATUS_INVALID_PARAMETER&&imports==0);
   }
   normal.next=NULL;CHECK(ReadIncludes(&data)==STATUS_SUCCESS&&imports==0);
 }else return 2;
 printf("{\"managed_%s_rejected_before_external_io\":true}\n",argv[1]);return 0;
}
