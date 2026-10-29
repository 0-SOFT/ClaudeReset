// Exact extracted candidate validator and actual pre-commit branch.
#include <stdbool.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <wctype.h>
#define _FX
#define NT_SUCCESS(x) ((x)>=0)
typedef unsigned long ULONG;typedef long NTSTATUS;
typedef wchar_t WCHAR;
#include "ManagedPolicyFixture.h"
enum {STATUS_SUCCESS=0,STATUS_INVALID_PARAMETER=-1};
typedef struct Setting {struct Setting*next;const wchar_t *name,*value;bool from_template;} CONF_SETTING;
typedef struct {CONF_SETTING*settings;bool from_template,is_virtual;void*include_path;} CONF_SECTION;
typedef struct {CONF_SECTION*global;CONF_SECTION*boxes[BOX_COUNT];} CONF_DATA;
static const wchar_t*Conf_GlobalSettings=L"GlobalSettings";
static CONF_SECTION*Conf_Find_Sections(CONF_DATA*data,const wchar_t*name){
 if(_wcsicmp(name,Conf_GlobalSettings)==0)return data->global;
 for(unsigned i=0;i<BOX_COUNT;i++)if(_wcsicmp(name,FixtureBoxes[i])==0)return data->boxes[i];
 return NULL;
}
#define List_Head(p) (*(p))
#define List_Next(p) ((p)->next)
#include "ManagedPolicyUnderTest.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char **argv){
 CONF_SETTING object={NULL,L"EnableObjectFiltering",L"y",false};
 CONF_SETTING network={&object,L"NetworkEnableWFP",L"y",false};
 CONF_SECTION global={&network,false,false,NULL};CONF_DATA data={&global};
 CONF_SECTION boxes[BOX_COUNT]={0};CONF_SETTING settings[BOX_COUNT][SETTING_COUNT]={0};
 for(unsigned i=0;i<BOX_COUNT;i++){
  data.boxes[i]=&boxes[i];boxes[i].settings=settings[i];
  for(unsigned k=0;k<SETTING_COUNT;k++){
   settings[i][k].name=FixtureKeys[k];settings[i][k].value=FixtureValues[k];
   if(k+1<SETTING_COUNT)settings[i][k].next=&settings[i][k+1];
  }
 }
 CHECK(CandidateMayReplace(data,0));
 if(argc==1){
 CHECK(CandidateMayReplace(data,0));CHECK(!CandidateMayReplace(data,-1));
 const wchar_t*bad[]={L"n",L"",L"yes",L"true",L"1",L"y,other",NULL};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
   network.value=bad[i];CHECK(!CandidateMayReplace(data,0));network.value=L"y";
   object.value=bad[i];CHECK(!CandidateMayReplace(data,0));object.value=L"y";
 }
 network.value=L"Y";object.value=L"Y";CHECK(CandidateMayReplace(data,0));
 network.next=NULL;CHECK(!CandidateMayReplace(data,0));network.next=&object;
 global.settings=&object;CHECK(!CandidateMayReplace(data,0));global.settings=&network;
 data.global=NULL;CHECK(!CandidateMayReplace(data,0));data.global=&global;
 CONF_SETTING duplicate={NULL,L"networkenablewfp",L"y",false};
 object.next=&duplicate;CHECK(!CandidateMayReplace(data,0));object.next=NULL;
 network.from_template=true;CHECK(!CandidateMayReplace(data,0));network.from_template=false;
 object.from_template=true;CHECK(!CandidateMayReplace(data,0));object.from_template=false;
 global.from_template=true;CHECK(!CandidateMayReplace(data,0));global.from_template=false;
 global.is_virtual=true;CHECK(!CandidateMayReplace(data,0));global.is_virtual=false;
 global.include_path=&global;CHECK(!CandidateMayReplace(data,0));global.include_path=NULL;
 CONF_SETTING include={NULL,L"iNcLuDeBoX",L"C:\\foreign.ini",false};
 object.next=&include;CHECK(!CandidateMayReplace(data,0));
 include.from_template=true;CHECK(!CandidateMayReplace(data,0));object.next=NULL;
 }
 CHECK(CandidateMayReplace(data,0));
 unsigned checks=0;
 for(unsigned i=0;i<BOX_COUNT;i++){
  data.boxes[i]=NULL;CHECK(!CandidateMayReplace(data,0));checks++;data.boxes[i]=&boxes[i];
  boxes[i].from_template=true;CHECK(!CandidateMayReplace(data,0));checks++;boxes[i].from_template=false;
  boxes[i].is_virtual=true;CHECK(!CandidateMayReplace(data,0));checks++;boxes[i].is_virtual=false;
  boxes[i].include_path=&boxes[i];CHECK(!CandidateMayReplace(data,0));checks++;boxes[i].include_path=NULL;
  for(unsigned k=0;k<SETTING_COUNT;k++){
   CONF_SETTING *item=&settings[i][k],*last=&settings[i][SETTING_COUNT-1];
   item->name=L"Unrelated";CHECK(!CandidateMayReplace(data,0));checks++;item->name=FixtureKeys[k];
   item->value=FixtureValues[k][0]==L'y'?L"n":L"y";CHECK(!CandidateMayReplace(data,0));checks++;
   item->value=NULL;CHECK(!CandidateMayReplace(data,0));checks++;item->value=FixtureValues[k];
   item->from_template=true;CHECK(!CandidateMayReplace(data,0));checks++;item->from_template=false;
   CONF_SETTING duplicate={NULL,item->name,item->value,false};last->next=&duplicate;
   CHECK(!CandidateMayReplace(data,0));checks++;last->next=NULL;
   wchar_t upper[80];wcscpy(upper,item->name);
   for(unsigned c=0;upper[c];c++)upper[c]=towupper(upper[c]);
   item->name=upper;item->value=FixtureValues[k][0]==L'y'?L"Y":L"N";
   CHECK(CandidateMayReplace(data,0));checks++;
   item->name=FixtureKeys[k];item->value=FixtureValues[k];
  }
 }
 unsigned forbidden_checks=0;
 const wchar_t *values[]={L"*",L"",L"n"};
 for(unsigned section=0;section<=BOX_COUNT;section++){
  CONF_SETTING **tail=section==0?&object.next:&settings[section-1][SETTING_COUNT-1].next;
  for(unsigned key=0;key<FORBIDDEN_COUNT;key++){
   wchar_t upper[80];wcscpy(upper,FixtureForbidden[key]);
   for(unsigned c=0;upper[c];c++)upper[c]=towupper(upper[c]);
   for(unsigned value=0;value<3;value++)for(unsigned inherited=0;inherited<2;inherited++)for(unsigned spelling=0;spelling<2;spelling++){
    CONF_SETTING extra={NULL,spelling?upper:FixtureForbidden[key],values[value],inherited!=0};
    *tail=&extra;CHECK(!CandidateMayReplace(data,0));forbidden_checks++;*tail=NULL;
   }
  }
 }
 CHECK(CandidateMayReplace(data,0));
 printf("{\"candidate_policy_gate_passed\":true,\"managed_box_policy_checks\":%u,\"managed_forbidden_setting_checks\":%u}\n",checks,forbidden_checks);return 0;
}
