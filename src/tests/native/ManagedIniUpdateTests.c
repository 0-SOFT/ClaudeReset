// Complete extracted CLI function. API stubs never contact a service/driver.
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <stdbool.h>
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef wchar_t WCHAR;
typedef bool BOOL;
#define FALSE false
#define TRUE true
#define ARRAYSIZE(a) (sizeof(a)/sizeof((a)[0]))
enum {ERRLVL_CMDLINE=1,ERRLVL_PASSWD=2,CONF_UPDATE_VALUE=1,CONF_APPEND_VALUE=2,
      CONF_REMOVE_VALUE=4,CONF_REMOVE_SECTION=5};
static const wchar_t *verb;
static bool driver;
static ULONG api_status;
static unsigned api_calls;
static WCHAR *CmdVerb(int n){
    static WCHAR section[]=L"ClaudeReset.Tools",setting[]=L"fixture",value[]=L"y";
    return n==1?section:n==2?setting:n==3?value:NULL;
}
static bool CmdIs(const wchar_t *s){return wcscmp(s,verb)==0;}
static WCHAR *CmdOpt(const wchar_t *s){static WCHAR yes[]=L"yes";return driver&&wcscmp(s,L"drv")==0?yes:NULL;}
static void UsageError(const wchar_t *s){(void)s;}
static wchar_t fixture_getwch(void){return 27;}
#define _getwch fixture_getwch
static ULONG SbieApi_UpdateConf(ULONG op,WCHAR *a,WCHAR *b,WCHAR *c){
    (void)op;(void)a;(void)b;(void)c;api_calls++;return api_status;
}
static ULONG SbieDll_UpdateConf(WCHAR op,WCHAR *pw,WCHAR *a,WCHAR *b,WCHAR *c){
    (void)op;(void)pw;(void)a;(void)b;(void)c;api_calls++;return api_status;
}
#include "ManagedIniUpdateUnderTest.inc"
static unsigned exit_code;
static LONG SbieApi_ReloadConf(ULONG session,ULONG flags){
    (void)session;(void)flags;api_calls++;return (LONG)api_status;
}
static void ExitProcess(unsigned result){exit_code=result;}
static void start_reload(void){
#include "ManagedStartReloadUnderTest.inc"
}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char **argv){
    (void)argv;
    const wchar_t *verbs[]={L"set",L"append",L"insert",L"delete"};
    const ULONG statuses[]={0,0xC0000022u,0xC000009Au,0xC000006Au};
    unsigned cases=0;
    if(argc==1)for(unsigned v=0;v<4;v++)for(unsigned d=0;d<2;d++)for(unsigned s=0;s<4;s++){
        verb=verbs[v];driver=d!=0;api_status=statuses[s];api_calls=0;
        int result=DoUpdate();
        CHECK(api_calls==1);
        CHECK(result==(s==0?0:s==3?ERRLVL_PASSWD:3));
        cases++;
    }
    for(unsigned s=0;s<4;s++){
        api_status=statuses[s];api_calls=0;exit_code=99;start_reload();
        CHECK(api_calls==1&&exit_code==(s==0?0:3));
    }
    // Wrong-password messages precede this report; verifier reads its final line.
    printf("\n{\"cli_mutation_results_checked\":%u,\"cli_reload_results_checked\":4}\n",cases);
    return 0;
}
