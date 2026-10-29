// Extracted signer predicate; kernel signature status and environment are modeled.
#include <stdbool.h>
#include <stdio.h>
#define _FX
#define TRUE true
#define FALSE false
#define NT_SUCCESS(s) ((s)>=0)
typedef bool BOOLEAN;typedef long NTSTATUS;
static bool Driver_OsTestSigning;
enum {eCertDeveloper=1};
static struct {int type;bool active;} Verify_CertInfo;
static NTSTATUS signature;static unsigned calls;
static NTSTATUS KphVerifyCurrentProcess(void){calls++;return signature;}
#include "ManagedCallerSignatureUnderTest.inc"
int main(void){
 unsigned cases=0,mismatches=0,invalid_accepted=0,skipped=0;
 for(int test=0;test<2;test++)for(int type=0;type<2;type++)
 for(int active=0;active<2;active++)for(int valid=0;valid<2;valid++){
  Driver_OsTestSigning=test;Verify_CertInfo.type=type;Verify_CertInfo.active=active;
  signature=valid?0:-1;calls=0;
  bool result=MyIsCallerSigned();cases++;
  if(result!=(bool)valid || calls!=1)mismatches++;
  if(result&&!valid)invalid_accepted++;
  if(calls!=1)skipped++;
 }
 printf("{\"caller_signature_checks\":%u,\"caller_signature_mismatches\":%u,"
        "\"caller_invalid_signature_accepted\":%u,\"caller_signature_checks_skipped\":%u}\n",
        cases,mismatches,invalid_accepted,skipped);
 return mismatches?1:0;
}
