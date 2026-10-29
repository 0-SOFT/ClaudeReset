// SPDX-License-Identifier: GPL-3.0-or-later
// Exact PutRplHandler reply publication; transport and Windows APIs are stubbed.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
using ULONG=uint32_t;
const ULONG STATUS_END_OF_FILE=0xc0000011, STATUS_SUCCESS=0, STATUS_SHARING_VIOLATION=0xc0000043, STATUS_INSUFFICIENT_RESOURCES=0xc000009a;
struct REQUEST_OBJ {ULONG client_pid=123;ULONG req_data_len=0;void* req_data_ptr=nullptr;void* rpl_data_ptr=nullptr;ULONG rpl_data_len=0;void* client_event=nullptr;};
struct QUEUE_OBJ {int requests=0;};
struct REQ {ULONG data_len;char data[8];};
static unsigned allocations,attempts,deletes,signals;
static bool failAllocation;
static void* allocated[8];
static void check(bool ok){if(!ok){fprintf(stderr,"queue reply ownership assertion failed\n");exit(3);}}
static void* HeapAlloc(int,int,size_t n){++attempts;if(failAllocation)return nullptr;check(allocations<8);void* p=malloc(n);check(p!=nullptr);allocated[allocations++]=p;return p;}
static void SetEvent(void*){++signals;}
static void DeleteRequestObj(int*,REQUEST_OBJ*){++deletes;}
static void reset(){for(unsigned i=0;i<allocations;++i)free(allocated[i]);allocations=attempts=deletes=signals=0;failAllocation=false;}
static ULONG send(REQUEST_OBJ* RequestObj,REQ* req){
 int m_heap=0;ULONG status=0;QUEUE_OBJ queue;QUEUE_OBJ* QueueObj=&queue;
 {
#include "QueueReplyUnderTest.inc"
 }
finish:return status;
}
int main(){
 REQ first{4,"one"},second{4,"two"};unsigned cases=0;
 for(unsigned event=0;event<2;++event){
  reset();REQUEST_OBJ request;request.client_event=event?(void*)1:nullptr;
  check(send(&request,&first)==STATUS_SUCCESS);void* firstPointer=request.rpl_data_ptr;
  check(send(&request,&second)==STATUS_SHARING_VIOLATION);
  check(request.rpl_data_ptr==firstPointer&&request.rpl_data_len==4&&memcmp(firstPointer,first.data,4)==0);
  check(attempts==1&&allocations==1&&signals==event&&deletes==0);++cases;
 }
 for(unsigned pointer=0;pointer<2;++pointer){
  reset();REQUEST_OBJ request;request.rpl_data_ptr=pointer?(void*)1:nullptr;request.rpl_data_len=pointer?0:4;
  check(send(&request,&second)==STATUS_SHARING_VIOLATION);
  check(request.rpl_data_ptr==(pointer?(void*)1:nullptr)&&request.rpl_data_len==(pointer?0u:4u));
  check(attempts==0&&signals==0&&deletes==0);++cases;
 }
 reset();REQUEST_OBJ request;failAllocation=true;
 check(send(&request,&first)==STATUS_INSUFFICIENT_RESOURCES&&attempts==1&&allocations==0&&deletes==1&&signals==0);++cases;
 reset();request.req_data_len=1;
 check(send(&request,&first)==STATUS_SHARING_VIOLATION&&attempts==0&&deletes==1&&signals==0);++cases;
 reset();printf("{\"cases\":%u,\"passed\":true,\"api_stubs\":true,\"installed_service_test\":false}\n",cases);
}
