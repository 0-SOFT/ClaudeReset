// SPDX-License-Identifier: GPL-3.0-or-later
// Extracted queue transitions; transport, allocations and handles are modeled.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
using ULONG=uint32_t;using ULONG_PTR=uintptr_t;using HANDLE=void*;
const ULONG STATUS_END_OF_FILE=0xc0000011;
struct REQUEST_OBJ{REQUEST_OBJ* next=nullptr;ULONG client_pid=123,client_tid=7;
 HANDLE client_event=nullptr,client_process=(HANDLE)22;ULONG request_id=1,req_data_len=0,rpl_data_len=0;
 void* req_data_ptr=nullptr;void* rpl_data_ptr=nullptr;};
struct LIST{void* first=nullptr;};
struct QUEUE_OBJ{QUEUE_OBJ* next=nullptr;HANDLE server_pid=(HANDLE)456;LIST requests;};
static unsigned closed=0,freed=0,deleted=0;
static void check(bool x){if(!x){fprintf(stderr,"queue lifecycle assertion failed\n");exit(3);}}
static void* List_Head(LIST* list){return list->first;}
template<class T>static T* List_Next(T* p){return p->next;}
static void List_Remove(LIST* list,REQUEST_OBJ* p){check(list->first==p);list->first=p->next;}
static void NtClose(HANDLE h){check(h==(HANDLE)22);++closed;}
static void HeapFree(int,int,void*){++freed;}
static void EnterCriticalSection(int*){}static void LeaveCriticalSection(int*){}
struct QueueServer{
 int m_heap=0,m_lock=0;LIST m_queues;
 void DeleteRequestObj(LIST*,void*);
 void NotifyHandler(HANDLE);
 void DeleteQueueObj(QUEUE_OBJ* q){
  while(q->requests.first)DeleteRequestObj(&q->requests,q->requests.first);
  m_queues.first=q->next;++deleted;
 }
 ULONG pending(REQUEST_OBJ* RequestObj,QUEUE_OBJ* QueueObj){
  ULONG status=0;
#include "QueuePendingUnderTest.inc"
 finish:return status;
 }
 ULONG abandoned(REQUEST_OBJ* RequestObj,QUEUE_OBJ* QueueObj){
  ULONG status=0;
#include "QueueAbandonedUnderTest.inc"
 finish:return status;
 }
};
#include "QueueDeleteUnderTest.inc"
#include "QueueNotifyUnderTest.inc"
int main(){
 unsigned cases=0;
 // Pending and partially populated replies may not release an active worker's identity.
 for(unsigned state=0;state<3;++state){
  closed=freed=deleted=0;REQUEST_OBJ r;QUEUE_OBJ q;QueueServer s;q.requests.first=&r;
  if(state==1)r.rpl_data_len=4;if(state==2)r.rpl_data_ptr=(void*)1;
  check(s.pending(&r,&q)==STATUS_END_OF_FILE&&q.requests.first==&r&&!closed&&!freed);++cases;
 }
 // A complete reply is not handled by the pending branch.
 {closed=freed=0;REQUEST_OBJ r;r.rpl_data_len=4;r.rpl_data_ptr=(void*)1;QUEUE_OBJ q;q.requests.first=&r;QueueServer s;
  check(s.pending(&r,&q)==0&&q.requests.first==&r&&!closed&&!freed);++cases;}
 for(unsigned state=0;state<4;++state){
  closed=freed=deleted=0;REQUEST_OBJ r;QUEUE_OBJ q;QueueServer s;q.requests.first=&r;s.m_queues.first=&q;
  if(state==0){r.req_data_len=4;r.req_data_ptr=(void*)1;}
  if(state==2){r.rpl_data_len=4;r.rpl_data_ptr=(void*)1;}
  if(state==3)r.client_pid=999;
  s.NotifyHandler((HANDLE)123);
  if(state==0||state==2)check(!q.requests.first&&closed==1&&freed==2);
  else if(state==1){
   check(q.requests.first==&r&&r.client_pid==0&&!closed&&!freed);
   check(s.abandoned(&r,&q)==STATUS_END_OF_FILE&&!q.requests.first&&closed==1&&freed==1);
  }else check(q.requests.first==&r&&r.client_pid==999&&!closed&&!freed);
  ++cases;
 }
 // A live client's completed operation is not discarded as abandoned.
 {closed=freed=0;REQUEST_OBJ r;QUEUE_OBJ q;q.requests.first=&r;QueueServer s;
  check(s.abandoned(&r,&q)==0&&q.requests.first==&r&&!closed&&!freed);++cases;}
 // Removal of the owning server still releases the complete queue.
 {closed=freed=deleted=0;REQUEST_OBJ r;QUEUE_OBJ q;q.requests.first=&r;QueueServer s;s.m_queues.first=&q;
  s.NotifyHandler((HANDLE)456);check(!s.m_queues.first&&closed==1&&freed==1&&deleted==1);++cases;}
 printf("{\"cases\":%u,\"passed\":true,\"api_stubs\":true,\"installed_service_test\":false}\n",cases);
}
