// SPDX-License-Identifier: GPL-3.0-or-later
// Actual PutReqHandler tail and DeleteRequestObj, with allocation/handle stubs.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
using ULONG=uint32_t;using ULONG_PTR=uintptr_t;using HANDLE=void*;using WCHAR=wchar_t;
const ULONG STATUS_INSUFFICIENT_RESOURCES=0xc000009a;
const ULONG STATUS_SHARING_VIOLATION=0xc0000043;
struct MSG_HEADER{ULONG status;};struct QUEUE_PUTREQ_RPL{MSG_HEADER h;ULONG req_id;};
struct REQUEST_OBJ{ULONG client_pid,client_tid;HANDLE client_event,client_process;ULONG request_id,req_data_len,rpl_data_len;void* req_data_ptr;void* rpl_data_ptr;REQUEST_OBJ* next;};
struct LIST{REQUEST_OBJ* first;};struct QUEUE_OBJ{LIST requests;HANDLE server_event;};
struct Request{ULONG data_len;};
static bool allocation;static unsigned eventCloses,processCloses,requestFrees,dataFrees,signals;
static REQUEST_OBJ requestObject;static int dataObject;
static QUEUE_PUTREQ_RPL reply;
static void check(bool value){if(!value){fprintf(stderr,"queue ownership assertion failed\n");exit(3);}}
struct PipeServer{static ULONG GetCallerThreadId(){return 7;}};
static ULONG InterlockedIncrement(ULONG* p){return ++*p;}
static void* LongReply(size_t){return allocation?&reply:nullptr;}
static void* ShortReply(ULONG status){reply.h.status=status;return &reply;}
#define LONG_REPLY(size) LongReply(size)
#define SHORT_REPLY(status) ShortReply(status)
static void HeapFree(int,int,void* p){if(p==&requestObject)++requestFrees;else if(p==&dataObject)++dataFrees;else check(false);}
static REQUEST_OBJ* List_Head(LIST* list){return list->first;}
static REQUEST_OBJ* List_Next(REQUEST_OBJ* p){return p->next;}
static void List_Insert_After(LIST* list,void*,REQUEST_OBJ* p){p->next=list->first;list->first=p;}
static void List_Remove(LIST* list,REQUEST_OBJ* p){check(list->first==p);list->first=p->next;}
static void SetEvent(HANDLE h){check(h==(HANDLE)33);++signals;}
static void CloseHandle(HANDLE h){if(h==(HANDLE)11)++eventCloses;else if(h==(HANDLE)22)++processCloses;else check(false);}
static void NtClose(HANDLE h){CloseHandle(h);}
static void LeaveCriticalSection(int*){}
struct QueueServer{
 int m_heap=0,m_lock=0;ULONG m_RequestId=1;
 void DeleteRequestObj(LIST*,void*);
 MSG_HEADER* tail(bool hasEvent,QUEUE_OBJ* QueueObj){
  HANDLE hEvent=hasEvent?(HANDLE)11:nullptr,hProcess=(HANDLE)22,idProcess=(HANDLE)123;
  WCHAR* QueueName=nullptr;ULONG status=0;QUEUE_PUTREQ_RPL* rpl=nullptr;
  REQUEST_OBJ* RequestObj=&requestObject;void* RequestData=&dataObject;
  Request request{8};Request* req=&request;
#include "QueueEventTailUnderTest.inc"
};
#include "QueueDeleteUnderTest.inc"
int main(int argc,char** argv){
 if(argc>1&&!strcmp(argv[1],"--process-lifetime")){
  unsigned cases=0;
  for(bool alloc:{false,true})for(bool event:{false,true}){
   allocation=alloc;eventCloses=processCloses=requestFrees=dataFrees=signals=0;
   requestObject={};reply={};QUEUE_OBJ queue{{nullptr},(HANDLE)33};QueueServer service;
   service.tail(event,&queue);
   if(alloc){
    check(processCloses==0&&requestObject.client_process==(HANDLE)22);
    service.DeleteRequestObj(&queue.requests,&requestObject);
   }
   check(processCloses==1&&!queue.requests.first&&requestFrees==1&&dataFrees==1);
   check(eventCloses==(event?1u:0u));++cases;
  }
  printf("{\"process_lifetime_checks\":%u,\"passed\":true}\n",cases);return 0;
 }
 if(argc>1&&!strcmp(argv[1],"--collision")){
  unsigned cases=0;
  for(bool event:{false,true})for(bool atHead:{false,true}){
   allocation=true;eventCloses=processCloses=requestFrees=dataFrees=signals=0;
   requestObject={};reply={};REQUEST_OBJ occupied{},other{};
   occupied.request_id=1;other.request_id=7;
   if(!atHead)other.next=&occupied;
   QUEUE_OBJ queue{{atHead?&occupied:&other},(HANDLE)33};
   REQUEST_OBJ* original=queue.requests.first;QueueServer service;service.m_RequestId=0xfffffffeu;
   MSG_HEADER* result=service.tail(event,&queue);
   check(result->status==STATUS_SHARING_VIOLATION&&queue.requests.first==original);
   check(occupied.request_id==1&&other.request_id==7&&!signals&&processCloses==1);
   check(eventCloses==(event?1u:0u)&&requestFrees==1&&dataFrees==1);
   ++cases;
  }
  for(bool event:{false,true}){
   allocation=true;eventCloses=processCloses=requestFrees=dataFrees=signals=0;
   requestObject={};reply={};REQUEST_OBJ occupied{};occupied.request_id=7;
   QUEUE_OBJ queue{{&occupied},(HANDLE)33};QueueServer service;service.m_RequestId=0xfffffffeu;
   service.tail(event,&queue);
   check(reply.req_id==1&&queue.requests.first==&requestObject&&requestObject.next==&occupied&&signals==1);
   service.DeleteRequestObj(&queue.requests,&requestObject);
   check(queue.requests.first==&occupied&&occupied.request_id==7&&processCloses==1);
   check(eventCloses==(event?1u:0u)&&requestFrees==1&&dataFrees==1);++cases;
  }
  printf("{\"request_id_collision_checks\":%u,\"passed\":true}\n",cases);return 0;
 }

 if(argc>1){
  for(ULONG seed:{0xfffffffeu,0xffffffffu,0u,1u}){
   allocation=true;eventCloses=processCloses=requestFrees=dataFrees=signals=0;
   requestObject={};reply={};QUEUE_OBJ queue{{nullptr},(HANDLE)33};QueueServer service;
   service.m_RequestId=seed;
   service.tail(false,&queue);
   check(reply.req_id!=0&&reply.req_id!=0xffffffffu&&reply.req_id==service.m_RequestId);
   service.DeleteRequestObj(&queue.requests,&requestObject);
  }
  printf("{\"request_id_boundary_checks\":4,\"passed\":true}\n");return 0;
 }
 unsigned cases=0;
 for(bool alloc:{false,true})for(bool event:{false,true}){
  allocation=alloc;eventCloses=processCloses=requestFrees=dataFrees=signals=0;
  requestObject={};reply={};QUEUE_OBJ queue{{nullptr},(HANDLE)33};QueueServer service;
  MSG_HEADER* result=service.tail(event,&queue);
  check(result&&processCloses==(alloc?0u:1u));
  if(!alloc){
   check(result->status==STATUS_INSUFFICIENT_RESOURCES&&!queue.requests.first&&!signals);
   check(eventCloses==(event?1u:0u)&&requestFrees==1&&dataFrees==1);
  }else{
   check(queue.requests.first==&requestObject&&signals==1&&!eventCloses&&!requestFrees&&!dataFrees);
   service.DeleteRequestObj(&queue.requests,&requestObject);
   check(processCloses==1&&!queue.requests.first&&eventCloses==(event?1u:0u)&&requestFrees==1&&dataFrees==1);
  }
  ++cases;
 }
 printf("{\"cases\":%u,\"passed\":true,\"installed_service_test\":false}\n",cases);
}
