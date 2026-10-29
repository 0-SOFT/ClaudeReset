"""Prepare a hash-pinned source patch; never replace/restart installed services."""
from pathlib import Path
import argparse,difflib,hashlib,json,shutil
ROOT=Path(__file__).resolve().parents[1];inputs=ROOT/'work/sandbox-driver';out=ROOT/'work/sandboxie-hardening'
HASHES=json.loads((ROOT/'third_party/sources/sandboxie-lock.json').read_text('utf-8'))['service_inputs']
def one(text,old,new):
    if text.count(old)!=1:raise ValueError('Upstream integration point changed')
    return text.replace(old,new,1)
def prepare(source_root=None,output_root=None):
    out=Path(output_root) if output_root else ROOT/'work/sandboxie-hardening'
    reviewed={}
    for name,digest in HASHES.items():
        source=Path(source_root)/'Sandboxie/core/svc'/name if source_root else inputs/('source-svc-'+name)
        data=source.read_bytes()
        if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Unreviewed upstream source: '+name)
        reviewed[name]=data
    out.mkdir(parents=True,exist_ok=True);patch=[];manifest={}
    for name,digest in HASHES.items():
        data=reviewed[name]
        before=data.decode('utf-8-sig').replace('\r\n','\n');after=before
        if name=='PipeServer.cpp':
            after=one(after,'#include "sbieiniserver.h"','#include "sbieiniserver.h"\n#include "CrBrokerWindows.h"')
            after=one(after,'        msgOut = (*target->handler)(target->context, msg);',
                '        if (CrIsStrictSandbox(GetCallerProcessId()) && !CrPipeAllowed(msgid))\n'
                '            msgOut = AllocShortMsg(STATUS_ACCESS_DENIED);\n'
                '        else\n            msgOut = (*target->handler)(target->context, msg);')
        elif name=='GuiServer.cpp':
            after=one(after,'#include "misc.h"','#include "misc.h"\n#include "CrBrokerWindows.h"')
            after=one(after,'    ULONG msgid = *(ULONG *)data_ptr;\n\n    if (msgid < GUI_MAX_REQUEST_CODE)',
                '    ULONG msgid = data_ptr && data_len >= sizeof(ULONG) ? *(ULONG *)data_ptr : 0;\n\n'
                '    if (msgid > 0 && msgid < GUI_MAX_REQUEST_CODE)')
            marker='            if (issue_request) {\n\n                args.req_len = data_len;'
            after=one(after,marker,
                '            if (issue_request && CrIsStrictSandbox(args.pid) && !CrGuiAllowed(msgid)) {\n'
                '                status = STATUS_ACCESS_DENIED;\n                issue_request = false;\n            }\n\n'+marker)
            # Validate the original element count before multiplication; the
            # later byte-size check alone can be bypassed by ULONG wrapping.
            after=one(after,'        if (req->uiCommand == RIDI_DEVICENAME && req->unicode) {\n            lenData *= sizeof(WCHAR);',
                '        if (req->uiCommand == RIDI_DEVICENAME && req->unicode) {\n'
                '            if (lenData > (MAX_RPL_BUF_SIZE - sizeof(GUI_GET_RAW_INPUT_DEVICE_INFO_RPL)) / sizeof(WCHAR))\n'
                '                return STATUS_INVALID_PARAMETER;\n'
                '            lenData *= sizeof(WCHAR);')
            start=after.index('ULONG GuiServer::WndHookRegisterSlave(SlaveArgs* args)')
            end=after.index('// GetProcessPathList',start)
            old=after[start:end]; fixed=old
            fixed=one(fixed,'        if (!hThread) \n            return STATUS_UNSUCCESSFUL;',
                '        if (!hThread) {\n            LeaveCriticalSection(&m_SlavesLock);\n'
                '            return STATUS_UNSUCCESSFUL;\n        }')
            fixed=one(fixed,'        if (ownerPid != args->pid)\n            return STATUS_ACCESS_DENIED;',
                '        if (ownerPid != args->pid) {\n            LeaveCriticalSection(&m_SlavesLock);\n'
                '            return STATUS_ACCESS_DENIED;\n        }')
            fixed=one(fixed,'            whk = (WND_HOOK *)HeapAlloc(GetProcessHeap(), 0, sizeof(WND_HOOK));\n            whk->pid',
                '            whk = (WND_HOOK *)HeapAlloc(GetProcessHeap(), 0, sizeof(WND_HOOK));\n'
                '            if (!whk) {\n                LeaveCriticalSection(&m_SlavesLock);\n'
                '                return STATUS_INSUFFICIENT_RESOURCES;\n            }\n            whk->pid')
            after=one(after,old,fixed)
        elif name=='queueserver.cpp':
            # A client may abandon a dispatched request before its worker ends.
            # PID zero is internal abandoned state, never a real client identity.
            start=after.index('MSG_HEADER *QueueServer::GetRplHandler(')
            end=after.index('// OpenProcess',start)
            old=after[start:end]
            fixed=one(old,'        DeleteRequestObj(&QueueObj->requests, RequestObj);\n        status = STATUS_END_OF_FILE;',
                '        // A premature fetch must not release the active worker identity.\n'
                '        status = STATUS_END_OF_FILE;')
            after=one(after,old,fixed)
            old='                if (RequestObj->client_pid == (ULONG)(ULONG_PTR)idProcess) {\n\n                    DeleteRequestObj(&QueueObj->requests, RequestObj);\n                }'
            new='                if (RequestObj->client_pid == (ULONG)(ULONG_PTR)idProcess) {\n                    // Keep a dispatched request alive until its worker replies.\n                    if (!RequestObj->req_data_len && !RequestObj->req_data_ptr &&\n                            !RequestObj->rpl_data_len && !RequestObj->rpl_data_ptr)\n                        RequestObj->client_pid = 0;\n                    else\n                        DeleteRequestObj(&QueueObj->requests, RequestObj);\n                }'
            after=one(after,old,new)
            start=after.index('MSG_HEADER *QueueServer::PutRplHandler(')
            end=after.index('// PutReqHandler',start)
            old=after[start:end]
            fixed=one(old,'    void *ReplyData = HeapAlloc(m_heap, 0, req->data_len);',
                '    // A reply ends ownership of a disconnected client request.\n'
                '    if (! RequestObj->client_pid) {\n'
                '        DeleteRequestObj(&QueueObj->requests, RequestObj);\n'
                '        status = STATUS_END_OF_FILE;\n        goto finish;\n    }\n\n'
                '    void *ReplyData = HeapAlloc(m_heap, 0, req->data_len);')
            after=one(after,old,fixed)
            # Retain the opened client object until its request is removed.
            # The numeric PID must not outlive the object whose request it names.
            after=one(after,'    HANDLE client_event;','    HANDLE client_event;\n    HANDLE client_process;')
            after=one(after,'    RequestObj->client_pid = (ULONG)(ULONG_PTR)idProcess;',
                '    RequestObj->client_pid = (ULONG)(ULONG_PTR)idProcess;\n'
                '    RequestObj->client_process = hProcess;')
            after=one(after,'        List_Insert_After(&QueueObj->requests, NULL, RequestObj);',
                '        hProcess = NULL; // the published request retains the client object\n'
                '        List_Insert_After(&QueueObj->requests, NULL, RequestObj);')
            for signature in ('void QueueServer::CloseCallback(', 'void QueueServer::DeleteRequestObj('):
                start=after.index(signature)
                position=after.index('    REQUEST_OBJ *RequestObj =',start)
                end=after.index('\n',position)
                after=after[:end]+('\n    if (RequestObj->client_process)\n'
                    '        NtClose(RequestObj->client_process);')+after[end:]
            start=after.index('MSG_HEADER *QueueServer::PutRplHandler(')
            end=after.index('// PutReqHandler',start)
            old=after[start:end]
            fixed=one(old,'    void *ReplyData = HeapAlloc(m_heap, 0, req->data_len);',
                '    // Preserve the first reply until the client consumes it.\n'
                '    if (RequestObj->rpl_data_len || RequestObj->rpl_data_ptr) {\n'
                '        status = STATUS_SHARING_VIOLATION;\n        goto finish;\n    }\n\n'
                '    void *ReplyData = HeapAlloc(m_heap, 0, req->data_len);')
            after=one(after,old,fixed)
            after=one(after,'''    RequestObj->request_id = InterlockedIncrement(&m_RequestId);
    while (m_RequestId == 0 || m_RequestId == -1)
        InterlockedIncrement(&m_RequestId);''',
                '''    // Assign the final non-reserved value to the request itself.
    do {
        RequestObj->request_id = InterlockedIncrement(&m_RequestId);
    } while (RequestObj->request_id == 0 || RequestObj->request_id == (ULONG)-1);
    // A wrapped counter must never alias a still outstanding request in this
    // queue. m_lock is held across allocation, this scan and list insertion.
    // Fail this submission without replacing or signalling the old request.
    for (REQUEST_OBJ *existing = (REQUEST_OBJ *)List_Head(&QueueObj->requests);
            existing; existing = (REQUEST_OBJ *)List_Next(existing)) {
        if (existing->request_id == RequestObj->request_id) {
            HeapFree(m_heap, 0, RequestData);
            HeapFree(m_heap, 0, RequestObj);
            status = STATUS_SHARING_VIOLATION;
            goto finish;
        }
    }''')
            # Keep the local event handle until the request is owned by
            # the queue. Reply allocation failure otherwise leaks the duplicate.
            after=one(after,'    RequestObj->client_event = hEvent;\n    hEvent = NULL;',
                '    RequestObj->client_event = hEvent;')
            after=one(after,'        List_Insert_After(&QueueObj->requests, NULL, RequestObj);',
                '        hEvent = NULL; // queue takes ownership only after reply allocation\n'
                '        List_Insert_After(&QueueObj->requests, NULL, RequestObj);')
            after=one(after,'#include "GuiServer.h"','#include "GuiServer.h"\n#include "core/dll/sbieapi.h"\n#include "CrBrokerWindows.h"')
            marker='    if (msg->msgid == MSGID_QUEUE_STARTUP) {'
            after=one(after,marker,
                '    // Only NotifyTargets uses a zero TLS caller thread; wire notifications are rejected.\n'
                '    if (msg->msgid == MSGID_QUEUE_NOTIFICATION && !PipeServer::GetCallerThreadId()) {\n'
                '        pThis->NotifyHandler(idProcess);\n        return NULL;\n    }\n\n'
                '    if (CrIsStrictSandbox((ULONG)(ULONG_PTR)idProcess)) {\n'
                '        if (msg->length < sizeof(MSG_HEADER) + QUEUE_NAME_MAXLEN * sizeof(WCHAR))\n'
                '            return SHORT_REPLY(STATUS_INVALID_PARAMETER);\n'
                '        ULONG session = 0;\n'
                '        if (SbieApi_QueryProcess(idProcess,NULL,NULL,NULL,&session) != 0 ||\n'
                '            !CrQueueAllowed(msg->msgid,((QUEUE_GETRPL_REQ*)msg)->queue_name,QUEUE_NAME_MAXLEN,session))\n'
                '            return SHORT_REPLY(STATUS_ACCESS_DENIED);\n    }\n\n'+marker)
        else:
            after=one(after,'#include "ProcessServer.h"','#include "ProcessServer.h"\n#include "CrBrokerWindows.h"\n#include "CrBootstrapSecurity.h"\n#include "CrBootstrapLaunch.h"')
            marker='    HANDLE ImpersonationTokenHandle = NULL;\n    ULONG LastError;\n    BOOL ok = TRUE;'
            after=one(after,marker,
                '    const ULONG strictCaller = PipeServer::GetCallerProcessId();\n'
                '    if (CrIsStrictSandbox(strictCaller) &&\n'
                '            !CrSpawnAllowed((long long)BoxNameOrModelPid,strictCaller,cmd,crflags)) {\n'
                '        SetLastError(ERROR_ACCESS_DENIED);\n        return FALSE;\n    }\n\n'+marker)
            marker='            // create new process\n            ok = CreateProcessAsUser(\n                    PrimaryTokenHandle, NULL, cmd, NULL, NULL, FALSE,\n                    crflags2, env, dir, si, pi);\n            LastError = GetLastError();'
            after=one(after,marker,
                '            // Set object ACLs at creation, before the first thread or driver admission.\n'
                '            CrBootstrapSecurity bootstrapSecurity;\n'
                '            CrBootstrapLaunch bootstrapLaunch;\n'
                '            const bool strictBootstrap = CrIsStrictSandbox(strictCaller);\n'
                '            ok = !strictBootstrap || bootstrapSecurity.Initialize();\n'
                '            if (ok && strictBootstrap) {\n'
                '                WCHAR trustedHome[MAX_PATH] = {0};\n'
                '                ok = SbieApi_GetHomePath(NULL, 0, trustedHome, MAX_PATH) == 0 &&\n'
                '                    bootstrapLaunch.Initialize(trustedHome);\n'
                '            }\n'
                '            if (ok) {\n'
                '                ok = CreateProcessAsUser(\n'
                '                    PrimaryTokenHandle, strictBootstrap ? bootstrapLaunch.Application() : NULL,\n'
                '                    strictBootstrap ? bootstrapLaunch.Command() : cmd,\n'
                '                    strictBootstrap ? bootstrapSecurity.Process() : NULL,\n'
                '                    strictBootstrap ? bootstrapSecurity.Thread() : NULL, FALSE,\n'
                '                    crflags2, strictBootstrap ? bootstrapLaunch.Environment() : env,\n'
                '                    strictBootstrap ? bootstrapLaunch.Directory() : dir,\n'
                '                    strictBootstrap ? bootstrapLaunch.Startup() : si, pi);\n'
                '            }\n            LastError = GetLastError();')
            after=one(after,'    if (!FilterHandles) {      // *COMSRV* case or breakout process',
                '    const bool strictHandles = CrIsStrictSandbox(PipeServer::GetCallerProcessId());\n'
                '    if (strictHandles) FilterHandles = TRUE;\n\n'
                '    if (!FilterHandles || strictHandles) { // strict bootstrap must remain boxed')
            after=one(after,'        ok = DuplicateHandle(GetCurrentProcess(), piInput->hProcess,',
                '        if (strictHandles) dwRead = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;\n'
                '        ok = DuplicateHandle(GetCurrentProcess(), piInput->hProcess,')
            after=one(after,'        ok = DuplicateHandle(GetCurrentProcess(), piInput->hThread,',
                '        if (strictHandles) dwRead = SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION;\n'
                '        ok = DuplicateHandle(GetCurrentProcess(), piInput->hThread,')
        destination=out/'prepared/Sandboxie/core/svc'/name;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(after.encode('utf-8'))
        original=out/'original/Sandboxie/core/svc'/name;original.parent.mkdir(parents=True,exist_ok=True);original.write_bytes(before.encode('utf-8'))
        path='Sandboxie/core/svc/'+name
        patch.extend(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+path,tofile='b/'+path))
        manifest[name]={'upstream_sha256':digest,'prepared_sha256':hashlib.sha256(after.encode()).hexdigest()}
    for name in ('CrBrokerPolicy.h','CrBrokerWindows.h','CrBootstrapSecurity.h','CrBootstrapLaunch.h'):
        source=ROOT/'src/native/sandboxie'/name;data=source.read_text();path='Sandboxie/core/svc/'+name
        shutil.copyfile(source,out/'prepared'/path)
        manifest[name]={'prepared_sha256':hashlib.sha256(source.read_bytes()).hexdigest()}
        patch.extend(difflib.unified_diff([],data.splitlines(True),fromfile='/dev/null',tofile='b/'+path))
    (out/'claudereset-strict-brokers.patch').write_text(''.join(patch),encoding='utf-8',newline='\n')
    result={'upstream_tag':'v1.18.8','files':manifest,'installed':False,'full_service_build_verified':False,
            'working_client_compatibility_verified':False,'production_clients_permitted':False,
            'full_tunnel_verified':False,'enable_only_after_protected_install':'ClaudeResetStrictBroker=y'}
    (out/'manifest.json').write_text(json.dumps(result,indent=2));print('Prepared dependency source patch; installed=false')
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,help='Upstream v1.18.8 checkout; exact source hashes are required')
    parser.add_argument('--output-root',type=Path,help='Prepared files and patch destination; no installation')
    args=parser.parse_args();prepare(args.source_root,args.output_root)
