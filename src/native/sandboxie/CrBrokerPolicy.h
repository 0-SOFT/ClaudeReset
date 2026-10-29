// SPDX-License-Identifier: GPL-3.0-or-later
// Prepared service-side policy for Sandboxie v1.18.8. Not installed by this file.
#ifndef CLAUDERESET_BROKER_POLICY_H
#define CLAUDERESET_BROKER_POLICY_H

// Restrictive bootstrap subset. Original handler authorization remains mandatory.
// Unknown operations, COM, NetAPI, ICMP, named-pipe/ALPC forwarding, service control,
// settings writes and endpoint resolution are denied before their handlers run.
static inline bool CrPipeAllowed(unsigned int id) {
    switch(id) {
    case 0x1201: // PROCESS_CHECK_INIT_COMPLETE
    case 0x1205: // PROCESS_RUN_SANDBOXED; existing same-box checks still apply
    case 0x1206: // PROCESS_SET_DEVICE_MAP
    case 0x1207: // PROCESS_OPEN_DEVICE_MAP
    case 0x1209: // PROCESS_GET_INFO
    case 0x1e01: // QUEUE_CREATE; restricted to box-local RPCSS_SXS
    case 0x1e02: // QUEUE_GETREQ; original queue owner check remains mandatory
    case 0x1e03: // QUEUE_PUTRPL; original queue owner check remains mandatory
    case 0x1e04: // QUEUE_PUTREQ; additional queue-name check below
    case 0x1e05: // QUEUE_GETRPL; additional queue-name check below
        return true;
    default:return false;
    }
}

// Own-window operations use normal in-box Win32 paths. Host GUI delegation is
// denied, including DDE's early compatibility branch and delayed clipboard data.
// Internal GUI_INIT_PROCESS is sent by the unboxed trusted service, not a client.
static inline bool CrGuiAllowed(unsigned int id) {
    return id==2; // GUI_GET_WINDOW_STATION; handler binds result to caller PID
}

static inline bool CrGuiQueueAllowed(const wchar_t* name,unsigned int capacity,unsigned int session) {
    const wchar_t prefix[]=L"*GUIPROXY_";
    const wchar_t digits[]=L"0123456789ABCDEF";
    if(!name || capacity<19)return false;
    for(unsigned int i=0;i<10;++i)if(name[i]!=prefix[i])return false;
    for(unsigned int i=0;i<8;++i)
        if(name[10+i]!=digits[(session>>(28-4*i))&15])return false;
    return name[18]==0;
}

// Non-asterisk names are prefixed with the authenticated caller's box IPC path
// by QueueServer::MakeQueueName. Do not grant helper privileges by image name.
static inline bool CrQueueAllowed(unsigned int id,const wchar_t* name,
                                  unsigned int capacity,unsigned int session) {
    if(id<0x1e01 || id>0x1e05 || !name)return false;
    const wchar_t local[]=L"RPCSS_SXS";
    bool matches=capacity>=10;
    if(matches)for(unsigned int i=0;i<10;++i)if(name[i]!=local[i]){matches=false;break;}
    if(matches)return true;
    return (id==0x1e04 || id==0x1e05) && CrGuiQueueAllowed(name,capacity,session);
}

// The service may launch only its fixed RpcSs bootstrap, inside the caller's box.
// Ordinary children use the inherited driver boundary. Do not let the unboxed
// service resolve a caller-supplied executable/working directory (UNC, mapped
// drives, search paths) before the new process has entered the box.
static inline bool CrSpawnAllowed(long long model,unsigned int caller,
                                 const wchar_t* command,unsigned int flags) {
    if(!caller || caller>0x7fffffff || model!=-(long long)caller || !command || !command[0])return false;
    // No priority changes, debugging, breakaway, FakeAdmin or requested suspension.
    if(flags & ~(0x08000000u|0x00000400u))return false; // NO_WINDOW / UNICODE_ENVIRONMENT only
    const wchar_t bootstrap[]=L"*RPCSS*";
    for(unsigned int i=0;i<8;++i)if(command[i]!=bootstrap[i])return false;
    return true;
}
#endif
