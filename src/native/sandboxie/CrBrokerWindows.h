// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef CLAUDERESET_BROKER_WINDOWS_H
#define CLAUDERESET_BROKER_WINDOWS_H
#include "CrBrokerPolicy.h"
#include "msgids.h"
#include "GuiWire.h"
static_assert(MSGID_PROCESS_RUN_SANDBOXED==0x1205 && MSGID_QUEUE_PUTREQ==0x1e04 &&
              MSGID_QUEUE_GETRPL==0x1e05 && GUI_GET_WINDOW_STATION==2,
              "Unreviewed Sandboxie wire protocol");
// Use the authenticated transport/queue sender, never a PID from payload.
// Every boxed caller is restricted in this private runtime. An unknown driver,
// query failure, dead process, or inaccessible process is restricted too.
static bool CrIsStrictSandbox(ULONG authenticatedPid) {
    HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                 FALSE, authenticatedPid);
    if (!process) return true;
    bool restricted = true;
    if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
        const ULONG64 classification = SbieApi_QueryProcessInfo(
            (HANDLE)(ULONG_PTR)authenticatedPid, 0x63726270);
        restricted = classification != 0x43524201 ||
                     WaitForSingleObject(process, 0) != WAIT_TIMEOUT;
    }
    CloseHandle(process);
    return restricted;
}
#endif
