"""Propagate driver WFP initialization failures; preserve prior prepared trees."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
from prepare_managed_config import one,function

ROOT=Path(__file__).resolve().parents[1]
NAME='Sandboxie/core/drv/wfp.c'


def prepare(source,output):
    if output.exists():raise RuntimeError('Preserve previous WFP lifecycle preparation')
    lock=json.loads((ROOT/'third_party/sources/sandboxie-wfp-lifecycle-lock.json').read_text())
    data=(source/NAME).read_bytes()
    if hashlib.sha256(data).hexdigest()!=lock['wfp_sha256']:raise RuntimeError('Unreviewed WFP source')
    before=data.decode('utf-8-sig').replace('\r\n','\n')
    old=function(before,'_FX BOOLEAN WFP_Load(void)')
    new=one(old,'\tif (WFP_Enabled)\n\t\treturn TRUE;',
        '\tif (WFP_Enabled)\n\t\treturn WFP_IsReady();')
    new=one(new,'\tif (!Mem_GetLockResource(&WFP_InitLock, TRUE))\n\t\treturn FALSE;',
        '\tif (!Mem_GetLockResource(&WFP_InitLock, TRUE)) {\n\t\tWFP_Enabled = FALSE;\n\t\treturn FALSE;\n\t}')
    new=one(new,'\t\tWFP_InitLock = NULL;\n\t\treturn FALSE;',
        '\t\tWFP_InitLock = NULL;\n\t\tWFP_Enabled = FALSE;\n\t\treturn FALSE;')
    new=one(new,'\tif (FwpmBfeStateGet() == FWPM_SERVICE_RUNNING) {',
        '\tBOOLEAN ready = FALSE;\n\tif (FwpmBfeStateGet() == FWPM_SERVICE_RUNNING) {')
    new=one(new,'\t\tWFP_Install_Callbacks();','\t\tready = WFP_Install_Callbacks();')
    new=one(new,'\treturn TRUE;\n}',
        '\t/* Release the callback lock before unsubscribe/cleanup. A configured\n'
        '\t   enabled bit alone never establishes installed packet callbacks. */\n'
        '\tif (!ready || !WFP_IsReady()) {\n\t\tWFP_Unload();\n\t\treturn FALSE;\n\t}\n\treturn TRUE;\n}')
    ready='''_FX BOOLEAN WFP_IsReady(void)
{
    return WFP_Enabled && InterlockedCompareExchange(&WFP_CallbacksReady, 0, 0) != 0 &&
        FwpmBfeStateGet() == FWPM_SERVICE_RUNNING;
}

'''
    after=one(before,'BOOLEAN WFP_Enabled = FALSE;',
        'BOOLEAN WFP_Enabled = FALSE;\nstatic volatile LONG WFP_CallbacksReady = 0;')
    after=one(after,old,ready+new)
    # All callback install/uninstall paths share this one resource. Shared
    # acquisitions allowed concurrent changes to the same engine/callout IDs.
    if after.count('ExAcquireResourceSharedLite(WFP_InitLock, TRUE)')!=3:
        raise RuntimeError('Unreviewed callback synchronization sites')
    after=after.replace('ExAcquireResourceSharedLite(WFP_InitLock, TRUE)',
                        'ExAcquireResourceExclusiveLite(WFP_InitLock, TRUE)')
    install=function(after,'_FX BOOLEAN WFP_Install_Callbacks(void)')
    replacement=one(install,'\t\treturn TRUE; // already initialized',
        '\t\treturn InterlockedCompareExchange(&WFP_CallbacksReady, 0, 0) != 0;')
    replacement=one(replacement,'\tNTSTATUS status = STATUS_SUCCESS;',
        '\tInterlockedExchange(&WFP_CallbacksReady, 0);\n\tNTSTATUS status = STATUS_SUCCESS;')
    replacement=one(replacement,'\tDbgPrint("Sbie WFP initialized successfully\\r\\n");',
        '\tInterlockedExchange(&WFP_CallbacksReady, 1);\n\tDbgPrint("Sbie WFP initialized successfully\\r\\n");')
    after=one(after,install,replacement)
    uninstall=function(after,'_FX void WFP_Uninstall_Callbacks(void)')
    after=one(after,uninstall,one(uninstall,'_FX void WFP_Uninstall_Callbacks(void)\n{\n',
        '_FX void WFP_Uninstall_Callbacks(void)\n{\n\tInterlockedExchange(&WFP_CallbacksReady, 0);\n'))
    # Track successful kernel registrations independently of the numeric ID
    # (zero is not used as an undocumented ownership sentinel).
    slots=('send_callout_id_v4','send_callout_id_v6','recv_callout_id_v4','recv_callout_id_v6')
    for slot in slots:
        after=one(after,'static UINT32 WFP_'+slot+' = 0;',
            'static UINT32 WFP_'+slot+' = 0;\nstatic BOOLEAN WFP_'+slot+'_owned = FALSE;')
        needle='&WFP_'+slot+', &WFP_'+slot.replace('callout','filter')+')'
        after=one(after,needle,needle[:-1]+', &WFP_'+slot+'_owned)')
    signature='NTSTATUS WFP_RegisterCallout(const GUID* calloutKey, const GUID* applicableLayer, UINT32* callout_id, UINT64* filter_id)'
    if after.count(signature)!=2:raise RuntimeError('Unreviewed callout registration declaration')
    after=after.replace(signature,signature[:-1]+', BOOLEAN* owned)')
    register=function(after,signature[:-1]+', BOOLEAN* owned)\n{')
    updated=one(register,'\tNTSTATUS status = STATUS_SUCCESS;',
        '\tNTSTATUS status = STATUS_SUCCESS;\n\tif (*owned) return STATUS_DEVICE_BUSY;')
    updated=one(updated,'\t// Setup a FWPM_CALLOUT structure',
        '\t/* Ownership begins at kernel registration, before management/filter adds. */\n'
        '\t*owned = TRUE;\n\n\t// Setup a FWPM_CALLOUT structure')
    after=one(after,register,updated)
    helper='''_FX BOOLEAN WFP_RemoveCallouts(void)
{
    UINT32 *ids[] = { &WFP_send_callout_id_v4, &WFP_send_callout_id_v6,
                     &WFP_recv_callout_id_v4, &WFP_recv_callout_id_v6 };
    BOOLEAN *owned[] = { &WFP_send_callout_id_v4_owned, &WFP_send_callout_id_v6_owned,
                        &WFP_recv_callout_id_v4_owned, &WFP_recv_callout_id_v6_owned };
    BOOLEAN complete = TRUE;
    ULONG index;
    for (index = 0; index < 4; ++index) {
        if (*owned[index]) {
            NTSTATUS status = FwpsCalloutUnregisterById(*ids[index]);
            if (NT_SUCCESS(status) || status == STATUS_FWP_CALLOUT_NOT_FOUND) {
                *owned[index] = FALSE;
                *ids[index] = 0;
            } else {
                complete = FALSE;
                DbgPrint("Sbie WFP callout cleanup pending: 0x%08x\\r\\n", status);
            }
        }
    }
    return complete;
}

'''
    install=function(after,'_FX BOOLEAN WFP_Install_Callbacks(void)')
    updated=one(install,'\tBOOLEAN callout_registered = FALSE;','')
    updated=one(updated,'\tcallout_registered = TRUE;','')
    updated=one(updated,'\tInterlockedExchange(&WFP_CallbacksReady, 0);',
        '\tInterlockedExchange(&WFP_CallbacksReady, 0);\n'
        '\tif (WFP_send_callout_id_v4_owned || WFP_send_callout_id_v6_owned ||\n'
        '\t    WFP_recv_callout_id_v4_owned || WFP_recv_callout_id_v6_owned)\n'
        '\t\treturn FALSE; // Preserve pending kernel cleanup; never overwrite owned IDs.\n')
    start=updated.index('\t\tif (callout_registered) {')
    end=updated.index('\n\t\tif (WFP_engine_handle)',start)
    updated=updated[:start]+'\t\tWFP_RemoveCallouts();\n'+updated[end:]
    after=one(after,install,helper+updated)
    uninstall=function(after,'_FX void WFP_Uninstall_Callbacks(void)')
    after=one(after,uninstall,'''_FX void WFP_Uninstall_Callbacks(void)
{
    InterlockedExchange(&WFP_CallbacksReady, 0);
    /* Kernel ownership can survive a failed first management add, even with
       no engine session. Preserve failed IDs for an explicit cleanup retry. */
    WFP_RemoveCallouts();
    if (WFP_engine_handle) {
        FwpmEngineClose(WFP_engine_handle);
        WFP_engine_handle = NULL;
    }
}
''')
    for label,text in [('original',before),('prepared',after)]:
        path=output/label/NAME;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(text.encode())
    patch=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),'a/'+NAME,'b/'+NAME))
    (output/'wfp-lifecycle.patch').write_bytes(patch.encode())
    manifest=dict(schema=1,upstream_commit=lock['upstream_commit'],file=NAME,
        original_sha256=hashlib.sha256(before.encode()).hexdigest(),prepared_sha256=hashlib.sha256(after.encode()).hexdigest(),
        installed=False,live_bfe_restart_accepted=False)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--output-root',type=Path,required=True)
    args=parser.parse_args();prepare(args.source_root.resolve(),args.output_root.resolve())
