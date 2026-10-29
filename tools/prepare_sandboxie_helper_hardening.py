"""Prepare the separate, uninstalled helper driver patch for pinned v1.18.8."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
HASHES = json.loads((ROOT/'third_party/sources/sandboxie-lock.json').read_text('utf-8'))['driver_inputs']


def one(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unreviewed driver integration point: ' + old[:100])
    return text.replace(old, new, 1)


def prepare(source_root=None, output_root=None):
    output = Path(output_root) if output_root else ROOT / 'work/sandboxie-helper-hardening'
    reviewed = {}
    for name, digest in HASHES.items():
        if source_root:
            path = Path(source_root) / 'Sandboxie/core/drv' / name
        elif name == 'process_api.c':
            path = ROOT / 'work/dependencies/sandboxie-v1.18.8/source/Sandboxie/core/drv/process_api.c'
        elif name == 'process.h':
            path = ROOT / 'work/sandboxie-headers/Sandboxie/core/drv' / name
        elif name == 'token.c':
            path = ROOT / 'work/sandbox-driver/token.c'
        else:
            path = ROOT / 'work/sandbox-driver' / ('source-driver-' + name)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Unreviewed upstream driver source: ' + name)
        reviewed[name] = data.decode('utf-8-sig').replace('\r\n', '\n')
    manifest = {}; patch = []
    for name, before in reviewed.items():
        after = before
        if name == 'process.h':
            after = one(after, '    BOOLEAN image_sbie;',
                '    BOOLEAN image_sbie;\n'
                '    BOOLEAN cr_strict_broker; // immutable/inherited until exit\n'
                '    UCHAR cr_helper_role;     // assigned under process-map lock before execution')
        elif name == 'process_api.c':
            after = one(after, '#include "common/my_version.h"',
                '#include "common/my_version.h"\n#include "CrBrokerQuery.h"')
            marker = '    ProcessId = args->process_id.val;'
            start = after.index('_FX NTSTATUS Process_Api_QueryInfo(')
            prefix, body = after[:start], after[start:]
            location = body.index(marker)
            body = body[:location] + (
                '    /* Explicit broker classification; old drivers return an error, never an allow. */\n'
                '    if (args->info_type.val == 0x63726270)\n'
                '        return CrBrokerQuery(proc, args->process_id.val, args->info_data.val);\n\n') + body[location:]
            after = prefix + body
        elif name == 'process.c':
            after = one(after, '    if (ProcessId == Api_ServiceProcessId)\n        Api_ResetServiceProcess();',
                '    /* The managed API checks the exiting identity under its registration lock. */\n'
                '    Api_ResetServiceProcess(ProcessId);')
            after = one(after, '#include <fltKernel.h>',
                '#include <fltKernel.h>\n#include "obj.h"\n#include "CrHelperDriver.h"')
            after = one(after, '    proc->bAppCompartment = Conf_Get_Boolean',
                '    proc->cr_strict_broker = Conf_Get_Boolean(proc->box->name, L"ClaudeResetStrictBroker", 0, FALSE);\n\n'
                '    proc->bAppCompartment = Conf_Get_Boolean')
            after = one(after, '    BOOLEAN parent_was_start_exe = FALSE;',
                '    BOOLEAN cr_inherited_strict = CrHelperCallerStrict(CallerId);\n    BOOLEAN parent_was_start_exe = FALSE;')
            # Do not let a designated SbieSvc parent bypass actual-caller lookup.
            after = one(after, '    if (ParentId == Api_ServiceProcessId) {',
                '    if (ParentId == Api_ServiceProcessId && (!cr_inherited_strict || CallerId == Api_ServiceProcessId)) {')
            after = one(after, '                    if (parent_proc->is_start_exe)',
                '                    cr_inherited_strict = cr_inherited_strict || parent_proc->cr_strict_broker;\n\n'
                '                    if (parent_proc->is_start_exe)')
            after = one(after, '        if (box && Process_IsBreakoutProcess(box, ImagePath)) {',
                '        if (box && !cr_inherited_strict && Process_IsBreakoutProcess(box, ImagePath)) {')
            marker = '        else if (!new_proc->image_from_box && new_proc->protect_host_images && parent_was_image_from_box) {'
            after = one(after, marker,
                '        else if (!CrHelperAdmitProcess(new_proc, CallerId, ParentId, cr_inherited_strict, bHostInject)) {\n'
                '            create_terminated = TRUE;\n'
                '            Process_SetTerminated(new_proc, 14);\n'
                '            new_proc = NULL;\n'
                '            ExReleaseResourceLite(Process_ListLock);\n'
                '            KeLowerIrql(irql);\n        }\n' + marker)
        elif name == 'token.c':
            after = one(after, '#include "dyn_data.h"', '#include "dyn_data.h"\n#include "CrHelperTokenDriver.h"')
            after = one(after, '    if (NT_SUCCESS(status))\n        status = Token_SetHandleDacl(NtCurrentProcess(), x_dacl_ptr);',
                '    if (NT_SUCCESS(status) && !CrHelperPreserveObjectDacl())\n        status = Token_SetHandleDacl(NtCurrentProcess(), x_dacl_ptr);')
            after = one(after, '    if (NT_SUCCESS(status))\n        status = Token_SetHandleDacl(NtCurrentThread(), x_dacl_ptr);',
                '    if (NT_SUCCESS(status) && !CrHelperPreserveObjectDacl())\n        status = Token_SetHandleDacl(NtCurrentThread(), x_dacl_ptr);')
            after = one(after, '                if (Token_AssignPrimary(ProcessObject, RestrictedToken,',
                '                if (CrHelperProtectPrimaryToken(proc, OriginalToken, RestrictedToken) &&\n'
                '                    Token_AssignPrimary(ProcessObject, RestrictedToken,')
        elif name == 'thread_token.c':
            after = one(after, '#include "conf.h"', '#include "conf.h"\n#include "CrHelperDriver.h"')
            marker = '    //\n    // open the token for the process\n    //\n'
            after = one(after, marker,
                '    if (!CrHelperTokenAccessAllowed(PsGetProcessId(ProcessObject), proc->pid, DesiredAccess)) {\n'
                '        ObDereferenceObject(ProcessObject);\n'
                '        return STATUS_ACCESS_DENIED;\n    }\n\n' + marker)
            marker = '    //\n    // open the token for the thread\n    //\n\n    ProcessObject = PsGetThreadProcess(ThreadObject);'
            after = one(after, marker,
                marker + '\n'
                '    if (!CrHelperTokenAccessAllowed(PsGetProcessId(ProcessObject), proc->pid, DesiredAccess)) {\n'
                '        ObDereferenceObject(ThreadObject);\n'
                '        return STATUS_ACCESS_DENIED;\n    }')
        else:
            marker = '//---------------------------------------------------------------------------\n// Functions'
            after = one(after, marker, '#include "process.h"\n#include "api.h"\n#include "CrHelperDriver.h"\n\n' + marker)
            after = one(after, '    PACCESS_MASK DesiredAccess = NULL;',
                '    HANDLE crRequesterId = PsGetCurrentProcessId();\n'
                '    HANDLE crRecipientId = crRequesterId;\n'
                '    PACCESS_MASK DesiredAccess = NULL;')
            marker = '    //\n    // Based on the object type apply the appropriate filter\n    //\n'
            after = one(after, marker,
                '    if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)\n'
                '        crRecipientId = PsGetProcessId((PEPROCESS)PreInfo->Parameters->DuplicateHandleInformation.TargetProcess);\n\n' + marker)
            for entire in ('TRUE', 'FALSE'):
                marker = f'        *DesiredAccess = Thread_CheckObject_CommonEx(TargetProcessId, ProcessObject, InitialDesiredAccess, {entire}, TRUE);'
                after = one(after, marker,
                    f'        InitialDesiredAccess = CrHelperHandleAccess(TargetProcessId, crRequesterId, InitialDesiredAccess, {entire});\n'
                    f'        InitialDesiredAccess = CrHelperHandleAccess(TargetProcessId, crRecipientId, InitialDesiredAccess, {entire});\n' + marker)
        relative = 'Sandboxie/core/drv/' + name
        for label, text in [('original', before), ('prepared', after)]:
            path = output / label / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
        patch.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
            fromfile='a/' + relative, tofile='b/' + relative))
        manifest[name] = {'upstream_sha256': HASHES[name], 'prepared_sha256': hashlib.sha256(after.encode()).hexdigest()}
    for name in ('CrHelperPolicy.h', 'CrHelperDriver.h', 'CrHelperTokenAcl.h', 'CrHelperTokenDriver.h', 'CrBrokerQuery.h'):
        data = (ROOT / 'src/native/sandboxie' / name).read_bytes()
        relative = 'Sandboxie/core/drv/' + name
        (output / 'prepared' / relative).write_bytes(data)
        patch.extend(difflib.unified_diff([], data.decode().splitlines(True), fromfile='/dev/null', tofile='b/' + relative))
        manifest[name] = {'prepared_sha256': hashlib.sha256(data).hexdigest()}
    (output / 'claudereset-helper-driver.patch').write_text(''.join(patch), encoding='utf-8', newline='\n')
    result = {'upstream_tag': 'v1.18.8', 'files': manifest, 'kernel_build_verified': False,
              'installed': False, 'production_clients_permitted': False, 'full_tunnel_verified': False}
    (output / 'manifest.json').write_text(json.dumps(result, indent=2))
    print('Prepared helper driver patch; installed=false')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--output-root', type=Path)
    args = parser.parse_args()
    prepare(args.source_root, args.output_root)
