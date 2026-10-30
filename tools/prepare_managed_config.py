"""Require the product's private configuration; never fall back to host policy."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]


def managed_policy_contract(*,policy=None,boxes=None):
    """The installer's fixed boxes and isolation settings; policy and boxes are the modules that define them
    (backend.broker_policy and backend.boxes unless a test gives stand-ins)."""
    # Use the installer's actual fixed policy, not a second native spelling.
    sys.path.insert(0,str(ROOT/'src'))
    from claude_reset.backend import broker_policy, boxes as install_configuration
    broker_policy,install_configuration=policy or broker_policy,boxes or install_configuration
    for module,name in ((broker_policy,'backend/broker_policy.py'),(install_configuration,'backend/boxes.py')):
        if Path(module.__file__).resolve()!=(ROOT/'src/claude_reset'/name).resolve():
            raise RuntimeError('Managed policy must come from this reviewed source tree')
    BOXES=install_configuration.BOXES
    settings=tuple(sorted(broker_policy.ISOLATION_SETTINGS.items()))
    if (len(BOXES)!=5 or len({name.casefold() for name in BOXES})!=5 or not 1<=len(settings)<=31
            or len({name.casefold() for name,value in settings})!=len(settings)
            or any(not re.fullmatch(r'ClaudeReset\.[A-Za-z]+',name) for name in BOXES)
            or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*',name) or value not in ('y','n') for name,value in settings)):
        raise RuntimeError('Unreviewed managed box policy contract')
    return tuple(BOXES),settings


def managed_forbidden_settings():
    managed_policy_contract()  # Also checks both imported modules belong to this tree.
    from claude_reset.backend.broker_policy import FORBIDDEN_SETTINGS
    values=FORBIDDEN_SETTINGS
    if (type(values) is not tuple or not 1<=len(values)<=64
            or any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*',v) for v in values)
            or len({v.casefold() for v in values})!=len(values)):
        raise RuntimeError('Unreviewed managed exception contract')
    return values


def managed_box_validation():
    boxes,settings=managed_policy_contract()
    def array(values):return ', '.join('L'+json.dumps(value) for value in values)
    return '''    if (seen != 3) return STATUS_INVALID_PARAMETER;
    /* Every fixed managed box must retain the installer's isolation contract.
       Template/default/virtual state cannot supply a missing security setting. */
    static const WCHAR *cr_boxes[] = {''' + array(boxes) + '''};
    static const WCHAR *cr_names[] = {''' + array(k for k,v in settings) + '''};
    static const WCHAR *cr_values[] = {''' + array(v for k,v in settings) + '''};
    ULONG box_index, key_index;
    for (box_index = 0; box_index < sizeof(cr_boxes)/sizeof(cr_boxes[0]); ++box_index) {
        CONF_SECTION *box = Conf_Find_Sections(data, cr_boxes[box_index]);
        ULONG required_seen = 0;
        if (!box || box->from_template || box->is_virtual || box->include_path)
            return STATUS_INVALID_PARAMETER;
        for (setting = List_Head(&box->settings); setting; setting = List_Next(setting)) {
            for (forbidden_index = 0; forbidden_index < sizeof(cr_forbidden)/sizeof(cr_forbidden[0]); ++forbidden_index)
                if (_wcsicmp(setting->name, cr_forbidden[forbidden_index]) == 0)
                    return STATUS_INVALID_PARAMETER;
            for (key_index = 0; key_index < sizeof(cr_names)/sizeof(cr_names[0]); ++key_index) {
                if (_wcsicmp(setting->name, cr_names[key_index]) == 0) {
                    ULONG bit = 1u << key_index;
                    if ((required_seen & bit) || setting->from_template || !setting->value ||
                            _wcsicmp(setting->value, cr_values[key_index]) != 0)
                        return STATUS_INVALID_PARAMETER;
                    required_seen |= bit;
                    break;
                }
            }
        }
        if (required_seen != '''+str((1<<len(settings))-1)+'''u) return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;'''


def one(text,old,new):
    if text.count(old)!=1:raise RuntimeError('Unreviewed managed-config integration point')
    return text.replace(old,new,1)


def function(text,signature):
    start=text.index(signature);end=text.index('{',start)+1;depth=1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    return text[start:end]


def prepare(source,output):
    if output.exists():raise RuntimeError('Preserve previous policy preparation')
    lock=json.loads((ROOT/'third_party/sources/sandboxie-managed-config-lock.json').read_text('utf-8'))
    message_ids=(source/'Sandboxie/core/svc/msgids.h').read_bytes()
    api_flags=(source/'Sandboxie/core/drv/api_flags.h').read_bytes()
    if hashlib.sha256(api_flags).hexdigest()!=lock['api_flags_sha256']:
        raise RuntimeError('Unreviewed managed-policy API flags')
    if hashlib.sha256(message_ids).hexdigest()!=lock['message_ids_sha256']:
        raise RuntimeError('Unreviewed managed-policy message identifiers')
    changes={};patch=[]
    for name,digest in lock['inputs'].items():
        path=source/name;data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=digest:raise RuntimeError('Unreviewed upstream policy source')
        before=data.decode('utf-8-sig').replace('\r\n','\n');after=before
        if name.endswith('/conf.c'):
            after=one(after,'#define KERNEL_MODE','#define KERNEL_MODE\n#include "verify.h"')
            after=one(after,'_FX NTSTATUS Conf_Read(ULONG session_id)\n{',r'''/* Validate the private candidate, never the currently published Conf_Data.
   Required security components cannot be disabled by a reload or defaults. */
_FX NTSTATUS Cr_ValidateManagedPolicy(CONF_DATA *data)
{
    CONF_SECTION *global = Conf_Find_Sections(data, Conf_GlobalSettings);
    if (!global || global->from_template || global->is_virtual || global->include_path)
        return STATUS_INVALID_PARAMETER;
    ULONG seen = 0;
    CONF_SETTING *setting;
    for (setting = List_Head(&global->settings); setting; setting = List_Next(setting)) {
        ULONG bit = 0;
        if (_wcsicmp(setting->name, L"NetworkEnableWFP") == 0) bit = 1;
        else if (_wcsicmp(setting->name, L"EnableObjectFiltering") == 0) bit = 2;
        else if (_wcsicmp(setting->name, L"IncludeBox") == 0)
            return STATUS_INVALID_PARAMETER;
        if (bit) {
            if ((seen & bit) || setting->from_template || !setting->value ||
                    _wcsicmp(setting->value, L"y") != 0)
                return STATUS_INVALID_PARAMETER;
            seen |= bit;
        }
    }
    return seen == 3 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

_FX NTSTATUS Conf_Read(ULONG session_id)
{''')
            forbidden=', '.join('L'+json.dumps(name) for name in managed_forbidden_settings())
            after=one(after,'    ULONG seen = 0;\n    CONF_SETTING *setting;',
                '    ULONG seen = 0;\n    CONF_SETTING *setting;\n'
                '    /* Match the runtime readback contract before publishing any candidate. */\n'
                '    static const WCHAR *cr_forbidden[] = {'+forbidden+'};\n'
                '    ULONG forbidden_index;')
            after=one(after,'    for (setting = List_Head(&global->settings); setting; setting = List_Next(setting)) {\n        ULONG bit = 0;',
                '    for (setting = List_Head(&global->settings); setting; setting = List_Next(setting)) {\n'
                '        for (forbidden_index = 0; forbidden_index < sizeof(cr_forbidden)/sizeof(cr_forbidden[0]); ++forbidden_index)\n'
                '            if (_wcsicmp(setting->name, cr_forbidden[forbidden_index]) == 0)\n'
                '                return STATUS_INVALID_PARAMETER;\n'
                '        ULONG bit = 0;')
            after=one(after,'    return seen == 3 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;',managed_box_validation())
            old=function(after,'_FX NTSTATUS Conf_Import_AllIncludes(CONF_DATA *data, ULONG session_id)')
            after=one(after,old,'''_FX NTSTATUS Conf_Import_AllIncludes(CONF_DATA *data, ULONG session_id)
{
    /* The managed policy is self-contained. Never open IncludeBox paths,
       wildcards, UNC names or caller-device-map paths, even for a signed service. */
    CONF_SECTION *section = Conf_Get_Section(data, Conf_GlobalSettings);
    if (!section)
        return STATUS_OBJECT_NAME_NOT_FOUND;
    map_iter_t iter = map_key_iter(&section->settings_map, Conf_ImportBox);
    return map_next(&section->settings_map, &iter)
        ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
}''')
            after=one(after,'        Conf_Import_AllIncludes(&data, session_id);',
                           '        status = Conf_Import_AllIncludes(&data, session_id);')
            after=one(after,'    //\n    // if read successfully, replace existing configuration\n',
                '    /* Managed invariants must pass before the candidate replaces Conf_Data. */\n'
                '    if (NT_SUCCESS(status))\n        status = Cr_ValidateManagedPolicy(&data);\n\n'
                '    //\n    // if read successfully, replace existing configuration\n')
            old=function(after,'_FX NTSTATUS Conf_Api_Update(PROCESS *proc, ULONG64 *parms)')
            after=one(after,old,'''_FX NTSTATUS Conf_Api_Update(PROCESS *proc, ULONG64 *parms)
{
    /* Managed policy has no mutable virtual sections, including for signed
       session leaders and the service. Use a protected on-disk transaction. */
    return STATUS_ACCESS_DENIED;
}''')
            old=function(after,'_FX NTSTATUS Conf_Api_Reload(PROCESS *proc, ULONG64 *parms)')
            new=one(old,'''    if (proc)
        return STATUS_NOT_IMPLEMENTED;''','''    /* Check identity before reading flags or performing certificate/config
       work. PID equality alone is not authority after service termination. */
    if (proc || !Api_ServiceProcessId ||
        PsGetCurrentProcessId() != Api_ServiceProcessId ||
        !MyIsCallerMyServiceProcess() || !NT_SUCCESS(KphVerifyCurrentProcess()))
        return STATUS_ACCESS_DENIED;''')
            new=one(new,'    flags = (ULONG)parms[2];','''    /* Serialize the complete reload, before Conf_Read can replace policy. */
    static volatile LONG cr_reload_lock = 0;
    if (InterlockedCompareExchange(&cr_reload_lock, 1, 0) != 0)
        return STATUS_OPERATION_IN_PROGRESS;

    flags = (ULONG)parms[2];
    /* Certificate and policy reloads are distinct operations. Reject unknown
       bits and noncanonical 64-bit input instead of silently truncating it. */
    if (parms[2] != (ULONG64)flags ||
        (flags != 0 && flags != SBIE_CONF_FLAG_RECONFIGURE && flags != SBIE_CONF_FLAG_RELOAD_CERT)) {
        status = STATUS_INVALID_PARAMETER;
        goto finish;
    }''')
            start=new.index('        static volatile ULONG reconf_lock = 0;')
            end=new.index('        BOOLEAN wpf_enabled =',start)
            new=new[:start]+new[end:]
            new=one(new,'        InterlockedExchange(&reconf_lock, 0);','')
            new=one(new,'    status = Conf_Read((ULONG)parms[1]);',
                '    /* Every policy reload, including flags=0, requires the existing\n'
                '       protection before parsing/publishing a candidate. Certificate\n'
                '       reload above remains separate from policy mutation. */\n'
                '    extern BOOLEAN WFP_IsReady(void);\n'
                '    if (!WFP_IsReady() || !Obj_CallbackInstalled) {\n'
                '        status = STATUS_DEVICE_NOT_READY;\n        goto finish;\n    }\n\n'
                '    status = Conf_Read((ULONG)parms[1]);')
            new=one(new,'        if (WFP_Enabled != wpf_enabled) {',
                '        /* Recheck actual callback readiness even when configured enabled. */\n'
                '        if (wpf_enabled || WFP_Enabled != wpf_enabled) {')
            new=one(new,'                WFP_Load();','''                if (!WFP_Load()) {
                    status = STATUS_UNSUCCESSFUL;
                    goto finish;
                }''')
            new=one(new,'                Obj_Load_Filter();','''                if (!Obj_Load_Filter()) {
                    status = STATUS_UNSUCCESSFUL;
                    goto finish;
                }''')
            new=one(new,'    //\n    // notify service about setting change\n',
                '    /* Readiness may be lost while parsing or applying the candidate.\n'
                '       Never report success for an unprotected post-reload state,\n'
                '       including a plain flags=0 reload. This is not policy rollback. */\n'
                '    if (!WFP_IsReady() || !Obj_CallbackInstalled) {\n'
                '        status = STATUS_DEVICE_NOT_READY;\n        goto finish;\n    }\n\n'
                '    //\n    // notify service about setting change\n')
            new=one(new,'finish:\n    return status;','finish:\n    InterlockedExchange(&cr_reload_lock, 0);\n    return status;')
            after=one(after,old,new)
            start=after.index('    UNICODE_STRING IniPath = { 0, (USHORT)path_len - (4 * sizeof(WCHAR)), path };')
            end=after.index('    //\n    // read data from the file',start)
            replacement=r'''    /* ClaudeReset: require one private DOS-absolute policy, resolving its
       drive in the global device namespace even during an impersonated call. */
    static const WCHAR cr_prefix[] = L"\\DosDevices\\Global\\";
    const ULONG cr_prefix_chars = (sizeof(cr_prefix) / sizeof(WCHAR)) - 1;
    UNICODE_STRING IniPath = { 0, (USHORT)(path_len - sizeof(cr_prefix)), path };
    status = GetRegString(RTL_REGISTRY_ABSOLUTE, Driver_RegistryPath, L"IniPath", &IniPath);
    if (!NT_SUCCESS(status)) {
        Pool_Delete(pool);
        return status;
    }
    if (IniPath.Length < 4 * sizeof(WCHAR) || (IniPath.Length % sizeof(WCHAR)) != 0 ||
        IniPath.Length + sizeof(WCHAR) > IniPath.MaximumLength ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\') {
        Pool_Delete(pool);
        return STATUS_INVALID_PARAMETER;
    }
    path[IniPath.Length / sizeof(WCHAR)] = 0;
    wmemmove(path + cr_prefix_chars, path, (IniPath.Length / sizeof(WCHAR)) + 1);
    wmemcpy(path, cr_prefix, cr_prefix_chars);
    path_home = 2;
    status = Stream_Open(&stream, path, FILE_GENERIC_READ, 0, FILE_SHARE_READ, FILE_OPEN, 0);
    if (!NT_SUCCESS(status)) {
        Pool_Delete(pool);
        return status;
    }

'''
            after=after[:start]+replacement+after[end:]
            start=after.index('    if (status == STATUS_OBJECT_NAME_NOT_FOUND ||',after.index('_FX NTSTATUS Conf_Api_Reload'))
            end=after.index('    //\n    // Check the reconfigure drier flag',start)
            after=after[:start]+'''    /* Never replace a valid policy with empty/default state on reload failure. */
    if (!NT_SUCCESS(status))
        goto finish;

'''+after[end:]
            after=one(after,'    Conf_Read(-1);','    if (!NT_SUCCESS(Conf_Read(-1)))\n        return FALSE;')
            after=one(after,'static NTSTATUS Conf_Read(ULONG session_id);',
                      'static NTSTATUS Conf_Read(ULONG session_id, BOOLEAN require_ready);')
            after=one(after,'_FX NTSTATUS Conf_Read(ULONG session_id)\n{',
                      '_FX NTSTATUS Conf_Read(ULONG session_id, BOOLEAN require_ready)\n{')
            after=one(after,'Conf_Read((ULONG)parms[1])','Conf_Read((ULONG)parms[1], TRUE)')
            after=one(after,'Conf_Read(-1)','Conf_Read(-1, FALSE)')
            after=one(after,'''                pool = Conf_Data.pool;
                memcpy(&Conf_Data, &data, sizeof(CONF_DATA));

                done = TRUE;''','''                /* Parsing can outlive the initial readiness check. Refuse
                   publication while holding the configuration writer lock.
                   Startup has no installed callbacks yet; only the explicit
                   internal startup call may omit this reload requirement.
                   This does not make WFP lifetime atomic with Conf_Lock. */
                extern BOOLEAN WFP_IsReady(void);
                if (require_ready && (!WFP_IsReady() || !Obj_CallbackInstalled)) {
                    status = STATUS_DEVICE_NOT_READY;
                } else {
                    pool = Conf_Data.pool;
                    memcpy(&Conf_Data, &data, sizeof(CONF_DATA));
                }
                done = TRUE;''')
            after=one(after,
                '        CONF_SECTION* common = Conf_Get_Section(data, Conf_DefaultTemplates);\n        if (common)\n            status = Conf_Merge_Templates(data, session_id, global, common, Conf_DefaultTemplates);',
                '        /* Managed product policy never imports implicit upstream defaults. */\n        if (!NT_SUCCESS(status))\n            return status;')
            after=one(after,
                '        RtlStringCbPrintfW(path, path_len, path_templates, Driver_HomePathDos);',
                r'''        /* Template lookup must not follow the caller's DOS drive mapping. */
        if (wcsncmp(Driver_HomePathDos, L"\\??\\", 4) != 0 ||
            wcslen(Driver_HomePathDos) < 7 ||
            !((Driver_HomePathDos[4] >= L'A' && Driver_HomePathDos[4] <= L'Z') ||
              (Driver_HomePathDos[4] >= L'a' && Driver_HomePathDos[4] <= L'z')) ||
            Driver_HomePathDos[5] != L':' || Driver_HomePathDos[6] != L'\\') {
            Mem_Free(path, path_len);
            Pool_Delete(pool);
            return STATUS_INVALID_PARAMETER;
        }
        RtlStringCbPrintfW(path, path_len, L"\\DosDevices\\Global\\%s\\Templates.ini", Driver_HomePathDos + 4);''')
            after=one(after,
                '    if (path_len < wcslen(Driver_HomePathDos) * sizeof(WCHAR) + 64)\n        path_len = wcslen(Driver_HomePathDos) * sizeof(WCHAR) + 64;',
                '    if (path_len < (wcslen(Driver_HomePathDos) + 64) * sizeof(WCHAR))\n        path_len = (wcslen(Driver_HomePathDos) + 64) * sizeof(WCHAR);')
        elif name.endswith('/session.c'):
            old=function(after,'_FX NTSTATUS Session_Api_DisableForce(PROCESS *proc, ULONG64 *parms)')
            new=one(old,'    //\n    // get status',
                '''    /* Managed policy has no runtime force-disable exceptions. */
    if (args->set_flag.val)
        return STATUS_ACCESS_DENIED;

    //
    // get status''')
            after=one(after,old,new)
            old=function(after,'_FX NTSTATUS Session_Api_ForceChildren(PROCESS *proc, ULONG64 *parms)')
            after=one(after,old,'''_FX NTSTATUS Session_Api_ForceChildren(PROCESS *proc, ULONG64 *parms)
{
    /* Managed child membership is inherited through the reviewed launch path.
       Legacy arbitrary-process force assignment is not a mutation interface. */
    if (proc)
        return STATUS_NOT_IMPLEMENTED;
    return STATUS_ACCESS_DENIED;
}''')
        elif name.endswith('/api.c'):
            old=function(after,'_FX NTSTATUS Api_SetSecureParam(PROCESS* proc, ULONG64* parms)')
            new=one(old,'    if (!MyIsCallerSigned()) {',
                '''    /* Secure parameter writes belong to the exact SYSTEM service image.
       Initial certificate blocklist seeding precedes service-port registration. */
    if (!MyIsCallerMyServiceProcess() || !MyIsCallerSigned()) {''')
            after=one(after,old,new)
            old=function(after,'_FX NTSTATUS Api_ProcessExemptionControl(PROCESS *proc, ULONG64 *parms)')
            new=one(old,'\tif (pArgs->process_id.val == 0)',
                '''    /* Managed process exemptions cannot override the reviewed policy.
       Reject every setter before probing user buffers or finding a process;
       signed callers retain the existing read-only query contract. */
    if (pArgs->set_flag.val)
        return STATUS_ACCESS_DENIED;

\tif (pArgs->process_id.val == 0)''')
            after=one(after,old,new)
            old=function(after,'_FX void Api_ResetServiceProcess(void)')
            after=one(after,old,'''_FX void Api_ResetServiceProcess(HANDLE ProcessId)
{
    /* A delayed exit notification must not revoke a newer registration.
       Match identity and detach both fields under the registration lock. */
    void *Old = NULL;
    KIRQL irql = Api_EnterCriticalSection();
    if (ProcessId && Api_ServiceProcessId == ProcessId) {
        Old = InterlockedExchangePointer(&Api_ServicePortObject, NULL);
        InterlockedExchangePointer(&Api_ServiceProcessId, NULL);
    }
    Api_LeaveCriticalSection(irql);
    /* The detached reference is ours; destruction must not run under Api_Lock. */
    if (Old)
        ObDereferenceObject(Old);
}''')
            old=function(after,'_FX NTSTATUS Api_SetServicePort(PROCESS *proc, ULONG64 *parms)')
            new=one(old,'if (NT_SUCCESS(status) && !MyIsCallerSigned())',
                'if (NT_SUCCESS(status) && !NT_SUCCESS(KphVerifyCurrentProcess()))')
            new=one(new,'PortHandle, 0, *LpcPortObjectType, KernelMode,',
                'PortHandle, 0, *LpcPortObjectType, UserMode,')
            after=one(after,old,new)
        elif name.endswith('/api.h'):
            after=one(after,'void Api_ResetServiceProcess(void);',
                            'void Api_ResetServiceProcess(HANDLE ProcessId);')
        elif name.endswith('/util.c'):
            signed=function(after,'_FX BOOLEAN MyIsCallerSigned(void)')
            after=one(after,signed,'_FX BOOLEAN MyIsCallerSigned(void)\n{\n    /* Development certificates and OS test mode are not image authority. */\n    return NT_SUCCESS(KphVerifyCurrentProcess());\n}')
            old=function(after,'_FX BOOLEAN MyIsCallerMyServiceProcess(void)')
            start=old.index('            if ((uni->Length > Driver_HomePathNt_Len')
            end=old.index('\n            Mem_Free(nbuf, nlen);',start)
            replacement=r'''            /* Match the complete counted canonical image path. A prefix sibling
               or nested directory with the same basename is not this service. */
            if (Driver_HomePathNt && Driver_HomePathNt_Len && uni->Buffer &&
                    uni->Length == ((SIZE_T)Driver_HomePathNt_Len + 1 + wcslen(SBIESVC_EXE)) * sizeof(WCHAR) &&
                    _wcsnicmp(uni->Buffer, Driver_HomePathNt, Driver_HomePathNt_Len) == 0 &&
                    uni->Buffer[Driver_HomePathNt_Len] == L'\\' &&
                    _wcsnicmp(uni->Buffer + Driver_HomePathNt_Len + 1, SBIESVC_EXE, wcslen(SBIESVC_EXE)) == 0) {
                ok = TRUE;
            }
'''
            after=one(after,old,old[:start]+replacement+old[end:])
        elif name.endswith('/driver.c'):
            after=one(after,'#include "api.h"',
                '#include "api.h"\n#define KERNEL_MODE\n#include "verify.h"\n#undef KERNEL_MODE')
            after=one(after,'_FX NTSTATUS Driver_Api_Unload(PROCESS *proc, ULONG64 *parms)\n{',
                '''_FX NTSTATUS Driver_Api_Unload(PROCESS *proc, ULONG64 *parms)
{
    /* Managed lifecycle changes belong only to the registered verified service.
       Reject before admission flags, process locks or API reference mutation. */
    if (proc || !Api_ServiceProcessId ||
        PsGetCurrentProcessId() != Api_ServiceProcessId ||
        !MyIsCallerMyServiceProcess() || !NT_SUCCESS(KphVerifyCurrentProcess()))
        return STATUS_ACCESS_DENIED;''')
        elif name.endswith('/start.cpp'):
            after=one(after,'            force_children_on_this_program = TRUE;',
                '''            /* Refuse legacy force assignment before creating any process. */
            ExitProcess(3);
            return FALSE;''')
            after=one(after,'        SbieApi_DisableForceProcess(&NewState, NULL);\n        ExitProcess(0);',
                '        LONG status = SbieApi_DisableForceProcess(&NewState, NULL);\n        ExitProcess(status == 0 ? 0 : 3);')
            after=one(after,'                SbieApi_DisableForceProcess(&NewState, NULL);',
                '''                /* Force-disable refusal must stop before Program_Start. */
                if (SbieApi_DisableForceProcess(&NewState, NULL) != 0)
                    return die(3);''')
            after=one(after,'            SbieApi_ReloadConf(-1, 0);\n            ExitProcess(0);',
                '            LONG status = SbieApi_ReloadConf(-1, 0);\n            ExitProcess(status == 0 ? 0 : 3);')
        elif name.endswith('/update.c'):
            after=one(after,'    return 0;\n}', '''    /* Preserve failures from both driver and service policy mutation APIs.
       Exit 3 is an operation failure; 1/2 remain command/password errors. */
    return status == 0 ? 0 : 3;
}''')
        else:
            after=one(after,'MSG_HEADER *SbieIniServer::Handler2(MSG_HEADER *msg)\n{',
                '''MSG_HEADER *SbieIniServer::Handler2(MSG_HEADER *msg)
{
    /* ClaudeReset managed policy is not writable through the legacy INI RPC.
       Updates belong to the protected backend transaction. This applies to
       every caller, independently of mutable EditAdminOnly/password settings.
       TEST_PASSWORD also refreshes/writes the cached configuration upstream. */
    switch (msg->msgid) {
        case MSGID_SBIE_INI_TEMPLATE:
        case MSGID_SBIE_INI_SET_PASSWORD:
        case MSGID_SBIE_INI_TEST_PASSWORD:
        case MSGID_SBIE_INI_SET_SETTING:
        case MSGID_SBIE_INI_ADD_SETTING:
        case MSGID_SBIE_INI_INS_SETTING:
        case MSGID_SBIE_INI_DEL_SETTING:
        case MSGID_SBIE_INI_SET_DAT:
            return SHORT_REPLY(STATUS_ACCESS_DENIED);
    }
''')
            old=function(after,'bool SbieIniServer::GetIniPath(WCHAR **IniPath, BOOLEAN *IsHomePath)')
            new=r'''bool SbieIniServer::GetIniPath(WCHAR **IniPath, BOOLEAN *IsHomePath)
{
    static const WCHAR nt_prefix[] = L"\\DosDevices\\Global\\";
    static const WCHAR win32_prefix[] = L"\\\\?\\GLOBALROOT";
    const size_t prefix_chars = (sizeof(nt_prefix) / sizeof(WCHAR)) - 1;
    WCHAR native_path[260] = { 0 };
    if (!IniPath)
        return false;
    *IniPath = NULL;
    if (IsHomePath)
        *IsHomePath = FALSE;
    LONG rc = SbieApi_QueryConfAsIs(NULL, L"IniLocation", 0, native_path, sizeof(native_path));
    size_t length = wcsnlen(native_path, 260);
    if (rc != 0 || length == 260 || length < prefix_chars + 4 ||
        wcsncmp(native_path, nt_prefix, prefix_chars) != 0 ||
        !((native_path[prefix_chars] >= L'A' && native_path[prefix_chars] <= L'Z') ||
          (native_path[prefix_chars] >= L'a' && native_path[prefix_chars] <= L'z')) ||
        native_path[prefix_chars + 1] != L':' || native_path[prefix_chars + 2] != L'\\')
        return false;
    size_t chars = length + (sizeof(win32_prefix) / sizeof(WCHAR));
    WCHAR *path = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, chars * sizeof(WCHAR));
    if (!path)
        return false;
    wcscpy(path, win32_prefix);
    wcscat(path, native_path);
    *IniPath = path;
    return true;
}'''
            after=one(after,old,new)
        for label,text in [('original',before),('prepared',after)]:
            target=output/label/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_text(text,encoding='utf-8',newline='\n')
        patch.extend(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+name,tofile='b/'+name))
        changes[name]={'upstream_sha256':digest,'original_normalized_sha256':hashlib.sha256(before.encode()).hexdigest(),
                       'prepared_sha256':hashlib.sha256(after.encode()).hexdigest()}
    (output/'managed-config.patch').write_text(''.join(patch),encoding='utf-8',newline='\n')
    (output/'ManagedMessageIds.h').write_bytes(message_ids)
    (output/'ManagedApiFlags.h').write_bytes(api_flags)
    (output/'manifest.json').write_text(json.dumps({'schema':1,'files':changes,
        'message_ids_sha256':lock['message_ids_sha256'],'api_flags_sha256':lock['api_flags_sha256'],
        'installed':False,'kernel_build_verified':False},indent=2),encoding='utf-8')
    print(json.dumps({'prepared_files':len(changes),'installed':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True);parser.add_argument('--output-root',type=Path,required=True)
    args=parser.parse_args();prepare(args.source_root.resolve(),args.output_root.resolve())
