"""Protected directory bootstrap primitives; no elevation, service or network changes.

Only a future authenticated installer may call create_store. A partial bootstrap
is deliberately not adopted on retry: it requires ownership-aware recovery.
"""
import ctypes as C
from ctypes import wintypes as W
import hashlib
from pathlib import Path
import re
import struct
from .safeio import SafetyError, guarded, local_volume
from .gateway_profile import local_path
from .service_store import program_files, verify_paths, validate_acl
from .install_inventory import services, fresh_install_blockers
from .install_journal import _LocalFile
from .install_transaction import Transaction
from .windows import ps_json
from .netguard import psq

PRIVATE = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
ROOT_ACL = PRIVATE+'(A;;0x1200a9;;;BU)'
RUNTIME_READ = PRIVATE+'(A;OICI;0x1200a9;;;BU)'
FOLDERS = ('Installer','Backend','Engine','Gateway','Runtime','RuntimeTemp',
           'Policy','Sandboxie','Sandboxie/x64','Sandboxie/Win32')
TRUSTED_INSTALLER = 'S-1-5-80-'+'-'.join(str(v) for v in struct.unpack(
    '<5I',hashlib.sha1('TRUSTEDINSTALLER'.encode('utf-16le')).digest()))


class Information(C.Structure):
    _fields_=[('attributes',W.DWORD),('creation',W.FILETIME),('access',W.FILETIME),
              ('write',W.FILETIME),('volume',W.DWORD),('size_high',W.DWORD),
              ('size_low',W.DWORD),('links',W.DWORD),('index_high',W.DWORD),
              ('index_low',W.DWORD)]


class SecurityAttributes(C.Structure):
    _fields_=[('length',W.DWORD),('descriptor',C.c_void_p),('inherit',W.BOOL)]


class Directory:
    """Hold a local directory handle without delete sharing; never follow reparse points."""
    def __init__(self,path):
        self.handle=None
        self.path=Path(local_path(str(path)))
        guarded(local_volume(self.path),self.path,allow_root=True)
        self.api=C.WinDLL('kernel32',use_last_error=True)
        for name,args,result in [
            ('CreateFileW',[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE],W.HANDLE),
            ('GetFileInformationByHandle',[W.HANDLE,C.POINTER(Information)],W.BOOL),
            ('GetFinalPathNameByHandleW',[W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD],W.DWORD),
            ('CloseHandle',[W.HANDLE],W.BOOL),
            ('CreateDirectoryW',[W.LPCWSTR,C.POINTER(SecurityAttributes)],W.BOOL),
            ('LocalFree',[C.c_void_p],C.c_void_p),
        ]:
            fn=getattr(self.api,name);fn.argtypes,fn.restype=args,result
        try:
            # GENERIC_READ participates in Windows share checks. A metadata-only
            # handle (READ_CONTROL/READ_ATTRIBUTES) does not reliably block rename.
            self.handle=self.api.CreateFileW(str(self.path),0x80000000,3,None,3,0x02200000,None)
            if self.handle in (None,C.c_void_p(-1).value):
                self.handle=None;raise SafetyError('Cannot hold installation directory')
            info=Information();final=C.create_unicode_buffer(32768)
            count=self.api.GetFinalPathNameByHandleW(self.handle,final,len(final),0)
            if (not self.api.GetFileInformationByHandle(self.handle,C.byref(info))
                    or not info.attributes&0x10 or info.attributes&0x400
                    or not 0<count<len(final)
                    or final.value.casefold()!=('\\\\?\\'+str(self.path)).casefold()):
                raise SafetyError('Installation directory identity differs')
            self.identity=(info.volume,info.index_high,info.index_low)
            self.receipt_identity=[*self.identity,info.creation.dwHighDateTime,info.creation.dwLowDateTime]
        except BaseException:self.close();raise

    def close(self):
        if self.handle:self.api.CloseHandle(self.handle);self.handle=None
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def _create_child(parent,name,sddl):
    """Low-level primitive. Caller supplies a trusted, held parent and ACL."""
    reserved={'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}
    if (not isinstance(parent,Directory) or not parent.handle or not isinstance(name,str)
            or not re.fullmatch(r'[A-Za-z][A-Za-z0-9._-]{0,63}',name)
            or name.endswith('.') or name.split('.')[0].upper() in reserved):
        raise SafetyError('Invalid held parent or directory component')
    security=C.WinDLL('advapi32',use_last_error=True)
    convert=security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes=[W.LPCWSTR,W.DWORD,C.POINTER(C.c_void_p),C.POINTER(W.DWORD)]
    convert.restype=W.BOOL
    descriptor=C.c_void_p()
    if not convert(sddl,1,C.byref(descriptor),None):
        raise SafetyError('Invalid installation security descriptor')
    try:
        attributes=SecurityAttributes(C.sizeof(SecurityAttributes),descriptor,False)
        path=parent.path/name
        if not parent.api.CreateDirectoryW(str(path),C.byref(attributes)):
            raise SafetyError('Directory already exists or cannot be created; no adoption or ACL repair')
    finally:parent.api.LocalFree(descriptor)
    return Directory(path)


def validate_parent(row):
    """Allow Windows servicing authority only on the existing Program Files parent."""
    if not isinstance(row,dict) or not isinstance(row.get('owner'),str):raise SafetyError('Program Files ACL unavailable')
    value=dict(row)
    if value.get('owner')==TRUSTED_INSTALLER:value['owner']='S-1-5-18'
    rules=value.get('rules')
    if not isinstance(rules,list):raise SafetyError('Program Files ACL unavailable')
    if any(not isinstance(r,dict) or not isinstance(r.get('sid'),str)
           or type(r.get('rights')) is not int or r.get('type') not in ('Allow','Deny') for r in rules):
        raise SafetyError('Invalid Program Files ACE')
    value['rules']=[r for r in rules if r['sid']!=TRUSTED_INSTALLER]
    validate_acl(value,directory=False)


def _verify_parent(parent):
    row=ps_json('$p='+psq(str(parent.path))+r''';$a=Get-Acl -LiteralPath $p;
    $f=Get-Item -LiteralPath $p -Force;
    @{owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;
      reparse=[bool]($f.Attributes -band [IO.FileAttributes]::ReparsePoint);
      rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
        Where-Object { -not ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) } |
        ForEach-Object {@{sid=$_.IdentityReference.Value;rights=[long]$_.FileSystemRights;type=[string]$_.AccessControlType}})
    }|ConvertTo-Json -Depth 5 -Compress''')
    validate_parent(row)


class Store:
    def __init__(self):
        self.directories={};self.journal=None
    def close(self):
        if self.journal:self.journal.close();self.journal=None
        for directory in reversed(list(self.directories.values())):directory.close()
        self.directories.clear()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def _require_admin():
    shell=C.WinDLL('shell32');shell.IsUserAnAdmin.argtypes=[];shell.IsUserAnAdmin.restype=W.BOOL
    if not shell.IsUserAnAdmin():raise SafetyError('Already elevated installer required')


def _require_vacant_service_slots():
    """SCM absence alone does not exclude an orphaned service registry key."""
    from .install_scm import require_vacant_registry_slot
    from .install_inventory import SERVICES
    if fresh_install_blockers(services(),False):
        raise SafetyError('Occupied installation slots require separate verified migration')
    for name in SERVICES:require_vacant_registry_slot(name)


def create_store(generation,package_sha256):
    """Installer bootstrap only; does not authenticate a package or permit installation.

    Requires an already elevated caller. No UAC, ACL repair, deletion or adoption.
    On failure leave created protected directories and journal for explicit recovery.
    """
    initial=Transaction(None,generation,package_sha256).value
    _require_admin()
    result=Store()
    try:
        parent=Directory(program_files());result.directories['parent']=parent
        _verify_parent(parent)
        try:(parent.path/'ClaudeReset').lstat();exists=True
        except FileNotFoundError:exists=False
        if fresh_install_blockers(services(),exists):
            raise SafetyError('Occupied installation slots require separate verified migration')
        _require_vacant_service_slots()
        root=_create_child(parent,'ClaudeReset',ROOT_ACL);result.directories['root']=root
        _require_vacant_service_slots()
        installer=_create_child(root,'Installer',PRIVATE);result.directories['Installer']=installer
        verify_paths([root.path,installer.path],[root.path,installer.path])
        result.journal=_LocalFile(installer.path);result.journal.save(initial)
        from .install_bootstrap import DirectoryReceipts
        receipts=DirectoryReceipts(result.journal)
        receipts.begin(root,installer)
        # The first durable journal records the generation before payload directories.
        for name in FOLDERS[1:]:
            _require_vacant_service_slots()
            parts=name.split('/')
            parent_dir=root if len(parts)==1 else result.directories[parts[0]]
            acl=RUNTIME_READ if parts[0]=='Sandboxie' else PRIVATE
            result.directories[name]=_create_child(parent_dir,parts[-1],acl)
            receipts.record(name,result.directories[name])
        paths=[d.path for key,d in result.directories.items() if key!='parent']
        verify_paths(paths,paths)
        _require_vacant_service_slots()
        return result
    except BaseException:result.close();raise
