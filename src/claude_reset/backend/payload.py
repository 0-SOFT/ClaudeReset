"""Pin the exact review payload without granting installation authority.

An expected manifest hash establishes an integrity anchor only. A production
installer must independently authenticate its release catalog and signatures.
"""
import os
from pathlib import Path
import re
import stat
from .spec import document, ENGINES
from ..errors import SafetyError
from ..safeio import guarded, local_volume
from ..windows.pin import PinnedFile
from ..model.records import PayloadFile, exact
from ..windows.catalog import catalog_bytes, require_manifest_member
from ..windows.authenticode import check_digest, inspect_signature

FILES=frozenset([
    'Backend/ClaudeResetBackend.exe','Runtime/ClaudeResetRuntime.exe',
    'Engine/engine.exe','Gateway/ClaudeResetGateway.exe',
    'Sandboxie/x64/Templates.ini',
    *('Sandboxie/x64/'+name for name in (
        'KmdUtil.exe','SandboxieBITS.exe','SandboxieCrypto.exe','SandboxieDcomLaunch.exe',
        'SandboxieRpcSs.exe','SandboxieWUAU.exe','SbieCtrl.exe','SbieDll.dll','SbieDrv.sys',
        'SbieIni.exe','SbieMsg.dll','SbieSvc.exe','SboxHostDll.dll','Start.exe')),
    *('Sandboxie/Win32/'+name for name in ('SbieDll.dll','SbieMsg.dll','SbieSvc.exe','SboxHostDll.dll')),
])


def catalog(value):
    if not exact(value, FILES):
        raise SafetyError('The package must contain the exact supported payload')
    total=0
    for row in value.values():
        if (not exact(row, PayloadFile)
                or not isinstance(row['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',row['sha256'])
                or type(row['bytes']) is not int or not 0<row['bytes']<=268435456):
            raise SafetyError('Invalid payload identity')
        total+=row['bytes']
    if total>536870912:
        raise SafetyError('Payload exceeds the fixed size bound')
    if value['Engine/engine.exe']['sha256'] not in ENGINES.values():
        raise SafetyError('Engine is absent from the compiled catalog')
    return value


def entries(root):
    guarded(local_volume(root),root,allow_root=True)
    directories={parent.as_posix() for name in FILES for parent in Path(name).parents if parent!=Path('.')}
    found=set()
    pending=[root]
    while pending:
        directory=pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                info=entry.stat(follow_symlinks=False)
                if entry.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
                    raise SafetyError('Reparse point in payload tree')
                path=Path(entry.path)
                relative=path.relative_to(root).as_posix()
                if stat.S_ISDIR(info.st_mode):
                    if relative not in directories:
                        raise SafetyError('Unexpected payload directory')
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    if relative not in FILES:
                        raise SafetyError('Unexpected payload file')
                    found.add(relative)
                else:
                    raise SafetyError('Nonregular payload input')
    return found


class PinnedPayload:
    def __init__(self, bundle, expected_manifest_sha256):
        self.pins={}
        self.manifest=None
        if not isinstance(expected_manifest_sha256,str) or not re.fullmatch('[a-f0-9]{64}',expected_manifest_sha256):
            raise SafetyError('An explicit manifest digest is required')
        root=Path(bundle)
        try:
            self.manifest=PinnedFile(root/'bundle-manifest.json',expected_sha256=expected_manifest_sha256,limit=65536)
            value=document(self.manifest.data)
            if not isinstance(value,dict):
                raise SafetyError('Invalid bundle manifest')
            payload=catalog(value.get('payload'))
            # A review payload contains no private engine config or extra DLLs.
            if entries(root/'payload')!=FILES:
                raise SafetyError('Unexpected or missing payload files')
            for name,row in sorted(payload.items()):
                pin=PinnedFile(root/'payload'/name,expected_sha256=row['sha256'],limit=row['bytes'])
                self.pins[name]=pin
                if pin.size()!=row['bytes']:
                    raise SafetyError('Payload size differs')
            self.manifest_sha256=expected_manifest_sha256
        except BaseException:
            self.close()
            raise

    def report(self):
        if (not exact(self.pins, FILES) or not isinstance(self.manifest,PinnedFile)
                or not self.manifest.handle
                or any(not isinstance(pin,PinnedFile) or not pin.handle for pin in self.pins.values())):
            raise SafetyError('Payload pins are closed or incomplete')
        return {'schema':1,'manifest_sha256':self.manifest_sha256,'payload_files':len(self.pins),
                'payload_integrity_verified':True,'manifest_authenticity_verified':False,
                'signatures_verified':False,'installable':False,'client_admission':False,
                'settings_changed':False}

    def close(self):
        for pin in reversed(list(self.pins.values())):
            pin.close()
        self.pins.clear()
        if self.manifest is not None:
            self.manifest.close()
            self.manifest=None

    def __enter__(self):
        return self
    def __exit__(self,*args):
        self.close()


def inspect_release_catalog(catalog_pin: PinnedFile, payload: PinnedPayload) -> dict:
    if not isinstance(catalog_pin,PinnedFile) or not catalog_pin.handle or not isinstance(payload,PinnedPayload):
        raise SafetyError('Held catalog and exact payload required')
    payload.report()
    raw=catalog_bytes(catalog_pin)
    signature=inspect_signature(catalog_pin)
    require_manifest_member(raw,payload.manifest_sha256)
    check_digest(catalog_pin)
    check_digest(payload.manifest)
    return {'schema':1,'catalog_sha256':catalog_pin.sha256,'manifest_sha256':payload.manifest_sha256,
            'catalog_authenticode_verified':True,'manifest_membership_verified':True,
            'signer_certificate_sha256':signature['signer_certificate_sha256'],
            'release_authority_verified':False,'kernel_load_verified':False,
            'installable':False,'client_admission':False}
