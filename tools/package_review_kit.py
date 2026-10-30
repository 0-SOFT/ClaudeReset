"""Create a portable read-only inspection kit; no installation or elevation."""
import argparse
from copy import deepcopy
from contextlib import ExitStack
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
import shutil
import sys
import zipfile
from build_preflight_candidate import require_as_invoker
from export_review_sbom import export,frozen_components,package,identifier,digest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.backend.payload import PinnedPayload
from claude_reset.windows.pin import PinnedFile
from claude_reset.backend.spec import document
from claude_reset.safeio import SafetyError,guarded,local_volume


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def member(value):
    if (not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9._/-]+',value)
            or value.startswith('/') or any(p in ('','.','..') for p in value.split('/'))):
        raise SafetyError('Invalid review-kit member')
    return value


def launcher(manifest_hash,catalog_hash,preflight_hash):
    if any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in (manifest_hash,catalog_hash,preflight_hash)):
        raise SafetyError('Fixed review-kit digests required')
    return ('@echo off\r\nsetlocal DisableDelayedExpansion\r\n'
        'set "CLAUDERESET_REVIEW_ROOT=%~dp0"\r\n'
        '"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command '
        '"$p=Join-Path $env:CLAUDERESET_REVIEW_ROOT \'ClaudeResetPreflight.exe\'; '
        'if ((Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash -ne \''+preflight_hash+'\') { exit 1 }"\r\n'
        'if errorlevel 1 exit /b 1\r\n'
        '"%~dp0ClaudeResetPreflight.exe" --bundle "%~dp0ServiceBundle" '
        '--expected-manifest-sha256 '+manifest_hash+' --catalog "%~dp0release.cat" '
        '--expected-catalog-sha256 '+catalog_hash+'\r\nexit /b %errorlevel%\r\n')


def archive_kit(folder,output,epoch):
    folder=Path(folder).resolve();output=Path(output).resolve()
    guarded(local_volume(output),output.parent)
    if output.exists() or output.is_relative_to(folder):raise SafetyError('Choose a fresh archive outside the kit')
    if type(epoch) is not int or not 315532800<=epoch<=4102444800:raise SafetyError('Bounded ZIP creation epoch required')
    date=datetime.fromtimestamp(epoch,timezone.utc).timetuple()[:6]
    with ExitStack() as stack:
        control=stack.enter_context(PinnedFile(folder/'kit-manifest.json',limit=65536))
        manifest=document(control.data)
        if (manifest.get('kind')!='portable_read_only_review_kit' or manifest.get('installable') is not False
                or manifest.get('client_admission') is not False or not isinstance(manifest.get('files'),dict)):
            raise SafetyError('Read-only review-kit manifest required')
        expected=set(manifest['files'])|{'kit-manifest.json'}
        actual={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
        if actual!=expected:raise SafetyError('Unexpected or missing review-kit files')
        pins={'kit-manifest.json':control}
        for relative,row in manifest['files'].items():
            path=folder/member(relative)
            pins[relative]=stack.enter_context(PinnedFile(path,expected_sha256=row['sha256'],limit=536870912))
            if path.stat().st_size!=row['bytes']:raise SafetyError('Review-kit member size changed')
        with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_STORED) as archive:
            for relative,pin in sorted(pins.items()):
                info=zipfile.ZipInfo(relative,date);info.create_system=3;info.external_attr=0o100644<<16
                with archive.open(info,'w') as destination,pin.path.open('rb') as source:
                    shutil.copyfileobj(source,destination)
        with zipfile.ZipFile(output) as archive:
            if set(archive.namelist())!=set(pins):raise SafetyError('Review archive member list differs')
            for relative,pin in pins.items():
                with archive.open(relative) as source:
                    if hashlib.file_digest(source,'sha256').hexdigest()!=pin.sha256:
                        raise SafetyError('Review archive member bytes differ')
    return dict(sha256=sha(output),bytes=output.stat().st_size,files=len(expected),
                source_date_epoch=epoch,installable=False,client_admission=False)


def kit_sbom(service,artifacts,catalog_hash):
    """Bind all frozen PE inventories to the same Python/crypto generation."""
    result=deepcopy(service);result.pop('documentNamespace',None)
    expected_names={'python312.dll','_ssl.pyd','_hashlib.pyd','libcrypto-3.dll','libssl-3.dll'}
    expected={}
    for row in result['packages']:
        if row['SPDXID'].startswith('SPDXRef-EmbeddedRuntime-') and row['name'] in expected_names:
            if row['name'] in expected:raise SafetyError('Ambiguous runtime SBOM identity')
            values=[v['checksumValue'] for v in row.get('checksums',[]) if v.get('algorithm')=='SHA256']
            if len(values)!=1:raise SafetyError('Runtime SBOM digest is required')
            expected[row['name']]=values[0]
    if set(expected)!=expected_names:raise SafetyError('Expanded runtime SBOM is required for a complete kit')
    metadata=dict(python_runtime_dll_sha256=expected.pop('python312.dll'),
                  python_cryptographic_runtime_sha256=expected)
    root='SPDXRef-ReviewKit'
    result['packages'].append(package(root,'ClaudeReset-portable-review-kit',comment=
        'Read-only candidate kit; no installation, publisher authentication or client admission.'))
    result['relationships']=[r for r in result['relationships'] if r['relationshipType']!='DESCRIBES']
    result['relationships']+= [dict(spdxElementId='SPDXRef-DOCUMENT',relationshipType='DESCRIBES',relatedSpdxElement=root),
                              dict(spdxElementId=root,relationshipType='CONTAINS',relatedSpdxElement='SPDXRef-ReviewBundle')]
    for label,pin in artifacts.items():
        key=identifier('Standalone',label)
        result['packages'].append(package(key,label,pin.sha256))
        result['relationships'].append(dict(spdxElementId=root,relationshipType='CONTAINS',relatedSpdxElement=key))
        for row in frozen_components(pin,metadata):
            child=identifier('EmbeddedStandalone',label+'/'+row['name'])
            result['packages'].append(package(child,row['name'],row['sha256'],comment=
                'Embedded PE bytes; Python/crypto identities agree with service runtime. Version/license mapping remains unasserted.'))
            result['relationships'].append(dict(spdxElementId=key,relationshipType='CONTAINS',relatedSpdxElement=child))
    result['packages'].append(package('SPDXRef-ReleaseCatalog','release.cat',catalog_hash,comment=
        'Pinned release metadata catalog; no approved release authority is asserted.'))
    result['relationships'].append(dict(spdxElementId=root,relationshipType='CONTAINS',relatedSpdxElement='SPDXRef-ReleaseCatalog'))
    result['name']='ClaudeReset-portable-review-kit'
    result['creationInfo']['creators'].append('Tool: ClaudeReset-review-kit-SBOM-1')
    result['comment']='Exact service, standalone app/preflight and embedded PE inventories. License conclusions and static native version mapping remain incomplete. Not release authorization; no project code license is assigned.'
    ids=[p['SPDXID'] for p in result['packages']]
    if len(ids)!=len(set(ids)):raise SafetyError('Duplicate kit SBOM identifier')
    known=set(ids)|{'SPDXRef-DOCUMENT'}
    if any(r['spdxElementId'] not in known or r['relatedSpdxElement'] not in known for r in result['relationships']):
        raise SafetyError('Dangling kit SBOM relationship')
    result['documentNamespace']='https://spdx.org/spdxdocs/claudereset-kit-'+digest(json.dumps(result,sort_keys=True,separators=(',',':')).encode())
    return result


def main(bundle,manifest_hash,catalog,catalog_hash,app,preflight,sbom,sbom_hash,epoch,output):
    bundle,catalog,app,preflight,sbom,output=[Path(p).resolve() for p in (bundle,catalog,app,preflight,sbom,output)]
    guarded(local_volume(output),output,allow_root=True)
    if output.exists():raise SafetyError('Preserve existing review kits')
    copies={};receipts={}
    with ExitStack() as stack:
        payload=stack.enter_context(PinnedPayload(bundle,manifest_hash))
        manifest=document(payload.manifest.data)
        copies['ServiceBundle/bundle-manifest.json']=payload.manifest
        for name,pin in payload.pins.items():copies['ServiceBundle/payload/'+name]=pin
        for filename,key in [('dependency-sources.zip','dependency_source_zip_sha256'),
                             ('reviewed-development-source.zip','source_zip_sha256')]:
            expected=manifest.get(key)
            if not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected):
                raise SafetyError('Source archive identity required')
            copies['ServiceBundle/'+filename]=stack.enter_context(PinnedFile(bundle/filename,expected_sha256=expected,limit=536870912))
        with zipfile.ZipFile(copies['ServiceBundle/reviewed-development-source.zip'].path) as source_archive:
            names=source_archive.namelist()
            if len(names)!=len(set(names)):raise SafetyError('Ambiguous development source archive')
            license_names=[n for n in names if n.startswith('third_party/licenses/')]
            if not license_names or 'third_party/NOTICES.md' not in names:
                raise SafetyError('Matching third-party license material is required')
            for relative in ['third_party/NOTICES.md',*license_names]:
                member(relative)
                if source_archive.getinfo(relative).file_size>1048576:raise SafetyError('License text exceeds bound')
                checksum=hashlib.sha256(source_archive.read(relative)).hexdigest()
                target='THIRD-PARTY-NOTICES.md' if relative.endswith('/NOTICES.md') else 'licenses/third-party/'+relative[len('third_party/licenses/'):]
                copies[target]=stack.enter_context(PinnedFile(ROOT/relative,expected_sha256=checksum,limit=1048576))
        copies['release.cat']=stack.enter_context(PinnedFile(catalog,expected_sha256=catalog_hash,limit=1048576))
        sbom_pin=stack.enter_context(PinnedFile(sbom,expected_sha256=sbom_hash,limit=2097152))
        service_sbom=document(sbom_pin.path.read_bytes(),2097152)
        if service_sbom!=export(bundle,manifest_hash,epoch,True):
            raise SafetyError('SBOM does not describe this exact review bundle')
        copies['service-payload.spdx.json']=sbom_pin
        for label,folder,filename in [('app',app,'ClaudeResetCandidate.exe'),
                                       ('preflight',preflight,'ClaudeResetPreflight.exe')]:
            receipt_pin=stack.enter_context(PinnedFile(folder/'build-receipt.json',limit=65536))
            receipt=document(receipt_pin.data);receipts[label]=receipt
            if (receipt.get('installed') is not False or receipt.get('client_network_opened') is not False
                    or receipt.get('final_release') is not False or not receipt.get('source_sha256')
                    or not receipt.get('license_sha256')):
                raise SafetyError('Reviewed frozen candidate evidence required')
            for relative,expected in receipt['source_sha256'].items():
                if sha(guarded(ROOT/member(relative),ROOT))!=expected:
                    raise SafetyError('Frozen candidate source drift')
            pin=stack.enter_context(PinnedFile(folder/'dist'/filename,expected_sha256=receipt['executable_sha256']))
            require_as_invoker(pin.path)
            copies[filename]=pin;copies['evidence/'+label+'-build-receipt.json']=receipt_pin
            for relative,expected in receipt['license_sha256'].items():
                copies['licenses/'+label+'/'+member(relative)]=stack.enter_context(
                    PinnedFile(folder/'licenses'/relative,expected_sha256=expected,limit=1048576))
        complete_sbom=kit_sbom(service_sbom,{filename:copies[filename] for filename in
            ('ClaudeResetCandidate.exe','ClaudeResetPreflight.exe')},catalog_hash)
        # Every input is pinned and validated before creating the destination.
        output.mkdir(parents=True)
        for relative,pin in copies.items():
            target=output/member(relative);target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as destination,pin.path.open('rb') as source:shutil.copyfileobj(source,destination)
            if sha(target)!=pin.sha256:raise SafetyError('Review-kit copy differs')
        (output/'Run-Preflight.cmd').write_bytes(launcher(manifest_hash,catalog_hash,
            receipts['preflight']['executable_sha256']).encode('ascii'))
        (output/'review-kit.spdx.json').write_text(json.dumps(complete_sbom,indent=2),encoding='utf-8')
        readme='''ClaudeReset INTERNAL REVIEW KIT — NOT AN INSTALLER

Windows x64. Python and the research checkout are not required for the EXEs.
From a command prompt in this directory, run:
  Run-Preflight.cmd > preflight.json
Exit 2 means inspection completed with outstanding blockers; exit 1 means invalid
input or failed inspection. No successful inspection grants client admission.
The command requests no elevation and performs no installation, service control,
WFP changes or client launch. Its binary hash check is an integrity snapshot,
not publisher authentication or protection against a concurrent privileged writer.

ClaudeResetCandidate.exe --help lists the separate app CLI. Review reset scopes
before using app actions; do not reset a live account as part of preflight.
Do not execute ServiceBundle/payload files manually or register its services.
Keep unsigned drivers uninstalled and existing client network admission closed.

ServiceBundle contains the exact service payload and corresponding source ZIPs.
service-payload.spdx.json describes the service bundle; review-kit.spdx.json also
inventories standalone app/preflight embedded PE bytes. Python and cryptographic
library hashes agree across these candidates. Static native version/license
mapping is still incomplete; equal hashes do not establish installed acceptance.
Licenses remain under review. No license is assigned to project code. Complete
production installation, signing authority, installed network/Cowork/privacy tests
and independent Windows acceptance remain outstanding. Nothing is published.
'''
        (output/'README.txt').write_bytes(readme.encode('utf-8'))
        files={p.relative_to(output).as_posix():dict(sha256=sha(p),bytes=p.stat().st_size)
               for p in sorted(output.rglob('*')) if p.is_file()}
        result=dict(schema=1,kind='portable_read_only_review_kit',files=files,
                    service_manifest_sha256=manifest_hash,catalog_sha256=catalog_hash,
                    installable=False,client_admission=False,release_ready=False,published=False)
        (output/'kit-manifest.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(dict(files=len(files)+1,installable=False,client_admission=False)))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for arg in ('bundle','catalog','app','preflight','sbom','output'):parser.add_argument('--'+arg,type=Path,required=True)
    for arg in ('manifest-sha256','catalog-sha256','sbom-sha256'):parser.add_argument('--'+arg,required=True)
    parser.add_argument('--created-epoch',type=int,required=True)
    parser.add_argument('--zip-output',type=Path)
    args=parser.parse_args();main(args.bundle,args.manifest_sha256,args.catalog,args.catalog_sha256,
        args.app,args.preflight,args.sbom,args.sbom_sha256,args.created_epoch,args.output)
    if args.zip_output:print(json.dumps(archive_kit(args.output,args.zip_output,args.created_epoch)))
