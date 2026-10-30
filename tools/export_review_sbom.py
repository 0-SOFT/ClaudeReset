"""Offline SPDX 2.3 artifact/dependency inventory for a pinned review bundle.

No executable is launched. NOASSERTION preserves unresolved license findings.
Source-supplement contents are distinguished from shipped runtime components.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
import sys
import zipfile
import zlib

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.backend.payload import PinnedPayload
from claude_reset.windows.pin import PinnedFile
from claude_reset.backend.spec import document
from claude_reset.safeio import SafetyError


def digest(value):return hashlib.sha256(value).hexdigest()


def identifier(kind,name):return 'SPDXRef-'+kind+'-'+digest(name.encode())[:24]


def name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9._~+/-]{1,512}',value):
        raise SafetyError('Unsupported SBOM component name or version')
    return value


def package(key,title,checksum=None,version=None,comment=None):
    result=dict(SPDXID=key,name=name(title),downloadLocation='NOASSERTION',filesAnalyzed=False,
                licenseConcluded='NOASSERTION',licenseDeclared='NOASSERTION',copyrightText='NOASSERTION')
    if checksum:
        if not re.fullmatch('[a-f0-9]{64}',checksum):raise SafetyError('Invalid SBOM component digest')
        result['checksums']=[dict(algorithm='SHA256',checksumValue=checksum)]
    if version:result['versionInfo']=name(version)
    if comment:result['sourceInfo']=comment
    return result


def frozen_components(pin,metadata):
    """Read bounded embedded PE bytes without extraction or execution."""
    from PyInstaller.archive.readers import CArchiveReader
    if not isinstance(pin,PinnedFile) or not pin.handle:raise SafetyError('Held runtime binary required')
    reader=CArchiveReader(str(pin.path));size=pin.path.stat().st_size
    if not isinstance(reader.toc,dict) or not 1<=len(reader.toc)<=4096:
        raise SafetyError('Unsupported frozen archive table')
    expected=metadata.get('python_cryptographic_runtime_sha256')
    if not isinstance(expected,dict) or set(expected)!={'_ssl.pyd','_hashlib.pyd','libcrypto-3.dll','libssl-3.dll'}:
        raise SafetyError('Frozen cryptographic source identities are missing')
    expected=dict(expected,**{'python312.dll':metadata.get('python_runtime_dll_sha256')})
    if any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in expected.values()):
        raise SafetyError('Invalid frozen runtime source identity')
    rows=[];total=0;seen=set()
    with pin.path.open('rb') as stream:
        for filename,entry in sorted(reader.toc.items()):
            if not isinstance(filename,str):raise SafetyError('Invalid frozen member name')
            if not filename.lower().endswith(('.dll','.pyd')):continue
            name(filename)
            if '/' in filename or '\\' in filename or filename.lower() in seen:
                raise SafetyError('Ambiguous embedded runtime path')
            seen.add(filename.lower())
            if not isinstance(entry,tuple) or len(entry)!=5:raise SafetyError('Unsupported frozen archive entry')
            offset,length,plain,compressed,kind=entry
            if (any(type(v) is not int for v in (offset,length,plain,compressed)) or offset<0
                    or not 0<length<=67108864 or not 0<plain<=67108864
                    or compressed not in (0,1) or kind!='b'
                    or type(reader._start_offset) is not int or reader._start_offset<0
                    or reader._start_offset+offset+length>size):
                raise SafetyError('Frozen archive entry exceeds bounds')
            total+=plain
            if total>268435456:raise SafetyError('Embedded runtime inventory exceeds bounds')
            stream.seek(reader._start_offset+offset);data=stream.read(length)
            if len(data)!=length:raise SafetyError('Truncated frozen member')
            if compressed:
                decoder=zlib.decompressobj()
                try:data=decoder.decompress(data,plain+1)
                except zlib.error:raise SafetyError('Invalid frozen compression stream') from None
                if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                    raise SafetyError('Ambiguous or oversized frozen compression stream')
            if len(data)!=plain or data[:2]!=b'MZ':raise SafetyError('Embedded PE content differs from its table')
            checksum=digest(data)
            if filename in expected and checksum!=expected[filename]:
                raise SafetyError('Embedded runtime differs from source-supplement identity')
            rows.append(dict(name=filename,sha256=checksum,bytes=plain))
    if not set(expected).issubset({row['name'] for row in rows}):
        raise SafetyError('Required embedded runtime library is missing')
    return rows


def export(bundle,manifest_sha256,epoch,expand_frozen=False):
    if type(epoch) is not int or not 0<=epoch<=4102444800:raise SafetyError('Explicit bounded SBOM creation epoch required')
    bundle=Path(bundle).resolve()
    packages=[];relationships=[]
    def relation(first,kind,second,comment=None):
        row=dict(spdxElementId=first,relationshipType=kind,relatedSpdxElement=second)
        if comment:row['comment']=comment
        relationships.append(row)
    root_id='SPDXRef-ReviewBundle';sources_id='SPDXRef-SourceSupplement'
    with PinnedPayload(bundle,manifest_sha256) as payload:
        manifest=document(payload.manifest.data)
        sources_hash=manifest.get('dependency_source_zip_sha256')
        if not isinstance(sources_hash,str) or not re.fullmatch('[a-f0-9]{64}',sources_hash):
            raise SafetyError('Pinned dependency source identity is required')
        packages.append(package(root_id,'ClaudeReset-review-payload',comment=
            'Exact 23-file internal review payload; manifest SHA256 '+manifest_sha256+'. Not installable or accepted.'))
        packages.append(package(sources_id,'dependency-sources.zip',sources_hash,comment=
            'Corresponding source artifacts and development-environment inventory; inclusion is not runtime linkage.'))
        relation(root_id,'OTHER',sources_id,'Associated source supplement, not executable payload.')
        payload_ids={}
        for filename,pin in sorted(payload.pins.items()):
            key=identifier('Payload',filename);payload_ids[filename]=key
            packages.append(package(key,filename,pin.sha256,comment='Shipped payload artifact; embedded dependency expansion is incomplete.'))
            relation(root_id,'CONTAINS',key)
        with PinnedFile(bundle/'dependency-sources.zip',expected_sha256=sources_hash,limit=536870912) as pin:
          with zipfile.ZipFile(pin.path) as archive:
            infos=archive.infolist();entries={entry.filename:entry for entry in infos}
            if len(entries)!=len(infos) or len(infos)>10000:raise SafetyError('Ambiguous or oversized source archive')
            if any(PurePosixPath(n).is_absolute() or '..' in PurePosixPath(n).parts or '\\' in n for n in entries):
                raise SafetyError('Unsafe source archive member')
            def raw(member,limit=2097152):
                if member not in entries or not 0<=entries[member].file_size<=limit:
                    raise SafetyError('Missing or oversized source metadata')
                return archive.read(member)
            metadata=document(raw('source-package.json'),2097152)
            files=metadata.get('files')
            if (not isinstance(files,dict) or metadata.get('engine_sha256')!=payload.pins['Engine/engine.exe'].sha256
                    or metadata.get('module_content_checksums_reverified') is not True):
                raise SafetyError('Source supplement does not match the payload engine')
            verified={}
            def verified_member(member):
                if member in verified:return verified[member]
                row=files.get(member)
                if (not isinstance(row,dict) or member not in entries or type(row.get('bytes')) is not int
                        or not 0<=row['bytes']<=536870912 or entries[member].file_size!=row['bytes']):
                    raise SafetyError('Source artifact size or inventory differs')
                with archive.open(member) as stream:checksum=hashlib.file_digest(stream,'sha256').hexdigest()
                if checksum!=row.get('sha256'):raise SafetyError('Source artifact hash differs')
                verified[member]=checksum;return checksum
            def metadata_member(member):
                verified_member(member);return document(raw(member),2097152)
            modules=metadata_member('inventory/source-inventory.json')
            buildinfo=metadata_member('inventory/engine-buildinfo.json')
            if (modules.get('engine_sha256')!=metadata['engine_sha256']
                    or not isinstance(modules.get('modules'),list)
                    or len(modules['modules'])!=metadata.get('go_modules')
                    or [row.get('module') for row in modules['modules']]!=buildinfo.get('Deps')):
                raise SafetyError('Go dependency inventory differs')
            seen=set()
            for row in modules['modules']:
                module=row['module'];title=name(module['Path']);version=name(module['Version'])
                if title in seen or row.get('verified') is not True:raise SafetyError('Ambiguous Go module inventory')
                seen.add(title)
                member='go-modules/'+PurePosixPath(row['archive']).name
                checksum=verified_member(member)
                if checksum!=row['sha256']:raise SafetyError('Go source inventory hash differs')
                key=identifier('Go',title+'@'+version)
                packages.append(package(key,title,checksum,version,
                    'Source archive for module recorded in the engine build information; license review incomplete.'))
                relation(payload_ids['Engine/engine.exe'],'STATIC_LINK',key)
                relation(sources_id,'CONTAINS',key)
            for inventory,prefix,label,count_field in (
                    ('inventory/python-sources.json','python-packages/','PythonDevelopment','python_source_distributions'),
                    ('inventory/cpython-native-sources.json','cpython-native/','NativeSource','cpython_native_source_archives')):
                rows=metadata_member(inventory)['sources']
                if not isinstance(rows,list) or len(rows)!=metadata.get(count_field):raise SafetyError('Source inventory count differs')
                identities=set()
                for row in rows:
                    title=name(row['name']);version=name(row['version']);identity=title+'@'+version
                    if identity in identities:raise SafetyError('Duplicate source inventory component')
                    identities.add(identity);member=prefix+name(row['file']);checksum=verified_member(member)
                    if checksum!=row['sha256']:raise SafetyError('Source inventory checksum differs')
                    key=identifier(label,identity)
                    packages.append(package(key,title,checksum,version,
                        'Source-supplement inventory only; this version is not asserted to be linked into the current runtime.'))
                    relation(sources_id,'CONTAINS',key)
            for member in sorted(files):
                if not member.startswith('upstream/'):continue
                key=identifier('Upstream',member)
                packages.append(package(key,PurePosixPath(member).name,verified_member(member),comment=
                    'Pinned upstream source archive in supplement; current runtime linkage is not inferred.'))
                relation(sources_id,'CONTAINS',key)
            if expand_frozen:
                for row in frozen_components(payload.pins['Runtime/ClaudeResetRuntime.exe'],metadata):
                    key=identifier('EmbeddedRuntime',row['name'])
                    packages.append(package(key,row['name'],row['sha256'],comment=
                        'PE bytes embedded in the pinned runtime; package version and license mapping are not asserted.'))
                    relation(payload_ids['Runtime/ClaudeResetRuntime.exe'],'CONTAINS',key)
        payload.report()
    ids=[row['SPDXID'] for row in packages]
    if len(ids)!=len(set(ids)):raise SafetyError('Duplicate SPDX component identifier')
    known=set(ids)|{'SPDXRef-DOCUMENT'}
    if any(r['spdxElementId'] not in known or r['relatedSpdxElement'] not in known for r in relationships):
        raise SafetyError('Dangling SPDX relationship')
    relation('SPDXRef-DOCUMENT','DESCRIBES',root_id)
    result=dict(spdxVersion='SPDX-2.3',dataLicense='CC0-1.0',SPDXID='SPDXRef-DOCUMENT',
        name='ClaudeReset-internal-review-bundle',
        creationInfo=dict(created=datetime.fromtimestamp(epoch,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                          creators=['Tool: ClaudeReset-review-SBOM-1']),
        packages=packages,relationships=relationships,
        comment='Artifact/dependency inventory, not release authorization. Licenses are NOASSERTION; no project code license is assigned. '
                'Standalone app/preflight and static native dependency/version mapping are outside this payload SBOM. '
                +('Embedded runtime PE hashes are inventoried. ' if expand_frozen else 'Embedded runtime PE contents are not expanded. ')+
                'Historical/source-only versions are not asserted to be current runtime dependencies.')
    identity=digest(json.dumps(result,sort_keys=True,separators=(',',':')).encode())
    result['documentNamespace']='https://spdx.org/spdxdocs/claudereset-review-'+identity
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--expected-manifest-sha256',required=True)
    parser.add_argument('--created-epoch',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expand-frozen',action='store_true',help='Inventory embedded runtime PE bytes without execution')
    args=parser.parse_args()
    result=export(args.bundle,args.expected_manifest_sha256,args.created_epoch,args.expand_frozen)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(dict(packages=len(result['packages']),relationships=len(result['relationships']),
                         license_review_complete=False,release_ready=False)))
