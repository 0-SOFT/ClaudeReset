import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile
import pytest
from test_install_payload import fixture as payload_fixture
from claude_reset.safeio import SafetyError

spec=importlib.util.spec_from_file_location('review_sbom',Path(__file__).resolve().parents[2]/'tools/export_review_sbom.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)


def fixture(root,monkeypatch,fault=None):
    payload_fixture(root,monkeypatch)
    manifest=json.loads((root/'bundle-manifest.json').read_text())
    engine=manifest['payload']['Engine/engine.exe']['sha256']
    archives={'go-modules/a.zip':b'go source','python-packages/example.tar.gz':b'python source',
              'cpython-native/b.tar.gz':b'native source','upstream/source.zip':b'upstream source'}
    sha=lambda raw:hashlib.sha256(raw).hexdigest()
    module=dict(Path='example.test/module',Version='v1.2.3',Sum='h1:fixture')
    modules=dict(engine_sha256=engine,modules=[dict(module=module,verified=True,archive='archives/a.zip',sha256=sha(archives['go-modules/a.zip']))])
    if fault=='duplicate-module':modules['modules']*=2
    buildinfo=dict(Deps=[row['module'] for row in modules['modules']])
    if fault=='buildinfo-drift':buildinfo['Deps']=[]
    archives['inventory/source-inventory.json']=json.dumps(modules).encode()
    archives['inventory/engine-buildinfo.json']=json.dumps(buildinfo).encode()
    for inventory,prefix,filename in [('python-sources','python-packages/','example.tar.gz'),
                                      ('cpython-native-sources','cpython-native/','b.tar.gz')]:
        archives['inventory/'+inventory+'.json']=json.dumps(dict(sources=[dict(name='example',version='1.0',file=filename,sha256=sha(archives[prefix+filename]))])).encode()
    metadata=dict(files={name:dict(bytes=len(raw),sha256=sha(raw)) for name,raw in archives.items()},
                  engine_sha256=engine,module_content_checksums_reverified=True,go_modules=len(modules['modules']),
                  python_source_distributions=1,cpython_native_source_archives=1)
    if fault=='hash-drift':archives['go-modules/a.zip']=b'bad bytes'
    if fault=='size-drift':metadata['files']['upstream/source.zip']['bytes']+=1
    if fault=='engine-drift':metadata['engine_sha256']='0'*64
    if fault=='name-private':
        value=json.loads(archives['inventory/python-sources.json']);value['sources'][0]['name']='C:\\SECRET\\name'
        raw=json.dumps(value).encode();archives['inventory/python-sources.json']=raw
        metadata['files']['inventory/python-sources.json']=dict(bytes=len(raw),sha256=sha(raw))
    with zipfile.ZipFile(root/'dependency-sources.zip','x') as archive:
        for name,raw in archives.items():archive.writestr(name,raw)
        archive.writestr('source-package.json',json.dumps(metadata))
        if fault=='duplicate-member':
            with pytest.warns(UserWarning):archive.writestr('source-package.json',json.dumps(metadata))
    manifest['dependency_source_zip_sha256']=sha((root/'dependency-sources.zip').read_bytes())
    raw=json.dumps(manifest).encode();(root/'bundle-manifest.json').write_bytes(raw)
    return sha(raw)


def test_sbom_is_deterministic_scoped_and_does_not_authorize_or_assign_code_license(tmp_path,monkeypatch):
    checksum=fixture(tmp_path,monkeypatch)
    before={p:p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    first=s.export(tmp_path,checksum,1793045343)
    assert first==s.export(tmp_path,checksum,1793045343)
    assert first['spdxVersion']=='SPDX-2.3' and len(first['packages'])==29
    assert all(p['licenseConcluded']==p['licenseDeclared']=='NOASSERTION' for p in first['packages'])
    assert all(p['filesAnalyzed'] is False and 'packageVerificationCode' not in p for p in first['packages'])
    ids={p['SPDXID'] for p in first['packages']}|{'SPDXRef-DOCUMENT'}
    assert all(r['spdxElementId'] in ids and r['relatedSpdxElement'] in ids for r in first['relationships'])
    assert len([r for r in first['relationships'] if r['relationshipType']=='STATIC_LINK'])==1
    assert 'not release authorization' in first['comment']
    assert str(tmp_path) not in json.dumps(first)
    assert all(p.read_bytes()==raw for p,raw in before.items())
    assert s.export(tmp_path,checksum,1793045344)['documentNamespace']!=first['documentNamespace']


@pytest.mark.parametrize('fault',['duplicate-module','buildinfo-drift','hash-drift','size-drift',
                                  'engine-drift','name-private','duplicate-member'])
def test_sbom_refuses_inconsistent_sources_without_mutation(tmp_path,monkeypatch,fault):
    checksum=fixture(tmp_path,monkeypatch,fault)
    before={p:p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    with pytest.raises(SafetyError):s.export(tmp_path,checksum,1793045343)
    assert all(p.read_bytes()==raw for p,raw in before.items())


def test_sbom_keeps_payload_and_sources_pinned_until_metadata_complete(tmp_path,monkeypatch):
    checksum=fixture(tmp_path,monkeypatch);original=s.package;observed=[]
    def package(*args,**kwargs):
        if args[1]=='example.test/module':
            for path in (tmp_path/'dependency-sources.zip',tmp_path/'payload/Engine/engine.exe'):
                with pytest.raises(OSError):path.write_bytes(b'replaced')
                observed.append(path)
        return original(*args,**kwargs)
    monkeypatch.setattr(s,'package',package)
    s.export(tmp_path,checksum,1793045343)
    assert len(observed)==2
    for path in observed:path.write_bytes(b'released')


@pytest.mark.parametrize('epoch',[True,-1,4102444801,'1793045343'])
def test_sbom_requires_explicit_bounded_creation_time(tmp_path,epoch):
    with pytest.raises(SafetyError):s.export(tmp_path,'a'*64,epoch)


@pytest.mark.parametrize('fault',[None,'hash','missing','oversized','bomb','tail','truncated','invalid','case-alias','non-pe'])
def test_bounded_embedded_runtime_inventory(tmp_path,monkeypatch,fault):
    from types import SimpleNamespace
    import zlib
    from PyInstaller.archive import readers
    from claude_reset.windows_pin import PinnedFile
    names=['python312.dll','_ssl.pyd','_hashlib.pyd','libcrypto-3.dll','libssl-3.dll','VCRUNTIME140.dll']
    data=b'MZsynthetic-PE';checksum=hashlib.sha256(data).hexdigest()
    metadata=dict(python_runtime_dll_sha256=checksum,
                  python_cryptographic_runtime_sha256={n:checksum for n in names[1:5]})
    raw=b'';toc={}
    for n in names:
        plain=data
        if n=='VCRUNTIME140.dll' and fault=='bomb':plain=b'MZ'+b'X'*1048576
        if n=='VCRUNTIME140.dll' and fault=='non-pe':plain=b'NOT-PE'
        compressed=zlib.compress(plain)
        advertised=4 if n=='VCRUNTIME140.dll' and fault=='bomb' else len(plain)
        if n=='VCRUNTIME140.dll':
            if fault=='tail':compressed+=b'extra'
            if fault=='truncated':compressed=compressed[:-2]
            if fault=='invalid':compressed=b'not a zlib stream'
            if fault=='oversized':advertised=67108865
        toc[n]=(len(raw),len(compressed),advertised,1,'b');raw+=compressed
    if fault=='missing':toc.pop('_ssl.pyd')
    if fault=='hash':metadata['python_runtime_dll_sha256']='0'*64
    if fault=='case-alias':toc['PYTHON312.DLL']=toc['python312.dll']
    path=tmp_path/'inert-frozen.bin';path.write_bytes(raw)
    monkeypatch.setattr(readers,'CArchiveReader',lambda path:SimpleNamespace(toc=toc,_start_offset=0))
    with PinnedFile(path) as pin:
        if fault:
            with pytest.raises(SafetyError):s.frozen_components(pin,metadata)
        else:
            rows=s.frozen_components(pin,metadata)
            assert len(rows)==6 and all(row['sha256']==checksum for row in rows)
            with pytest.raises(OSError):path.write_bytes(b'changed')
    assert path.read_bytes()==raw
