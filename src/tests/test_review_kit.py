import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import zipfile
import pytest
from test_install_payload import fixture as payload_fixture
from claude_reset.safeio import SafetyError

tools=Path(__file__).resolve().parents[2]/'tools'
previous=list(sys.path)
try:
    sys.path.insert(0,str(tools))
    spec=importlib.util.spec_from_file_location('review_kit',tools/'package_review_kit.py')
    k=importlib.util.module_from_spec(spec);spec.loader.exec_module(k)
finally:sys.path[:]=previous


def fixture(root,monkeypatch):
    bundle=root/'bundle';bundle.mkdir();payload_fixture(bundle,monkeypatch)
    source=root/'project';source.mkdir()
    files={'src/main.py':b'fixture source','third_party/NOTICES.md':b'fixture notice',
           'third_party/licenses/example/LICENSE':b'fixture license'}
    for name,raw in files.items():
        path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    monkeypatch.setattr(k,'ROOT',source)
    with zipfile.ZipFile(bundle/'reviewed-development-source.zip','x') as archive:
        for name,raw in files.items():archive.writestr(name,raw)
    (bundle/'dependency-sources.zip').write_bytes(b'inert source supplement')
    manifest=json.loads((bundle/'bundle-manifest.json').read_text())
    manifest.update(source_zip_sha256=k.sha(bundle/'reviewed-development-source.zip'),
                    dependency_source_zip_sha256=k.sha(bundle/'dependency-sources.zip'))
    (bundle/'bundle-manifest.json').write_text(json.dumps(manifest))
    cat=root/'release.cat';cat.write_bytes(b'inert catalog')
    names=['python312.dll','_ssl.pyd','_hashlib.pyd','libcrypto-3.dll','libssl-3.dll']
    service={'packages':[k.package('SPDXRef-ReviewBundle','bundle')]+[
        k.package(k.identifier('EmbeddedRuntime',name),name,hashlib.sha256(name.encode()).hexdigest())
        for name in names], 'relationships':[], 'creationInfo':{'creators':['Tool: fixture']}}
    sbom=root/'sbom.json';sbom.write_text(json.dumps(service))
    monkeypatch.setattr(k,'export',lambda *args:service)
    def embedded(pin,metadata):
        assert metadata['python_runtime_dll_sha256']==hashlib.sha256(b'python312.dll').hexdigest()
        assert set(metadata['python_cryptographic_runtime_sha256'])==set(names[1:])
        return [dict(name=name,sha256=hashlib.sha256(name.encode()).hexdigest()) for name in names]
    monkeypatch.setattr(k,'frozen_components',embedded)
    levels=[]
    monkeypatch.setattr(k,'require_as_invoker',lambda path:levels.append(path.name))
    for folder,filename in [('app','ClaudeResetCandidate.exe'),('preflight','ClaudeResetPreflight.exe')]:
        base=root/folder;(base/'dist').mkdir(parents=True);(base/'licenses').mkdir()
        (base/'dist'/filename).write_bytes(b'MZinert '+filename.encode())
        (base/'licenses/LICENSE').write_bytes(b'license')
        receipt=dict(installed=False,client_network_opened=False,final_release=False,
                     source_sha256={'src/main.py':k.sha(source/'src/main.py')},
                     license_sha256={'LICENSE':k.sha(base/'licenses/LICENSE')},
                     executable_sha256=k.sha(base/'dist'/filename))
        (base/'build-receipt.json').write_text(json.dumps(receipt))
    args=[bundle,k.sha(bundle/'bundle-manifest.json'),cat,k.sha(cat),root/'app',root/'preflight',
          sbom,k.sha(sbom),1793045343,root/'output']
    return args,levels


def test_review_kit_copies_only_hash_bound_members_and_never_authorizes_install(tmp_path,monkeypatch):
    args,levels=fixture(tmp_path,monkeypatch)
    (args[0]/'PRIVATE-extra.json').write_bytes(b'SECRET')
    before={p:p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    result=k.main(*args)
    assert levels==['ClaudeResetCandidate.exe','ClaudeResetPreflight.exe']
    assert result['installable'] is result['client_admission'] is result['release_ready'] is False
    assert 'PRIVATE' not in json.dumps(result) and 'SECRET' not in json.dumps(result)
    assert set(result['files'])|{'kit-manifest.json'}=={
        p.relative_to(args[-1]).as_posix() for p in args[-1].rglob('*') if p.is_file()}
    assert all(k.sha(args[-1]/name)==row['sha256'] for name,row in result['files'].items())
    assert all(p.read_bytes()==raw for p,raw in before.items())
    assert b'NOT AN INSTALLER' in (args[-1]/'README.txt').read_bytes()
    sbom=json.loads((args[-1]/'review-kit.spdx.json').read_text())
    assert len([p for p in sbom['packages'] if p['SPDXID'].startswith('SPDXRef-EmbeddedStandalone-')])==10
    assert {p['name'] for p in sbom['packages']} >= {'ClaudeResetCandidate.exe','ClaudeResetPreflight.exe','release.cat'}


@pytest.mark.parametrize('fault',['payload','catalog','sbom','frozen','source','license','elevation','existing-output'])
def test_invalid_review_kit_is_refused_before_creating_output(tmp_path,monkeypatch,fault):
    args,_=fixture(tmp_path,monkeypatch)
    if fault=='payload':(args[0]/'payload/Engine/engine.exe').write_bytes(b'changed')
    elif fault=='catalog':args[2].write_bytes(b'changed')
    elif fault=='sbom':args[6].write_bytes(b'changed')
    elif fault=='frozen':(args[4]/'dist/ClaudeResetCandidate.exe').write_bytes(b'changed')
    elif fault=='source':(k.ROOT/'src/main.py').write_bytes(b'changed')
    elif fault=='license':(args[4]/'licenses/LICENSE').write_bytes(b'changed')
    elif fault=='elevation':
        def reject(*args):raise SafetyError('Elevating PE refused')
        monkeypatch.setattr(k,'require_as_invoker',reject)
    else:
        args[-1].mkdir();(args[-1]/'preserve').write_bytes(b'original')
    with pytest.raises(SafetyError):k.main(*args)
    if fault=='existing-output':assert (args[-1]/'preserve').read_bytes()==b'original'
    else:assert not args[-1].exists()


def test_copy_failure_does_not_leave_a_launch_command_or_complete_manifest(tmp_path,monkeypatch):
    args,_=fixture(tmp_path,monkeypatch)
    def fail(*args):raise OSError('fixture copy failure')
    monkeypatch.setattr(k.shutil,'copyfileobj',fail)
    with pytest.raises(OSError):k.main(*args)
    assert not (args[-1]/'Run-Preflight.cmd').exists()
    assert not (args[-1]/'kit-manifest.json').exists()


def test_incompatible_embedded_generation_refused_before_output(tmp_path,monkeypatch):
    args,_=fixture(tmp_path,monkeypatch)
    def incompatible(*args):raise SafetyError('Embedded runtime differs from source metadata')
    monkeypatch.setattr(k,'frozen_components',incompatible)
    with pytest.raises(SafetyError,match='runtime differs'):k.main(*args)
    assert not args[-1].exists()


@pytest.mark.parametrize('fault',['missing','duplicate','no-digest','dangling'])
def test_kit_sbom_rejects_incomplete_or_ambiguous_service_inventory(tmp_path,monkeypatch,fault):
    args,_=fixture(tmp_path,monkeypatch)
    service=json.loads(args[6].read_text())
    if fault=='missing':service['packages'].pop()
    elif fault=='duplicate':service['packages'].append(service['packages'][-1])
    elif fault=='no-digest':service['packages'][-1].pop('checksums')
    else:service['relationships'].append(dict(spdxElementId='missing',relatedSpdxElement='SPDXRef-ReviewBundle',relationshipType='CONTAINS'))
    with pytest.raises(SafetyError):k.kit_sbom(service,{},'a'*64)


@pytest.mark.parametrize('digest',[None,True,'a'*63,'a'*64+' & command','../escape'])
def test_launcher_accepts_only_fixed_hex_digests(digest):
    with pytest.raises(SafetyError):k.launcher(digest,'b'*64,'c'*64)


def test_review_archive_repeats_exact_bytes_and_preserves_existing_output(tmp_path,monkeypatch):
    args,_=fixture(tmp_path,monkeypatch);k.main(*args)
    first=tmp_path/'first.zip';second=tmp_path/'second.zip'
    a=k.archive_kit(args[-1],first,1793045343);b=k.archive_kit(args[-1],second,1793045343)
    assert a==b and first.read_bytes()==second.read_bytes()
    assert a['installable'] is a['client_admission'] is False
    with pytest.raises(SafetyError):k.archive_kit(args[-1],first,1793045343)
    assert k.sha(first)==a['sha256']
    with pytest.raises(SafetyError):k.archive_kit(args[-1],args[-1]/'nested.zip',1793045343)


@pytest.mark.parametrize('fault',['extra','changed','missing'])
def test_review_archive_refuses_drift_without_creating_zip(tmp_path,monkeypatch,fault):
    args,_=fixture(tmp_path,monkeypatch);k.main(*args)
    if fault=='extra':(args[-1]/'PRIVATE.json').write_bytes(b'SECRET')
    elif fault=='changed':(args[-1]/'ClaudeResetPreflight.exe').write_bytes(b'changed')
    else:(args[-1]/'Run-Preflight.cmd').unlink()
    output=tmp_path/'invalid.zip'
    with pytest.raises(SafetyError):k.archive_kit(args[-1],output,1793045343)
    assert not output.exists()
