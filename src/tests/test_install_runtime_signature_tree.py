"""Real held sidecar trees and real CNG; no installed files or signing authority."""
import hashlib
import pytest
from claude_reset import install_runtime_signature as runtime
from claude_reset.safeio import SafetyError
from test_install_runtime_signature import signed
from test_install_runtime_signature_set import fixture


def tree(tmp_path,signed):
    root=tmp_path/'runtime-signatures';root.mkdir()
    (root/'runtime-public-key.blob').write_bytes(signed['key'])
    hashes={}
    for name in runtime.RUNTIME_IMAGES:
        path=root/(name+'.sig');path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(signed['signature']);hashes[name]=hashlib.sha256(signed['signature']).hexdigest()
    return root,hashlib.sha256(signed['key']).hexdigest(),hashes


def test_tree_holds_every_input_and_verifies_complete_set(tmp_path,monkeypatch,signed):
    args=tree(tmp_path,signed)
    with fixture(tmp_path,monkeypatch,signed) as inputs:
        with runtime.PinnedRuntimeSignatures(*args) as held:
            row=held.inspect(inputs[0])
            assert row['complete_signature_set_verified'] is True
            assert row['key_authority_verified'] is False
            assert row['staged_sidecars_verified'] is False
            for path in args[0].rglob('*'):
                if path.is_file():
                    with pytest.raises(OSError):path.write_bytes(b'changed')
        for path in args[0].rglob('*'):
            if path.is_file():path.write_bytes(b'released')


@pytest.mark.parametrize('fault',['missing','extra-file','extra-dir','wrong-name','short-key',
    'large-key','short-signature','large-signature','wrong-key-digest','wrong-signature-digest',
    'missing-digest','extra-digest','uppercase-digest'])
def test_invalid_tree_releases_all_acquired_inputs(tmp_path,signed,fault):
    root,key,hashes=tree(tmp_path,signed)
    name=sorted(runtime.RUNTIME_IMAGES)[-1];path=root/(name+'.sig')
    if fault=='missing':path.unlink()
    if fault=='extra-file':(root/'unexpected.sig').write_bytes(b'x')
    if fault=='extra-dir':(root/'unexpected').mkdir()
    if fault=='wrong-name':path.rename(path.with_suffix('.SIG'))
    if fault=='short-key':
        (root/'runtime-public-key.blob').write_bytes(b'x');key=hashlib.sha256(b'x').hexdigest()
    if fault=='large-key':(root/'runtime-public-key.blob').write_bytes(b'x'*73)
    if fault=='short-signature':path.write_bytes(b'x');hashes[name]=hashlib.sha256(b'x').hexdigest()
    if fault=='large-signature':path.write_bytes(b'x'*65)
    if fault=='wrong-key-digest':key='f'*64
    if fault=='wrong-signature-digest':hashes[name]='f'*64
    if fault=='missing-digest':hashes.pop(name)
    if fault=='extra-digest':hashes['unknown.exe']='f'*64
    if fault=='uppercase-digest':hashes[name]='A'*64
    with pytest.raises(SafetyError):runtime.PinnedRuntimeSignatures(root,key,hashes)
    # Failed acquisition must leave no sharing lock behind, even on earlier files.
    for path in root.rglob('*'):
        if path.is_file():path.write_bytes(b'released')


def test_extra_file_added_during_signature_verification_is_refused(tmp_path,monkeypatch,signed):
    args=tree(tmp_path,signed)
    with fixture(tmp_path,monkeypatch,signed) as inputs,runtime.PinnedRuntimeSignatures(*args) as held:
        verify=runtime.inspect_runtime_signature_set
        def inspect(*values):
            row=verify(*values)
            (args[0]/'late.sig').write_bytes(b'x')
            return row
        monkeypatch.setattr(runtime,'inspect_runtime_signature_set',inspect)
        with pytest.raises(SafetyError,match='Unexpected'):held.inspect(inputs[0])


def test_closed_tree_cannot_reuse_prior_evidence(tmp_path,monkeypatch,signed):
    args=tree(tmp_path,signed)
    with fixture(tmp_path,monkeypatch,signed) as inputs:
        with runtime.PinnedRuntimeSignatures(*args) as held:held.inspect(inputs[0])
        with pytest.raises(SafetyError):held.inspect(inputs[0])
