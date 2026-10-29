import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from test_runtime_trust_preparation import fixture as source_fixture, tool as preparation

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native_candidate_tool', ROOT / 'tools/package_native_candidate.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def fixture(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'tools'))
    source, combined, key, digest = source_fixture(tmp_path, monkeypatch)
    metadata = preparation.prepare(source, combined / 'runtime-trust', key, digest)
    expected = {preparation.RELATIVE: metadata['prepared_sha256'],
                preparation.SERVICE_RELATIVE: metadata['service_prepared_sha256']}
    receipt = dict(runtime_public_key_sha256=digest, runtime_key_authority_verified=False,
                   changes={name: dict(layer='runtime-trust', prepared_sha256=value)
                            for name, value in expected.items()})
    return combined, expected, receipt


def test_both_verifiers_and_public_provenance_retained(tmp_path, monkeypatch):
    args = fixture(tmp_path, monkeypatch)
    files, digest = tool.runtime_trust_evidence(*args)
    assert digest == args[2]['runtime_public_key_sha256']
    assert {path.name for path in files} == {'manifest.json', 'runtime-public-key.blob'}


def test_default_upstream_has_no_selected_key(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'tools'))
    assert tool.runtime_trust_evidence(tmp_path, {}, {'changes': {}}) == ([], None)


@pytest.mark.parametrize('fault', ['only-driver', 'only-service', 'no-verifiers', 'wrong-digest',
    'authority', 'metadata-authority', 'metadata-mismatch', 'service-source', 'driver-source',
    'private-key', 'different-embedded-key', 'duplicate-array', 'extra-field', 'installed-claim', 'signature-claim'])
def test_incomplete_or_changed_evidence_refused(tmp_path, monkeypatch, fault):
    combined, expected, receipt = fixture(tmp_path, monkeypatch)
    folder = combined / 'runtime-trust'
    metadata_path = folder / 'manifest.json'
    metadata = json.loads(metadata_path.read_text())
    if fault == 'only-driver': receipt['changes'].pop(preparation.SERVICE_RELATIVE)
    elif fault == 'only-service': receipt['changes'].pop(preparation.RELATIVE)
    elif fault == 'no-verifiers': receipt['changes'] = {}
    elif fault == 'wrong-digest': receipt['runtime_public_key_sha256'] = '0' * 64
    elif fault == 'authority': receipt['runtime_key_authority_verified'] = True
    elif fault == 'metadata-authority': metadata['key_authority_verified'] = True
    elif fault == 'metadata-mismatch': metadata['service_runtime_key_matches_driver'] = False
    elif fault == 'extra-field': metadata['unexpected'] = 'not copied'
    elif fault == 'installed-claim': metadata['installed'] = True
    elif fault == 'signature-claim': metadata['runtime_signatures_supplied'] = True
    elif fault in ('service-source', 'driver-source'):
        name = preparation.RELATIVE if fault == 'driver-source' else preparation.SERVICE_RELATIVE
        (folder / 'prepared' / name).write_bytes(b'changed')
    elif fault == 'private-key':
        public = folder / 'runtime-public-key.blob'
        public.write_bytes(b'ECS2' + public.read_bytes()[4:])
    elif fault in ('different-embedded-key', 'duplicate-array'):
        # Even internally consistent metadata hashes must not claim that a
        # different source array is the supplied public key.
        name = preparation.SERVICE_RELATIVE
        path = folder / 'prepared' / name
        text = path.read_text()
        if fault == 'different-embedded-key': text = text.replace('0x45', '0x46', 1)
        else: text += '\n' + text
        path.write_bytes(text.encode())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        metadata['service_prepared_sha256'] = expected[name] = digest
        receipt['changes'][name]['prepared_sha256'] = digest
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises((RuntimeError, ValueError)):
        tool.runtime_trust_evidence(combined, expected, receipt)
