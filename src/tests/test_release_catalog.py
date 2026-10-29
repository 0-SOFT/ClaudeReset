import importlib.util
from pathlib import Path
import hashlib
import json
import subprocess
import pytest
from claude_reset.safeio import SafetyError
from claude_reset.windows_pin import PinnedFile
from claude_reset.install_signature import inspect_signature

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_release_catalog', ROOT/'tools/prepare_release_catalog.py')
catalog = importlib.util.module_from_spec(spec); spec.loader.exec_module(catalog)


def generate(tmp_path,manifest=b'{"fixture":true}\n',*,sha1=False):
    kit = ROOT/'work/toolchains/ewdk-26100.6584/extracted'
    if not (kit/catalog.TOOL).exists(): pytest.skip('Pinned EWDK fixture unavailable')
    extraction = json.loads((kit.parent/'extraction-manifest.json').read_text('utf-8'))
    (tmp_path/'release-manifest.json').write_bytes(manifest)
    cdf=catalog.CDF
    if sha1:cdf=cdf.replace('CatalogVersion=2','CatalogVersion=1').replace('SHA256','SHA1')
    (tmp_path/'release.cdf').write_bytes(cdf.encode('ascii'))
    with PinnedFile(kit/catalog.TOOL, expected_sha256=extraction[catalog.TOOL]['sha256']) as tool:
        inspect_signature(tool)
        result = subprocess.run([str(tool.path), '-v', '-r', 'release.cdf'], cwd=tmp_path,
                                capture_output=True, timeout=30, creationflags=0x08000000)
        assert result.returncode == 0, result.stdout+result.stderr
    return tmp_path/'release.cat', hashlib.sha256(manifest).hexdigest()


@pytest.fixture
def generated(tmp_path):return generate(tmp_path)


def test_native_catalog_exact_sha256_membership(generated):
    path, digest = generated
    catalog.verify_generated_member(path, digest)
    with PinnedFile(path, limit=1048576) as pin:
        with pytest.raises(SafetyError, match='0x800b0100'): inspect_signature(pin)


def test_native_catalog_rejects_different_manifest(generated):
    path, _ = generated
    with pytest.raises(SafetyError, match='absent'): catalog.verify_generated_member(path, '0'*64)
    # Read-only member query closes its catalog handle even after rejection.
    path.unlink()


def test_native_catalog_rejects_non_catalog(tmp_path):
    path = tmp_path/'invalid.cat'; path.write_bytes(b'not a catalog')
    with pytest.raises(SafetyError, match='Cannot read'): catalog.verify_generated_member(path, '0'*64)
