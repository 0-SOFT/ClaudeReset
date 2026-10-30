import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

import pytest

from claude_reset.ui import help_docs

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('gui_source_inventory', ROOT / 'tools/prepare_gui_source_inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def test_source_inventory_hashes_sbom_and_bundled_help(tmp_path):
    output = tmp_path / 'review'
    result = inventory.prepare(ROOT, ['src/claude_reset/ui/help_docs.py'], output)
    assert result['release_ready'] is False
    for name, digest in result['sha256'].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    manifest = json.loads((output / 'source-files.json').read_text('utf-8'))
    sbom = json.loads((output / 'source.spdx.json').read_text('utf-8'))
    assert len(sbom['packages']) == result['declared_dependencies'] + 1
    assert all(p['licenseConcluded'] == 'NOASSERTION' for p in sbom['packages'])
    assert len(sbom['files']) == result['files']
    with zipfile.ZipFile(output / 'gui-source-review.zip') as archive:
        assert set(archive.namelist()) == {r['path'] for r in manifest['files']}
        for row, entry in zip(manifest['files'], sbom['files']):
            data = archive.read(row['path'])
            assert hashlib.sha256(data).hexdigest() == row['sha256'] == entry['checksums'][0]['checksumValue']
            assert len(data) == row['bytes']
        archive.extractall(tmp_path / 'unpacked')
    for kind in help_docs.DOCUMENTS:
        assert help_docs.read_document(kind, root=tmp_path / 'unpacked')[1].strip()


def test_missing_source_refuses_before_output(tmp_path):
    with pytest.raises(ValueError, match='неполон'):
        inventory.prepare(tmp_path, [], tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_existing_output_not_overwritten(tmp_path):
    with pytest.raises(FileExistsError):
        inventory.prepare(ROOT, [], tmp_path)
