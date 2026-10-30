"""The bundle carries every file the program reads at run time; the icon is a valid .ico."""
import importlib.util
import re
import struct
import subprocess
import tomllib
from pathlib import Path

import pytest

from claude_reset import __version__, config
from claude_reset.ui import brand

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('build_bundle', ROOT / 'tools/build_bundle.py')
build_bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_bundle)


def test_runtime_files_exist():
    missing = [p for p in build_bundle.RUNTIME if not (ROOT / p).exists()]
    assert not missing


def test_every_root_relative_path_in_the_code_is_bundled():
    used = set()
    for file in (ROOT / 'src/claude_reset').rglob('*.py'):
        used |= set(re.findall(r"ROOT / '([^']+)'", file.read_text(encoding='utf-8')))
    used |= {'packaging/identity'}  # package_isolation joins it in two parts
    used -= {'controller'}  # built into the bundle by build_controller, not copied
    covered = lambda path: any(path == p or path.startswith(p.rstrip('/') + '/') for p in build_bundle.RUNTIME)
    assert sorted(p for p in used if not covered(p) and not p.startswith('src')) == []
    assert all(covered(path) for _, path in __import__('claude_reset.ui.help_docs', fromlist=['DOCUMENTS']).DOCUMENTS.values())


def test_project_metadata_follows_the_program():
    project = tomllib.loads((ROOT / 'src/pyproject.toml').read_text(encoding='utf-8'))['project']
    assert project['version'] == __version__
    runtime = (ROOT / 'requirements-runtime.txt').read_text(encoding='utf-8').splitlines()
    assert set(project['dependencies']) <= set(runtime)


def test_icon_holds_every_size_as_png():
    data = brand.ico((16, 32, 256))
    reserved, kind, count = struct.unpack('<HHH', data[:6])
    assert (reserved, kind, count) == (0, 1, 3)
    for index, size in enumerate((16, 32, 256)):
        width, height, _, _, _, _, length, offset = struct.unpack('<BBBBHHII', data[6 + 16 * index:22 + 16 * index])
        assert (width, height) == (size % 256, size % 256)
        assert data[offset:offset + 8] == b'\x89PNG\r\n\x1a\n' and offset + length <= len(data)


@pytest.mark.skipif(not build_bundle.CSC.is_file(), reason='the .NET Framework C# compiler is not installed')
def test_installer_and_launcher_compile_with_the_product_names(tmp_path):
    product = build_bundle.product_source(tmp_path)
    assert f'"{config.PRODUCT_NAME}"' in product.read_text('utf-8') and f'"{config.PUBLISHER}"' in product.read_text('utf-8')
    for source in ('ClaudeResetLauncher.cs', 'ClaudeResetSetup.cs'):
        result = subprocess.run([str(build_bundle.CSC), '/nologo', '/target:winexe', '/codepage:65001',
                                 '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll',
                                 '/r:System.IO.Compression.FileSystem.dll', '/out:' + str(tmp_path / (source + '.exe')),
                                 str(product), str(ROOT / 'packaging/bundle' / source)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout[-800:]
        text = (ROOT / 'packaging/bundle' / source).read_text('utf-8')
        assert not [line for line in text.splitlines() if '"ClaudeReset' in line or "0-soft\"" in line]
