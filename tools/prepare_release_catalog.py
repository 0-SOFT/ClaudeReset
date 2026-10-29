"""Create an unsigned SHA-256 release-manifest catalog; never sign or install it.

This release metadata catalog is not a driver package catalog or kernel trust
submission. Approved publisher policy and authenticated preflight remain required.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from claude_reset.install_payload import PinnedPayload
from claude_reset.install_copy import _copy_pinned
from claude_reset.install_signature import inspect_signature
from claude_reset.windows_pin import PinnedFile
from claude_reset.safeio import SafetyError, guarded, local_volume

TOOL = 'Program Files/Windows Kits/10/bin/10.0.26100.0/x64/makecat.exe'
CDF = ('[CatalogHeader]\nName=release.cat\nCatalogVersion=2\nHashAlgorithms=SHA256\n'
       '[CatalogFiles]\n<HASH>release-manifest=release-manifest.json\n')


class Blob(C.Structure):
    _fields_ = [('size', W.DWORD), ('data', C.c_void_p)]


class Algorithm(C.Structure):
    _fields_ = [('oid', C.c_char_p), ('parameters', Blob)]


class Indirect(C.Structure):
    _fields_ = [('data', Algorithm), ('algorithm', Algorithm), ('digest', Blob)]


class Guid(C.Structure):
    _fields_ = [('a', W.DWORD), ('b', W.WORD), ('c', W.WORD), ('d', C.c_ubyte*8)]


class Member(C.Structure):
    _fields_ = [('size', W.DWORD), ('tag', W.LPWSTR), ('file', W.LPWSTR),
                ('subject', Guid), ('flags', W.DWORD), ('indirect', C.POINTER(Indirect)),
                ('version', W.DWORD), ('reserved', W.DWORD), ('handle', W.HANDLE),
                ('encoded_indirect', Blob), ('encoded_member', Blob)]


def verify_generated_member(path, expected):
    """Read back build output membership only; this does not authenticate it."""
    api = C.WinDLL('wintrust', use_last_error=True)
    for name, args, result in (
        ('CryptCATOpen', [W.LPWSTR, W.DWORD, W.HANDLE, W.DWORD, W.DWORD], W.HANDLE),
        ('CryptCATGetMemberInfo', [W.HANDLE, W.LPWSTR], C.POINTER(Member)),
        ('CryptCATClose', [W.HANDLE], W.BOOL),
    ):
        fn = getattr(api, name); fn.argtypes, fn.restype = args, result
    handle = api.CryptCATOpen(str(path), 4, None, 0, 0)
    if handle in (None, C.c_void_p(-1).value): raise SafetyError('Cannot read generated catalog')
    try:
        member = api.CryptCATGetMemberInfo(handle, expected.upper())
        if not member or member.contents.size < C.sizeof(Member) or not member.contents.indirect:
            raise SafetyError('Manifest absent from generated catalog')
        data = member.contents.indirect.contents
        if (data.algorithm.oid != b'2.16.840.1.101.3.4.2.1' or data.digest.size != 32
                or not data.digest.data or C.string_at(data.digest.data,32).hex() != expected):
            raise SafetyError('Generated catalog manifest digest differs')
    finally:
        if not api.CryptCATClose(handle): raise SafetyError('Cannot close generated catalog')


def main(bundle, expected, kit, output):
    bundle, kit, output = bundle.resolve(), kit.resolve(), output.resolve()
    guarded(local_volume(output), output.parent, allow_root=True)
    extraction = json.loads((kit.parent/'extraction-manifest.json').read_text('utf-8'))
    with PinnedFile(kit/TOOL, expected_sha256=extraction[TOOL]['sha256']) as tool:
        tool_signature = inspect_signature(tool)
        # Tool provenance comes from the separately verified pinned EWDK image;
        # OS trust alone is not a publisher allowlist for release components.
        with PinnedPayload(bundle, expected) as payload:
            output.mkdir(exist_ok=False)
            with _copy_pinned(payload.manifest, output/'release-manifest.json') as manifest:
                (output/'release.cdf').write_bytes(CDF.encode('ascii'))
                result = subprocess.run([str(tool.path), '-v', '-r', 'release.cdf'],
                    cwd=output, capture_output=True, timeout=120, creationflags=0x08000000)
                (output/'makecat.log').write_bytes(result.stdout+result.stderr)
                if result.returncode: raise SafetyError('MakeCat failed; inspect retained log')
                with PinnedFile(output/'release.cat', limit=1048576) as catalog:
                    verify_generated_member(catalog.path, manifest.sha256)
                    try: inspect_signature(catalog)
                    except SafetyError as error:
                        if '0x800b0100' not in str(error): raise
                        refusal = str(error)
                    else: raise SafetyError('Unexpected signed catalog from unsigned build')
                    receipt = {'schema':1, 'manifest_sha256':manifest.sha256,
                        'catalog_sha256':catalog.sha256, 'catalog_version':2,
                        'catalog_hash_algorithm':'SHA256', 'manifest_payload_files':len(payload.pins),
                        'manifest_membership_verified':True,
                        'tool_sha256':tool.sha256, 'tool_signature':tool_signature,
                        'cdf_sha256':hashlib.sha256(CDF.encode('ascii')).hexdigest(),
                        'signature_refusal':refusal, 'signed':False, 'installed':False,
                        'release_authority_verified':False, 'kernel_load_verified':False,
                        'installable':False, 'client_admission':False}
                    (output/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'output':str(output),'catalog_sha256':receipt['catalog_sha256'],
                      'signed':False,'installed':False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--kit', type=Path, default=ROOT/'work/toolchains/ewdk-26100.6584/extracted')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    main(args.bundle, args.expected_manifest_sha256, args.kit, args.output)
