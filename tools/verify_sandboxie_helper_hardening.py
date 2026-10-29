"""Exercise the prepared driver callback in a user-mode identity/lock harness."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--compiler', type=Path, default=ROOT/'work/toolchains/zig-pypi-0.13.0/ziglang/zig.exe')
parser.add_argument('--prepared-root', type=Path, default=ROOT/'work/sandboxie-helper-hardening')
args = parser.parse_args()
output = args.prepared_root
manifest = json.loads((output/'manifest.json').read_text())
for name, metadata in manifest['files'].items():
    data = (output/'prepared/Sandboxie/core/drv'/name).read_bytes()
    if hashlib.sha256(data).hexdigest() != metadata['prepared_sha256']:
        raise ValueError('Prepared driver file changed since manifest: ' + name)
source = (output/'prepared/Sandboxie/core/drv/obj_flt.c').read_text()
start = source.index('_FX OB_PREOP_CALLBACK_STATUS Obj_PreOperationCallback(')
end = source.index('// Obj_PostOperationCallback', start)
fragment = source[start:end]
(output/'HelperObjectCallbackUnderTest.inc').write_text(fragment)
token_source = (output/'prepared/Sandboxie/core/drv/thread_token.c').read_text()
token_hashes = {}
for name, destination in [('Thread_OpenProcessToken_Common', 'HelperProcessTokenUnderTest.inc'),
                          ('Thread_OpenThreadToken_Common', 'HelperThreadTokenUnderTest.inc')]:
    start = token_source.index('_FX NTSTATUS ' + name + '(')
    end = token_source.index('\n}\n', start) + 3
    token_fragment = token_source[start:end]
    (output/destination).write_text(token_fragment)
    token_hashes[name] = hashlib.sha256(token_fragment.encode()).hexdigest()
exe = output/'HelperDriverPolicyTests.exe'
env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(ROOT/'work/toolchains/zig-cache'))
build = subprocess.run([str(args.compiler), 'c++', '-std=c++17', '-fms-extensions', '-I'+str(output/'prepared/Sandboxie/core/drv'),
    '-I'+str(output), str(ROOT/'src/tests/native/HelperDriverPolicyTests.cpp'), '-lntdll', '-ladvapi32', '-o', str(exe)],
    capture_output=True, timeout=120, creationflags=0x08000000, env=env)
if build.returncode:
    raise RuntimeError(build.stderr.decode(errors='replace')[-6000:])
run = subprocess.run([str(exe)], capture_output=True, timeout=15, creationflags=0x08000000)
if run.returncode:
    raise RuntimeError(run.stderr.decode(errors='replace'))
result = json.loads(run.stdout)
result['callback_source_sha256'] = hashlib.sha256(fragment.encode()).hexdigest()
result['token_wrapper_sha256'] = token_hashes
result['prepared_files'] = manifest['files']
(output/'helper-driver-tests.json').write_text(json.dumps(result, indent=2))
print(json.dumps({k:v for k,v in result.items() if k != 'prepared_files'}))
token_exe = output/'HelperTokenAclWindowsTests.exe'
build = subprocess.run([str(args.compiler), 'c++', '-std=c++17', '-I'+str(output/'prepared/Sandboxie/core/drv'),
    str(ROOT/'src/tests/native/HelperTokenAclWindowsTests.cpp'), '-ladvapi32', '-lntdll', '-o', str(token_exe)],
    capture_output=True, timeout=120, creationflags=0x08000000, env=env)
if build.returncode: raise RuntimeError(build.stderr.decode(errors='replace')[-6000:])
run = subprocess.run([str(token_exe)], capture_output=True, timeout=15, creationflags=0x08000000)
if run.returncode: raise RuntimeError(run.stderr.decode(errors='replace'))
result = json.loads(run.stdout)
result['acl_source_sha256'] = hashlib.sha256((output/'prepared/Sandboxie/core/drv/CrHelperTokenAcl.h').read_bytes()).hexdigest()
(output/'windows-token-acl-result.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result))
