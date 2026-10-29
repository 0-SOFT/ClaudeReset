"""Test separated signature verification using an ephemeral, never-exported private key."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
from prepare_runtime_trust import prepare, RELATIVE, SERVICE_RELATIVE, validate_public_key

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=120, creationflags=0x08000000, **kwargs)
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr).decode(errors='replace')[-4000:])
    return result.stdout


def main():
    folder = ROOT / 'work/release-execution-2026-10-26' / ('runtime-trust-fixture-' + uuid.uuid4().hex)
    folder.mkdir()
    generator = folder / 'EphemeralKey.cs'
    generator.write_text('''using System;using System.IO;using System.Security.Cryptography;
class EphemeralKey {static void Main(string[] args) {
  byte[] data=System.Text.Encoding.ASCII.GetBytes("ClaudeReset synthetic signing fixture only");
  using(var key=new ECDsaCng(256))using(var hash=SHA256.Create()) {
    File.WriteAllBytes(Path.Combine(args[0],"public.blob"),key.Key.Export(CngKeyBlobFormat.EccPublicBlob));
    File.WriteAllBytes(Path.Combine(args[0],"payload.bin"),data);
    File.WriteAllBytes(Path.Combine(args[0],"signature.bin"),key.SignHash(hash.ComputeHash(data)));
  }
}}''', encoding='utf-8')
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    exe = folder / 'EphemeralKey.exe'
    run([compiler, '/nologo', '/out:' + str(exe), generator])
    run([exe, folder])
    public = folder / 'public.blob'
    source = ROOT / 'work/dependencies/sandboxie-v1.18.8/source'
    output = folder / 'prepared-trust'
    prepare(source, output, public, hashlib.sha256(public.read_bytes()).hexdigest())
    original = (source / RELATIVE).read_text(encoding='utf-8-sig')
    changed = (output / 'prepared' / RELATIVE).read_text(encoding='utf-8')
    service = (output / 'prepared' / SERVICE_RELATIVE).read_text(encoding='utf-8')
    service_key = re.search(r'static UCHAR CrRuntimePublicKey\[\].*?\};', service, re.S).group()
    service_verifier = service[service.index('static NTSTATUS VerifyHashSignature('):service.index('NTSTATUS VerifyFileSignature(')]
    service_key = service_key.replace('CrRuntimePublicKey', 'CrServiceRuntimePublicKey')
    service_verifier = service_verifier.replace('CrRuntimePublicKey', 'CrServiceRuntimePublicKey')
    vendor_start = original.index('NTSTATUS KphVerifySignature(')
    file_start = original.index('NTSTATUS KphVerifyFile(')
    assert original[vendor_start:file_start] in changed
    assert original[original.index('NTSTATUS KphVerifyBuffer('):] == changed[changed.index('NTSTATUS KphVerifyBuffer('):]
    run(['git', 'apply', '--check', output / 'runtime-trust.patch'], cwd=source)
    for invalid in (b'', public.read_bytes()+b'private', b'ECS2'+public.read_bytes()[4:], b'ECS1'+b'\0'*68,
                    public.read_bytes()[:8]+bytes(64)):
        try: validate_public_key(invalid)
        except ValueError: pass
        else: raise AssertionError('Invalid/private blob accepted')
    vendor_key = re.search(r'static const UCHAR KphpTrustedPublicKey\[\]\s*=\s*\{.*?\};', original, re.S).group()
    runtime = changed[changed.index('static const UCHAR CrRuntimePublicKey'):changed.index('NTSTATUS KphVerifyFile(')]
    digest = hashlib.sha256((folder / 'payload.bin').read_bytes()).digest()
    test = folder / 'SignatureTests.c'
    test.write_text('''#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#define NT_SUCCESS(s) (((LONG)(s))>=0)
#define KPH_SIGN_ALGORITHM BCRYPT_ECDSA_P256_ALGORITHM
#define KPH_BLOB_PUBLIC BCRYPT_ECCPUBLIC_BLOB
#define CST_SIGN_ALGORITHM BCRYPT_ECDSA_P256_ALGORITHM
#define CST_BLOB_PUBLIC BCRYPT_ECCPUBLIC_BLOB
''' + vendor_key + '\n' + original[vendor_start:file_start] + runtime + service_key + service_verifier + '''
int main(int argc,char** argv) {
  if(argc!=2)return 10;
  FILE* input=fopen(argv[1],"rb");if(!input)return 10;
  unsigned char signature[65];size_t length=fread(signature,1,65,input);fclose(input);
  unsigned char hash[]={''' + ','.join(str(v) for v in digest) + '''};
  if(length!=64)return 11;
  if(!NT_SUCCESS(KphVerifyRuntimeSignature(hash,32,signature,64)))return 12;
  if(NT_SUCCESS(KphVerifySignature(hash,32,signature,64)))return 13;
  if(!NT_SUCCESS(VerifyHashSignature(hash,32,signature,64)))return 17;
  hash[0]^=1;if(NT_SUCCESS(KphVerifyRuntimeSignature(hash,32,signature,64)))return 14;
  if(NT_SUCCESS(VerifyHashSignature(hash,32,signature,64)))return 18;
  hash[0]^=1;signature[0]^=1;if(NT_SUCCESS(KphVerifyRuntimeSignature(hash,32,signature,64)))return 15;
  if(NT_SUCCESS(VerifyHashSignature(hash,32,signature,64)))return 19;
  if(NT_SUCCESS(KphVerifyRuntimeSignature(hash,32,signature,63)))return 16;
  if(NT_SUCCESS(VerifyHashSignature(hash,32,signature,63)))return 20;
  puts("{\\"passed\\":true,\\"checks\\":9}");return 0;
}
''', encoding='utf-8')
    zig = ROOT / 'work/toolchains/zig-pypi-0.13.0/ziglang/zig.exe'
    tested = folder / 'SignatureTests.exe'
    run([zig, 'cc', '-std=c11', test, '-lbcrypt', '-o', tested], env=dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(ROOT / 'work/toolchains/zig-cache')))
    checks = json.loads(run([tested, folder / 'signature.bin']))
    report = {'schema': 1, 'passed': checks['passed'], 'native_cng_checks': checks['checks'],
        'vendor_certificate_verifier_unchanged': True, 'patch_check': True,
        'private_key_exported': False, 'test_key_only': True, 'production_key_selected': False,
        'driver_loaded': False, 'windows_driver_signature_supplied': False,
        'fixture': str(folder), 'generator_sha256': hashlib.sha256((ROOT / 'tools/prepare_runtime_trust.py').read_bytes()).hexdigest()}
    (folder.parent / 'runtime-trust-verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__': main()
