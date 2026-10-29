"""Package pinned upstream sources, actual Go module sources and native patches."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path): return json.loads(path.read_text('utf-8'))


def license_document_name(name):
    """License filename candidates, excluding directories and source-code files.

    A matching filename is not a license conclusion or redistribution approval.
    In particular, Go's license_test.go is a test, not a license document.
    """
    if name.endswith('/') or Path(name).suffix.lower() in {
            '.go','.py','.c','.h','.cc','.cpp','.hpp','.cs','.js','.jsx','.ts','.tsx',
            '.mjs','.cjs','.rs','.java','.sh','.ps1'}:
        return False
    return re.fullmatch(r'(?i)(license|copying|copyright|notice)(?:[._-].*)?',Path(name).name) is not None


def module_hash(path):
    """Go's documented dirhash.Hash1: sorted name/content SHA-256 summary."""
    digest = hashlib.sha256()
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(set(names)) != len(names) or any('\n' in n for n in names):
            raise RuntimeError('Ambiguous module archive')
        if sum(i.file_size for i in archive.infolist()) > 1024*1024*1024:
            raise RuntimeError('Module archive exceeds bounded source size')
        for name in sorted(names):
            with archive.open(name) as stream: item = hashlib.file_digest(stream, 'sha256').hexdigest()
            digest.update((item+'  '+name+'\n').encode('utf-8'))
    return 'h1:'+base64.b64encode(digest.digest()).decode('ascii')


def main(go, modules, combined, output, openssl_lts=False, *, dependency_root=None):
    dependencies = (dependency_root or ROOT/"work/dependencies").resolve()
    modules, combined, output = (p.resolve() for p in (modules, combined, output))
    if output.exists(): raise RuntimeError('Preserve existing source packages')
    engine_lock = read(ROOT/'third_party/sources/sing-box-lock.json')
    native_lock = read(ROOT/'third_party/sources/sandboxie-lock.json')
    go_lock = read(ROOT/'third_party/sources/go-source-lock.json')
    python_lock = read(ROOT/'third_party/sources/python-source-lock.json')
    python_native_lock = read(ROOT/'third_party/sources/cpython-native-source-lock.json')
    security_lock = read(ROOT/'third_party/sources/python-security-candidate-lock.json')
    security_binaries = read(ROOT/'third_party/sources/python-security-build-binaries-lock.json')
    security_root = dependencies/(security_lock['version']+'-openssl359' if openssl_lts else security_lock['version'])
    if openssl_lts:
        openssl_lock=read(ROOT/'third_party/sources/openssl-lts-lock.json')
        security_binaries['archives']=[r for r in security_binaries['archives'] if not r['tag'].startswith('openssl-bin-')]+[openssl_lock['binary']]
    dep = dependencies/('sing-box-'+engine_lock['version'])
    exe = dep/'extracted'/('sing-box-'+engine_lock['version']+'-windows-amd64')/'sing-box.exe'
    if sha(exe) != engine_lock['executable_sha256']: raise RuntimeError('Engine hash differs')
    build = json.loads(subprocess.check_output([str(go),'version','-m','-json',str(exe)]))
    inventory = read(modules/'source-inventory.json')
    actual = sorted(build['Deps'], key=lambda row: row['Path'])
    if ([r['module'] for r in inventory['modules']] != actual
            or inventory['all_module_sources_verified'] is not True
            or build['GoVersion'] != go_lock['version']):
        raise RuntimeError('Sources do not cover actual linked module identities')
    inputs = {
        'upstream/Sandboxie-'+native_lock['commit']+'.zip':(
            dependencies/'sandboxie-v1.18.8/upstream.zip',native_lock['archive_sha256']),
        'upstream/sing-box-'+engine_lock['source_commit']+'.zip':(
            dep/engine_lock['source_archive'],engine_lock['source_sha256']),
        'upstream/'+go_lock['filename']:(dependencies/go_lock['version']/go_lock['filename'],go_lock['sha256']),
        'upstream/'+python_lock['filename']:(dependencies/python_lock['version']/python_lock['filename'],python_lock['sha256']),
        'upstream/'+security_lock['filename']:(security_root/security_lock['filename'],security_lock['sha256']),
    }
    if openssl_lts:
        item=openssl_lock['source']
        inputs['upstream/'+item['file']]=(dependencies/'openssl-3.5.9'/item['file'],item['sha256'])
        inputs['locks/openssl-lts-lock.json']=(ROOT/'third_party/sources/openssl-lts-lock.json',sha(ROOT/'third_party/sources/openssl-lts-lock.json'))
    for row in security_binaries['archives']:
        if not re.fullmatch(r'[A-Za-z0-9._-]+',row['file']):raise RuntimeError('Invalid Python build archive name')
        inputs['cpython-build-binaries/'+row['file']] = (security_root/'build-dependency-archives'/row['file'],row['sha256'])
    for name in ('effective-source-manifest.json','regenerated-source-delta.json','build-dependency-manifest.json'):
        inputs['cpython-build-inputs/'+name]=(security_root/name,sha(security_root/name))
    for name,row in read(security_root/'regenerated-source-delta.json').items():
        if Path(name).is_absolute() or '..' in Path(name).parts or ':' in name:raise RuntimeError('Invalid regenerated source path')
        inputs['cpython-build-inputs/regenerated/'+name]=(security_root/'source'/name,row['after'])
    python_sources = dependencies/'python-locked-sources'
    python_inventory = read(python_sources/'source-inventory.json')
    if python_inventory['requirements_sha256'] != sha(ROOT/'requirements-lock.txt'):
        raise RuntimeError('Python source inventory does not match current dependency lock')
    wanted = [line.split('==') for line in (ROOT/'requirements-lock.txt').read_text('utf-8').splitlines()
              if line and not line.startswith('#')]
    if [[r['name'],r['version']] for r in python_inventory['sources']] != wanted:
        raise RuntimeError('Incomplete Python source inventory')
    for row in python_inventory['sources']:
        if not re.fullmatch(r'[A-Za-z0-9._-]+',row['file']): raise RuntimeError('Unsafe Python source filename')
        inputs['python-packages/'+row['file']] = (python_sources/row['file'],row['sha256'])
    native_sources = dependencies/'cpython-native-sources'
    native_inventory = read(native_sources/'source-inventory.json')
    if [{k:r[k] for k in ('name','version','url','sha256')} for r in native_inventory['sources']] != python_native_lock['source_archives']:
        raise RuntimeError('Incomplete CPython native source inventory')
    for row in native_inventory['sources']:
        if not re.fullmatch(r'[a-f0-9]{64}\.(?:zip|tar\.gz)',row['file']): raise RuntimeError('Unsafe native source filename')
        inputs['cpython-native/'+row['file']] = (native_sources/row['file'],row['sha256'])
    inputs['inventory/python-sources.json'] = (python_sources/'source-inventory.json',sha(python_sources/'source-inventory.json'))
    inputs['inventory/cpython-native-sources.json'] = (native_sources/'source-inventory.json',sha(native_sources/'source-inventory.json'))
    licenses = []; missing = []
    for row in inventory['modules']:
        name = row['archive']
        if not re.fullmatch(r'archives/[a-f0-9]{64}\.zip', name): raise RuntimeError('Invalid module archive path')
        source = modules/name
        if row['verified'] is not True or module_hash(source) != row['module']['Sum']:
            raise RuntimeError('Actual archive differs from embedded Go module checksum')
        inputs['go-modules/'+Path(name).name] = (source, row['sha256'])
        with zipfile.ZipFile(source) as archive:
            names = [n for n in archive.namelist() if license_document_name(n)]
            if not names: missing.append(row['module']['Path'])
            for entry in names:
                if archive.getinfo(entry).file_size > 4*1024*1024: raise RuntimeError('Oversized license entry')
                licenses.append({'module':row['module']['Path'], 'archive': 'go-modules/'+Path(name).name,
                                 'entry':entry, 'sha256':hashlib.sha256(archive.read(entry)).hexdigest()})
    for name in ('combined.patch','combined-receipt.json','source-manifest.json'):
        inputs['native-hardening/'+name] = (combined/name,sha(combined/name))
    for name in ('source-inventory.json','engine-buildinfo.json'):
        inputs['inventory/'+name] = (modules/name,sha(modules/name))
    for name in ('sing-box-lock.json','sandboxie-lock.json','go-source-lock.json','ewdk-lock.json',
                 'python-source-lock.json','cpython-native-source-lock.json',
                 'sandboxie-managed-config-lock.json','sandboxie-wfp-lifecycle-lock.json'):
        path = ROOT/'third_party/sources'/name
        if path.exists(): inputs['locks/'+name] = (path,sha(path))
    for name in ('python-security-candidate-lock.json','python-security-build-binaries-lock.json'):
        path=ROOT/'third_party/sources'/name;inputs['locks/'+name]=(path,sha(path))
    for source, expected in inputs.values():
        if source.is_symlink() or getattr(source.lstat(),'st_file_attributes',0)&0x400 or sha(source)!=expected:
            raise RuntimeError('Source archive identity changed')
    metadata = {'schema':1, 'kind':'dependency_source_supplement',
        'engine_sha256':engine_lock['executable_sha256'], 'go_modules':len(actual),
        'python_source_distributions':len(python_inventory['sources']),
        'cpython_native_source_archives':len(native_inventory['sources']),
        'python_versions':['3.12.10','3.12.16'],
        'python_runtime_dll_sha256':sha(security_root/'source/PCbuild/amd64/python312.dll'),
        'python_cryptographic_runtime_sha256':{name:sha(security_root/'source/PCbuild/amd64'/name)
            for name in ('_ssl.pyd','_hashlib.pyd','libcrypto-3.dll','libssl-3.dll')},
        'openssl_lts_override':openssl_lts,
        'module_content_checksums_reverified':True, 'license_entries':licenses,
        'modules_without_license_filename':missing, 'license_review_complete':False,
        'native_source_manifest_sha256':sha(combined/'source-manifest.json'),
        'files':{name:{'sha256':digest,'bytes':path.stat().st_size} for name,(path,digest) in inputs.items()},
        'limits':['Use with the matching reviewed development source archive and build scripts.',
                  'Does not include proprietary Microsoft EWDK; obtain the pinned toolchain separately.',
                  'Complete license review, installed wheel provenance and bit reproducibility remain open.',
                  'No private runtime signing key or trusted production kernel signature is included.']}
    output.mkdir(parents=True)
    target = output/'dependency-sources.zip'
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_STORED) as archive:
        for name,(source,_) in sorted(inputs.items()): archive.write(source,name)
        archive.writestr('source-package.json',json.dumps(metadata,indent=2))
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(inputs)|{'source-package.json'}:
            raise RuntimeError('Source package integrity differs')
    (output/'source-package.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    receipt = {'sha256':sha(target),'bytes':target.stat().st_size,'go_modules':len(actual),
               'license_entries':len(licenses),'modules_without_license_filename':len(missing),
               'license_review_complete':False}
    (output/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(receipt))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('go','modules','combined','output'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--openssl-lts',action='store_true')
    parser.add_argument('--dependency-root',type=Path,help='Pinned dependency cache; repository locks remain authoritative')
    args=parser.parse_args();main(args.go,args.modules,args.combined,args.output,args.openssl_lts,dependency_root=args.dependency_root)
