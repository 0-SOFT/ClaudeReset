"""Collect exact installed toolchain license texts, independently of old releases."""
import argparse
import base64
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def verify_frozen_python(executable):
    from PyInstaller.archive.readers import CArchiveReader
    base=Path(sys.base_prefix)
    library=(base/'PCbuild/amd64/python312.dll' if sys.version_info[:3]==(3,12,16)
             else base/'python312.dll')
    expected=hashlib.sha256(library.read_bytes()).hexdigest()
    archive=CArchiveReader(str(executable))
    embedded=archive.extract('python312.dll')
    if hashlib.sha256(embedded).hexdigest()!=expected:
        raise RuntimeError('Frozen Python library differs from the selected build runtime')
    import ssl
    native={}
    folder=base/'PCbuild/amd64' if sys.version_info[:3]==(3,12,16) else base/'DLLs'
    for name in ('_ssl.pyd','_hashlib.pyd','libcrypto-3.dll','libssl-3.dll'):
        digest=hashlib.sha256((folder/name).read_bytes()).hexdigest()
        if hashlib.sha256(archive.extract(name)).hexdigest()!=digest:
            raise RuntimeError('Frozen cryptographic runtime differs: '+name)
        native[name]=digest
    return {'version':sys.version,'python_dll_sha256':expected,
            'openssl_version':ssl.OPENSSL_VERSION,'cryptographic_runtime_sha256':native,
            'cryptographic_runtime_matches':True,
            'base_executable_sha256':hashlib.sha256(Path(sys._base_executable).read_bytes()).hexdigest(),
            'frozen_library_matches':True}


def verify_python_layout(dependency_root=None):
    version=sys.version_info[:3]
    if version not in ((3,12,10),(3,12,16)):raise RuntimeError('Unreviewed Python toolchain version')
    base=Path(sys.base_prefix)
    if version==(3,12,16):
        dependencies=(dependency_root or ROOT/'work/dependencies').resolve()
        expected={(dependencies/name/'source').resolve()
                  for name in ('Python-3.12.16','Python-3.12.16-openssl359')}
        if base.resolve() not in expected:raise RuntimeError('Unreviewed security runtime layout')
    return base


def collect(output,*,dependency_root=None):
    output = output.resolve()
    if output.exists(): raise RuntimeError('Choose a fresh license output')
    base=verify_python_layout(dependency_root)
    version=sys.version_info[:3]
    inputs = {}; distributions = []
    for line in (ROOT/'requirements-lock.txt').read_text('utf-8').splitlines():
        if not line or line.startswith('#'): continue
        name, expected = line.split('==')
        dist = metadata.distribution(name)
        if dist.version != expected: raise RuntimeError('Installed build dependency version differs: '+name)
        licenses = [f for f in dist.files or []
                    if re.match(r'(?i)^(license|copying|copyright|notice)(?:[._-].*)?$',Path(f).name)]
        if not licenses: raise RuntimeError('Installed package has no license text: '+name)
        for index, entry in enumerate(licenses):
            path = Path(dist.locate_file(entry))
            data = path.read_bytes()
            if entry.hash and entry.hash.mode == 'sha256':
                actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
                if actual != entry.hash.value: raise RuntimeError('Installed license differs from RECORD: '+name)
            inputs[name+'/'+str(index)+'-'+path.name] = data
        distributions.append({'name':name,'version':dist.version,'license_files':len(licenses)})
    if version==(3,12,16):
        inputs['Python/LICENSE.txt'] = (base/'PCbuild/amd64/LICENSE.txt').read_bytes()
        for label in ('tcl','tk','tix'):
            inputs[label+'/license.terms'] = (base/'externals/tcltk-8.6.15.2/amd64'/(label+'license.terms')).read_bytes()
        if base.parent.name.endswith('-openssl359'):
            inputs['OpenSSL/LICENSE.txt']=(base/'externals/openssl-bin-3.5.9/amd64/LICENSE.txt').read_bytes()
    else:
        inputs['Python/LICENSE.txt'] = (base/'LICENSE.txt').read_bytes()
        inputs['Tk/license.terms'] = (base/'tcl/tk8.6/license.terms').read_bytes()
    output.mkdir(parents=True)
    hashes = {}
    for name, data in sorted(inputs.items()):
        path = output/name; path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data); hashes[name] = hashlib.sha256(data).hexdigest()
    result = {'schema':1,'python':sys.version,'distributions':distributions,
              'license_sha256':hashes,'installed_license_inventory_complete':True,
              'old_release_files_used':False,'full_dependency_compliance_review':False,
              'limits':['Includes pinned build/test tools as well as runtime dependencies.',
                        'Installed license inventory does not replace corresponding source delivery.']}
    (output/'manifest.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--dependency-root',type=Path,help='Explicit dependency cache for the active reviewed interpreter')
    args=parser.parse_args();result=collect(args.output,dependency_root=args.dependency_root)
    print(json.dumps({'license_files':len(result['license_sha256']),'old_release_files_used':False}))
