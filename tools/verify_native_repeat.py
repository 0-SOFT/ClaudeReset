"""Compare two clean build results without mistaking timestamp drift for source drift."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import uuid
import pefile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe_details(path):
    """Diagnostics only: matching code sections are not binary equivalence."""
    data=path.read_bytes();pe=pefile.PE(data=data)
    try:
        debug=[]
        for entry in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
            start,size=entry.struct.PointerToRawData,entry.struct.SizeOfData
            if start+size>len(data):raise RuntimeError('Debug record exceeds built PE file')
            raw=data[start:start+size]
            row={'type':entry.struct.Type,'timestamp':entry.struct.TimeDateStamp,
                 'bytes':size,'sha256':hashlib.sha256(raw).hexdigest()}
            if raw.startswith(b'RSDS') and len(raw)>=24:
                row.update(pdb_guid=str(uuid.UUID(bytes_le=raw[4:20])),
                           pdb_age=struct.unpack_from('<I',raw,20)[0],
                           pdb_path=raw[24:].split(b'\0',1)[0].decode('utf-8',errors='replace'))
            debug.append(row)
        return {'timestamp':pe.FILE_HEADER.TimeDateStamp,'checksum':pe.OPTIONAL_HEADER.CheckSum,
                'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'debug':debug,
                'sections':[{'name':s.Name.rstrip(b'\0').decode('ascii',errors='replace'),
                    'rva':s.VirtualAddress,'raw_bytes':s.SizeOfRawData,
                    'sha256':hashlib.sha256(s.get_data()).hexdigest()} for s in pe.sections]}
    finally:pe.close()


def main(first, second, destination):
    if destination.exists():raise RuntimeError('Preserve previous build comparison evidence')
    manifests = [];recipes=[]
    for base in (first, second):
        manifest = json.loads((base / 'source-manifest.json').read_text())
        assert all(sha(base / 'source' / name) == digest for name, digest in manifest.items())
        manifests.append(manifest)
        build_recipes={}
        for kind in ('driver', 'core-x86', 'core-x64'):
            row = json.loads((base / 'ewdk-build' / (kind + '-receipt.json')).read_text())
            assert row['returncode'] == 0 and row['source_manifest_sha256'] == sha(base / 'source-manifest.json')
            deterministic=row.get('deterministic_link_requested',False)
            if deterministic:
                if row.get('recipe_sha256')!=sha(base/'ewdk-build/deterministic.targets'):
                    raise RuntimeError('Recorded deterministic recipe changed')
            build_recipes[kind]=(deterministic,row.get('recipe_sha256'),row.get('build_tool_sha256'))
        recipes.append(build_recipes)
    assert manifests[0] == manifests[1]
    if recipes[0]!=recipes[1]:raise RuntimeError('Clean-repeat build recipes differ')
    records = {}
    for platform in ('x64', 'Win32'):
        relative = Path('source/Sandboxie/Bin') / platform / 'SbieRelease'
        names = [{p.name for p in (base / relative).iterdir() if p.suffix in ('.exe', '.dll', '.sys')} for base in (first, second)]
        assert names[0] == names[1] and names[0]
        for name in sorted(names[0]):
            a, b = first / relative / name, second / relative / name
            first_hash,second_hash=sha(a),sha(b)
            records[platform + '/' + name] = {'first_sha256':first_hash,'repeat_sha256':second_hash,
                'byte_identical':first_hash==second_hash,'first_pe':pe_details(a),'repeat_pe':pe_details(b)}
    report = {'schema': 1, 'clean_build_repeated': True, 'same_reviewed_source': True,
        'same_recorded_recipes':True,'build_recipes':recipes[0],
        'artifacts': records, 'byte_reproducible': all(r['byte_identical'] for r in records.values()),
        'installed': False, 'runtime_verified': False,
        'limits': ['Different output bytes require separate hash/signature review; no equivalence is inferred from successful compilation.',
                   'PE section/debug diagnostics do not normalize, modify or authorize either binary.',
                   'Same-host clean-directory comparison only; cross-host and cross-date acceptance remain separate.',
                   'Legacy receipts without recipe/tool hashes do not establish full build-recipe provenance.']}
    with destination.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps({'clean_build_repeated': True, 'files': len(records), 'byte_identical': sum(r['byte_identical'] for r in records.values())}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('first', 'second', 'output'): parser.add_argument('--' + flag, type=Path, required=True)
    args = parser.parse_args()
    main(args.first, args.second, args.output)
