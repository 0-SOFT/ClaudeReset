"""Compare exact frozen candidates built with the same explicit recipe."""
import argparse,hashlib,json
from pathlib import Path


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def inspect(folder):
    folder=folder.resolve();receipt=json.loads((folder/'build-receipt.json').read_text(encoding='utf-8'))
    binaries=list((folder/'dist').glob('*.exe'))
    if len(binaries)!=1 or binaries[0].name not in ('ClaudeResetCandidate.exe','ClaudeResetRuntime.exe','ClaudeResetPreflight.exe'):
        raise RuntimeError('One fixed frozen executable required')
    binary=binaries[0];digest=sha(binary)
    if digest!=receipt['executable_sha256']:raise RuntimeError('Frozen executable differs from receipt')
    recipe=receipt.get('frozen_build_recipe')
    if (not recipe or type(recipe.get('source_date_epoch')) is not int
            or recipe.get('pythonhashseed')!='0' or recipe.get('isolated_build_cache') is not True
            or receipt.get('installed') is not False or receipt.get('client_network_opened') is not False
            or not receipt.get('source_sha256') or not receipt.get('python_toolchain')):
        raise RuntimeError('Explicit frozen recipe and candidate evidence required')
    return binary.name,digest,receipt


def main(first,second,output):
    if output.exists():raise RuntimeError('Preserve prior comparison reports')
    if first.resolve()==second.resolve():raise RuntimeError('Distinct build directories required')
    aname,ahash,a=inspect(first);bname,bhash,b=inspect(second)
    if aname!=bname:raise RuntimeError('Different frozen entry points')
    for key in ('source_sha256','python_toolchain','frozen_build_recipe','license_sha256'):
        if a[key]!=b[key]:raise RuntimeError('Frozen comparison inputs differ: '+key)
    result=dict(schema=1,executable=aname,byte_identical=ahash==bhash,first_sha256=ahash,second_sha256=bhash,
                source_files=len(a['source_sha256']),recipe=a['frozen_build_recipe'],
                installed=False,client_admission=False,
                limits=['Same host, interpreter, dependencies and source path; no cross-host acceptance.',
                        'No binary normalization; no release signing or installed-client acceptance.'])
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(result))
    if not result['byte_identical']:raise RuntimeError('Frozen repeat differs; inspect the preserved report')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('first','second','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();main(args.first,args.second,args.output)
