"""Compare the exact managed packaging recipe in two clean directories."""
from pathlib import Path
import argparse,json
from managed_compiler import build,TARGETS


def main(output):
    output=output.resolve()
    if output.exists():raise RuntimeError('Preserve prior experiment')
    first=build(output/'first',TARGETS)
    second=build(output/'second',TARGETS)
    for key in ('recipe_sha256','extraction_manifest_sha256','compiler_sha256','compiler_files',
                'references','source_sha256','manifest_sha256'):
        if first[key]!=second[key]:raise RuntimeError('Managed repeat inputs differ: '+key)
    report=dict(first)
    report['builds']={'first':first['builds'],'second':second['builds']}
    report['byte_identical']={name:first['builds'][name]['sha256']==second['builds'][name]['sha256'] for name in TARGETS}
    report['packaging_recipe_shared']=True
    (output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    if not all(report['byte_identical'].values()):raise RuntimeError('Managed repeat differs')
    print(json.dumps({'byte_identical':report['byte_identical'],'tests':{n:r.get('tests') for n,r in first['builds'].items()}}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();main(args.output)
