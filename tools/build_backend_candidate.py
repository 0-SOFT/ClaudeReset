"""Compile and test the fixed backend service bootstrap. No elevation/installation."""
import argparse,json,shutil
from pathlib import Path
from managed_compiler import build,sha


def main(output,*,kit_root=None):
    output=output.resolve()
    if output.exists():raise RuntimeError('Preserve existing candidates; choose a fresh directory')
    managed=build(output/'managed-build',['ClaudeResetBackend','BackendBootstrapTests'],kit_root=kit_root)
    for name in ('ClaudeResetBackend','BackendBootstrapTests'):
        target=output/(name+'.exe');shutil.copyfile(output/'managed-build'/(name+'.exe'),target)
        if sha(target)!=managed['builds'][name]['sha256']:raise RuntimeError('Managed candidate copy differs')
    result=managed['builds']['BackendBootstrapTests']['tests']
    (output/'tests.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    receipt={'schema':1,'source_sha256':managed['source_sha256'],
             'compiler_sha256':managed['compiler_sha256'],'compiler_signature':managed['compiler_signature'],
             'managed_build':managed,'executable_sha256':managed['builds']['ClaudeResetBackend']['sha256'],
             'tests':result,'installed':False,'service_started':False,'client_network_opened':False,
             'limits':['Service token, protected installation and full lifecycle not yet tested as an installed service.']}
    (output/'build-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'compiled':True,'checks':result['checks'],'installed':False,'deterministic_recipe':True}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--kit-root',type=Path,help='Explicit extracted EWDK; all pinned compiler checks remain required')
    args=parser.parse_args();main(args.output,kit_root=args.kit_root)
