"""Build a separate internal GUI/CLI candidate; never replace an installed app."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from collect_python_licenses import collect, verify_frozen_python, verify_python_layout
from frozen_sources import snapshot, selected
from frozen_recipe import environment

ROOT=Path(__file__).resolve().parents[1]


def main(output,source_date_epoch=None,*,dependency_root=None):
    verify_python_layout(dependency_root)
    output=output.resolve()
    build_env,recipe=environment(output,source_date_epoch)
    if output.exists():raise RuntimeError('Choose a fresh app candidate directory')
    entry=ROOT/'src/launcher.py'; before=snapshot(entry)
    output.mkdir(parents=True)
    with (output/'build.log').open('wb') as log:
        result=subprocess.run([sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onefile','--noupx',
            '--name','ClaudeResetCandidate','--paths',str(ROOT/'src'),
            '--distpath',str(output/'dist'),'--workpath',str(output/'build'),'--specpath',str(output),
            str(ROOT/'src/launcher.py')],stdout=log,stderr=subprocess.STDOUT,timeout=300,creationflags=0x08000000,env=build_env)
    if result.returncode:raise RuntimeError('App candidate build failed; inspect build.log')
    exe=output/'dist/ClaudeResetCandidate.exe'
    result=subprocess.run([str(exe),'--help'],capture_output=True,timeout=30,creationflags=0x08000000)
    if result.returncode or b'--backend-list' not in result.stdout:raise RuntimeError('Candidate CLI is incomplete')
    licenses=collect(output/'licenses',dependency_root=dependency_root)
    receipt={'schema':1,'executable_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
        'source_sha256':selected(output/'build/ClaudeResetCandidate/PYZ-00.toc',before,entry),
        'source_scope':'actual frozen project modules plus entry',
        'installed':False,'client_network_opened':False,'final_release':False}
    receipt['license_sha256']=licenses['license_sha256']
    receipt['python_toolchain']=verify_frozen_python(exe)
    receipt['frozen_build_recipe']=recipe
    (output/'build-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'compiled':True,'executable_sha256':receipt['executable_sha256'],'installed':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-date-epoch',type=int)
    parser.add_argument('--dependency-root',type=Path,help='Explicit dependency cache for the active reviewed interpreter')
    args=parser.parse_args();main(args.output,args.source_date_epoch,dependency_root=args.dependency_root)
