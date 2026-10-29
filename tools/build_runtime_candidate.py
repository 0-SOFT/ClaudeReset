"""Freeze the dedicated runtime and verify it refuses uninstalled invocation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from collect_python_licenses import collect, verify_frozen_python, verify_python_layout
from frozen_sources import snapshot, selected
from frozen_recipe import environment

ROOT = Path(__file__).resolve().parents[1]


def main(output,source_date_epoch=None,*,dependency_root=None):
    verify_python_layout(dependency_root)
    output = output.resolve()
    build_env,recipe=environment(output,source_date_epoch)
    if output.exists(): raise RuntimeError('Choose a fresh candidate directory')
    entry=ROOT/'src/backend_runtime_main.py'; before=snapshot(entry)
    output.mkdir(parents=True)
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile',
        '--name', 'ClaudeResetRuntime', '--paths', str(ROOT/'src'),
        '--distpath', str(output/'dist'), '--workpath', str(output/'build'),
        '--specpath', str(output), str(ROOT/'src/backend_runtime_main.py')]
    with (output/'build.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300, creationflags=0x08000000,env=build_env)
    if result.returncode: raise RuntimeError('Runtime build failed; inspect build.log')
    exe = output/'dist/ClaudeResetRuntime.exe'
    rows = []
    for args, expected in [([],2), (['--service'],1), (['--service','--command','cmd.exe'],2)]:
        result = subprocess.run([str(exe),*args], capture_output=True, timeout=30, creationflags=0x08000000)
        if result.returncode != expected or result.stdout or result.stderr:
            raise RuntimeError('Uninstalled runtime did not reject invocation cleanly')
        rows.append({'arguments':args,'exit_code':result.returncode,'rejected':True})
    licenses = collect(output/'licenses',dependency_root=dependency_root)
    receipt = {'schema':1,'executable_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
        'license_sha256':licenses['license_sha256'],
        'python_toolchain':verify_frozen_python(exe),
        'source_sha256':selected(output/'build/ClaudeResetRuntime/PYZ-00.toc',before,entry),
        'source_scope':'actual frozen project modules plus entry',
        'entry_sha256':hashlib.sha256((ROOT/'src/backend_runtime_main.py').read_bytes()).hexdigest(),
        'invocation_tests':rows,'installed':False,'service_started':False,'client_network_opened':False,
        'limits':['Installed positive service lifecycle and WFP endpoint enforcement remain unverified.']}
    receipt['frozen_build_recipe']=recipe
    (output/'build-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'compiled':True,'rejection_checks':len(rows),'installed':False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-date-epoch',type=int)
    parser.add_argument('--dependency-root',type=Path,help='Explicit dependency cache for the active reviewed interpreter')
    args=parser.parse_args();main(args.output,args.source_date_epoch,dependency_root=args.dependency_root)
