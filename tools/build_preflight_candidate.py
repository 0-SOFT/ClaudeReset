"""Freeze read-only installer preflight; never build an elevating installer."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
import pefile
from collect_python_licenses import collect,verify_frozen_python,verify_python_layout
from frozen_sources import snapshot,selected
from frozen_recipe import environment

ROOT=Path(__file__).resolve().parents[1]


def require_as_invoker(exe):
    with pefile.PE(str(exe)) as pe:
        manifests=[]
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id!=24:continue
            for name in entry.directory.entries:
                for language in name.directory.entries:
                    data=language.data.struct
                    if not 1<=data.Size<=65536:raise RuntimeError('Unexpected executable manifest size')
                    manifests.append(pe.get_data(data.OffsetToData,data.Size))
    if len(manifests)!=1:raise RuntimeError('One explicit executable manifest required')
    root=ET.fromstring(manifests[0])
    levels=root.findall('.//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel')
    if len(levels)!=1 or levels[0].attrib!={'level':'asInvoker','uiAccess':'false'}:
        raise RuntimeError('Preflight must never request elevation or UI access')


def main(output,epoch,*,dependency_root=None):
    verify_python_layout(dependency_root)
    output=output.resolve();env,recipe=environment(output,epoch)
    if output.exists():raise RuntimeError('Choose a fresh preflight candidate directory')
    entry=ROOT/'src/installer_preflight_main.py';before=snapshot(entry);output.mkdir(parents=True)
    with (output/'build.log').open('wb') as log:
        result=subprocess.run([sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onefile','--noupx',
            '--name','ClaudeResetPreflight','--paths',str(ROOT/'src'),'--distpath',str(output/'dist'),
            '--workpath',str(output/'build'),'--specpath',str(output),str(entry)],
            stdout=log,stderr=subprocess.STDOUT,timeout=300,creationflags=0x08000000,env=env)
    if result.returncode:raise RuntimeError('Preflight build failed; inspect build.log')
    exe=output/'dist/ClaudeResetPreflight.exe';require_as_invoker(exe)
    for args,code in [(['--help'],0),([],2),(['--install'],2)]:
        result=subprocess.run([str(exe),*args],capture_output=True,timeout=30,creationflags=0x08000000)
        if result.returncode!=code:raise RuntimeError('Unexpected preflight CLI behavior')
    licenses=collect(output/'licenses',dependency_root=dependency_root)
    receipt=dict(schema=1,executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
        source_sha256=selected(output/'build/ClaudeResetPreflight/PYZ-00.toc',before,entry),
        source_scope='actual frozen project modules plus entry',
        license_sha256=licenses['license_sha256'],python_toolchain=verify_frozen_python(exe),
        frozen_build_recipe=recipe,execution_level='asInvoker',ui_access=False,
        installed=False,client_network_opened=False,final_release=False)
    (output/'build-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(dict(compiled=True,execution_level='asInvoker',installed=False)))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--source-date-epoch',type=int,required=True)
    parser.add_argument('--dependency-root',type=Path,help='Explicit dependency cache for the active reviewed interpreter')
    args=parser.parse_args();main(args.output,args.source_date_epoch,dependency_root=args.dependency_root)
