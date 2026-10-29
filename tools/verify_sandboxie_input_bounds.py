"""Execute prepared GUI input handlers against in-memory Windows API stubs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def main(prepared,compiler,upstream=None):
    prepared=prepared.resolve()
    file=prepared/'prepared/Sandboxie/core/svc/GuiServer.cpp'
    manifest=json.loads((prepared/'manifest.json').read_text())
    digest=hashlib.sha256(file.read_bytes()).hexdigest()
    if digest!=manifest['files']['GuiServer.cpp']['prepared_sha256']:raise RuntimeError('Prepared GUI source drift')
    source=file.read_text('utf-8')
    def extract(source,directory):
      fragments={}
      for signature,name in [('ULONG GuiServer::GetRawInputDeviceInfoSlave(','RawInputUnderTest.inc'),
                           ('ULONG GuiServer::WndHookRegisterSlave(','WndHookUnderTest.inc')]:
        start=source.index(signature);end=source.index('{',start)+1;depth=1
        while depth:
            if source[end]=='{':depth+=1
            elif source[end]=='}':depth-=1
            end+=1
        body=source[start:end]+'\n'
        (directory/name).write_text(body,encoding='utf-8')
        fragments[name]=hashlib.sha256(body.encode()).hexdigest()
      return fragments
    fragments=extract(source,prepared)
    exe=prepared/'GuiInputBoundsTests.exe'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(ROOT/'work/toolchains/zig-cache'))
    command=[str(compiler),'c++','-std=c++17','-include','initializer_list','-I'+str(prepared),
             str(ROOT/'src/tests/native/GuiInputBoundsTests.cpp'),'-o',str(exe)]
    result=subprocess.run(command,capture_output=True,timeout=180,env=env,creationflags=0x08000000)
    if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace')[-4000:])
    result=subprocess.run([str(exe)],capture_output=True,timeout=15,creationflags=0x08000000)
    if result.returncode:raise RuntimeError('Prepared GUI bounds test failed: '+result.stderr.decode(errors='replace'))
    report=json.loads(result.stdout)
    if upstream:
        original=upstream/'Sandboxie/core/svc/GuiServer.cpp'
        if hashlib.sha256(original.read_bytes()).hexdigest()!=manifest['files']['GuiServer.cpp']['upstream_sha256']:
            raise RuntimeError('Upstream negative control source differs')
        control=prepared/'bounds-negative-control';control.mkdir(exist_ok=True)
        extract(original.read_text('utf-8-sig'),control)
        control_exe=control/'GuiInputBoundsTests.exe'
        command=[str(compiler),'c++','-std=c++17','-include','initializer_list','-I'+str(control),
                 str(ROOT/'src/tests/native/GuiInputBoundsTests.cpp'),'-o',str(control_exe)]
        result=subprocess.run(command,capture_output=True,timeout=180,env=env,creationflags=0x08000000)
        if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace')[-4000:])
        for arguments in ([],['--hook-only']):
            result=subprocess.run([str(control_exe),*arguments],capture_output=True,timeout=15,creationflags=0x08000000)
            if result.returncode!=1 or b'check failed' not in result.stderr:
                raise RuntimeError('Upstream negative control did not expose the expected failure')
        report['upstream_bounds_and_lock_negative_controls_failed_as_expected']=True
    report.update(gui_source_sha256=digest,extracted_functions=fragments,installed=False,
                  limits=['Stubbed handler execution; not live driver/service acceptance.'])
    (prepared/'gui-input-bounds-result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared-root',type=Path,required=True)
    parser.add_argument('--upstream-root',type=Path)
    parser.add_argument('--compiler',type=Path,default=ROOT/'work/toolchains/zig-pypi-0.13.0/ziglang/zig.exe')
    args=parser.parse_args();main(args.prepared_root,args.compiler,args.upstream_root)
