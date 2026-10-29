"""Build reviewed sources with extracted Microsoft tools; never sign, install or load drivers."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.windows import ps_json
from claude_reset.safeio import guarded


def main(source,kit,kind,deterministic=False):
    source,kit=source.resolve(),kit.resolve()
    manifest_file=kit.parent/'extraction-manifest.json'
    if not manifest_file.is_file(): raise RuntimeError('Complete toolchain extraction required')
    manifest=json.loads(manifest_file.read_text())
    vs='Program Files/Microsoft Visual Studio/2022/BuildTools/'
    vc=vs+'VC/Tools/MSVC/14.44.35207/'
    sdk='Program Files/Windows Kits/10/bin/10.0.26100.0/'
    names=[vs+'MSBuild/Current/Bin/amd64/MSBuild.exe',vc+'bin/Hostx64/x64/cl.exe',
           vc+'bin/Hostx64/x64/link.exe',vc+'bin/Hostx64/x86/cl.exe',
           sdk+'x64/rc.exe',sdk+'x64/mc.exe',sdk+'x86/rc.exe',sdk+'x86/mc.exe']
    for name in names:
        p=guarded(kit/name,kit)
        if hashlib.sha256(p.read_bytes()).hexdigest()!=manifest[name]['sha256']:
            raise RuntimeError('Extracted tool changed: '+name)
    quoted=','.join("'"+str(kit/name).replace("'","''")+"'" for name in names)
    signatures=ps_json("@("+quoted+") | ForEach-Object { $s=Get-AuthenticodeSignature -LiteralPath $_; @{path=$_;status=$s.Status.ToString();subject=$s.SignerCertificate.Subject;thumbprint=$s.SignerCertificate.Thumbprint} } | ConvertTo-Json -Depth 4 -Compress")
    if not all(s['status']=='Valid' and 'Microsoft' in s['subject'] for s in signatures):
        raise RuntimeError('Primary Microsoft tool signature verification failed: '+json.dumps(signatures))
    expected=json.loads((source.parent/'source-manifest.json').read_text())
    for relative,digest in expected.items():
        p=guarded(source/relative,source)
        if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('Reviewed source changed before build: '+relative)
    folder=source.parent/'ewdk-build';folder.mkdir(exist_ok=True)
    if (folder/(kind+'-receipt.json')).exists():raise RuntimeError('Preserve previous build; prepare a fresh source tree')
    empty=folder/'empty-user-props';empty.mkdir(exist_ok=True)
    (folder/'tool-verification.json').write_text(json.dumps({'primary_tools':signatures,'hashes_match_extracted_image':True,'installed':False},indent=2),encoding='utf-8')
    solution,platform={'driver':('SandboxDrv.sln','x64'),'core-x86':('SandboxDll.sln','Win32'),'core-x64':('Sandbox.sln','x64')}[kind]
    arguments=['/nologo','/t:Build','/m:2','/nodeReuse:false','/v:minimal','/p:Configuration=SbieRelease',
               '/p:Platform='+platform,'/p:WindowsTargetPlatformVersion=10.0.26100.0',
               '/p:SignMode=Off','/p:TestSign=false','/p:PostBuildEventUseInBuild=false',
               '/p:UserRootDir='+str(empty)+'\\']
    recipe=None
    if deterministic:
        recipe=folder/'deterministic.targets'
        content='''<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup><LinkIncremental>false</LinkIncremental></PropertyGroup>
  <ItemDefinitionGroup>
    <Link><AdditionalOptions>/Brepro /INCREMENTAL:NO /PDBALTPATH:$(TargetName).pdb %(AdditionalOptions)</AdditionalOptions></Link>
  </ItemDefinitionGroup>
</Project>
'''
        if recipe.exists() and recipe.read_text('utf-8')!=content:
            raise RuntimeError('Deterministic recipe changed between build targets')
        recipe.write_bytes(content.encode('utf-8'))
        arguments.append('/p:ForceImportAfterCppTargets='+str(recipe))
    script=folder/(kind+'.cmd')
    # Paths originate from this reviewed workspace; reject cmd expansion syntax.
    if any(any(c in str(p) for c in '%!&|<>\r\n') for p in (source,kit,empty)):
        raise RuntimeError('Unsupported batch path characters')
    command='"'+str(kit/names[0])+'" "'+str(source/'Sandboxie'/solution)+'" '+subprocess.list2cmdline(arguments)
    script.write_text('@echo off\nset "VSCMD_SKIP_SENDTELEMETRY=1"\ncall "'+str(kit/'BuildEnv/SetupBuildEnv.cmd')+'" amd64\nif errorlevel 1 exit /b %errorlevel%\n'+command+'\nexit /b %errorlevel%\n',encoding='utf-8')
    env={k:v for k,v in os.environ.items() if k.upper() not in ('CL','_CL_','LINK','_LINK_')
         and not k.upper().startswith(('COR_','CORECLR_','COMPLUS_','DOTNET_','MSBUILD','VSCMD','VSINSTALL','VCINSTALL','WINDOWSSDK','WINDOWSTARGET','WDK'))}
    env['MSBUILDDISABLENODEREUSE']='1';env['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
    log=folder/(kind+'.log')
    # cmd.exe uses shell quoting, not the C argv quoting of list2cmdline.
    command_line='"'+str(Path(os.environ['SystemRoot'])/'System32/cmd.exe')+'" /d /s /c ""'+str(script)+'""'
    with log.open('wb') as stream:
        result=subprocess.run(command_line,cwd=ROOT,env=env,
                              stdout=stream,stderr=subprocess.STDOUT,timeout=1200,creationflags=0x08000000)
    receipt={'schema':1,'utc':datetime.now(timezone.utc).isoformat(),'kind':kind,'returncode':result.returncode,
             'source_manifest_sha256':hashlib.sha256((source.parent/'source-manifest.json').read_bytes()).hexdigest(),
             'toolchain':'EWDK 26100.6584, MSVC 14.44.35207','log':str(log),'signed':False,'installed':False,'loaded':False}
    receipt['deterministic_link_requested']=deterministic
    receipt['build_tool_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    receipt['recipe_sha256']=hashlib.sha256(recipe.read_bytes()).hexdigest() if recipe else None
    (folder/(kind+'-receipt.json')).write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(receipt),flush=True)
    if result.returncode:
        print(log.read_text(errors='replace')[-14000:])
    return result.returncode


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--kit-root',type=Path,default=ROOT/'work/toolchains/ewdk-26100.6584/extracted')
    parser.add_argument('--kind',choices=('driver','core-x86','core-x64'),required=True)
    parser.add_argument('--deterministic',action='store_true',help='Experimental /Brepro and stable PDB name; still requires clean-repeat evidence')
    args=parser.parse_args();raise SystemExit(main(args.source_root,args.kit_root,args.kind,args.deterministic))
