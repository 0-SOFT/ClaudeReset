"""Build isolated CPython with pinned EWDK; never install or kill Python processes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import argparse

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.windows import ps_json
from claude_reset.safeio import guarded


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main(openssl_lts=False):
    base=ROOT/'work/dependencies'/('Python-3.12.16-openssl359' if openssl_lts else 'Python-3.12.16');source=base/'source'
    kit=ROOT/'work/toolchains/ewdk-26100.6584/extracted'
    output=base/'ewdk-build'
    if output.exists():raise RuntimeError('Preserve existing build evidence')
    manifest=json.loads((kit.parent/'extraction-manifest.json').read_text('utf-8'))
    prefix='Program Files/Microsoft Visual Studio/2022/BuildTools/'
    names=[prefix+'MSBuild/Current/Bin/amd64/MSBuild.exe',
           prefix+'VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe',
           prefix+'VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/link.exe',
           'Program Files/Windows Kits/10/bin/10.0.26100.0/x64/rc.exe','BuildEnv/SetupBuildEnv.cmd']
    for name in names:
        if sha(guarded(kit/name,kit))!=manifest[name]['sha256']:raise RuntimeError('EWDK input differs')
    quoted=','.join("'"+str(kit/name).replace("'","''")+"'" for name in names[:-1])
    signatures=ps_json('@('+quoted+')|ForEach-Object {$s=Get-AuthenticodeSignature -LiteralPath $_;@{path=$_;status=$s.Status.ToString();subject=$s.SignerCertificate.Subject}}|ConvertTo-Json -Compress')
    if not all(r['status']=='Valid' and 'Microsoft' in r['subject'] for r in signatures):raise RuntimeError('Compiler signature invalid')
    for file,root in [('source-manifest.json',source),('build-dependency-manifest.json',source/'externals')]:
        for name,digest in json.loads((base/file).read_text('utf-8')).items():
            if sha(guarded(root/name,root))!=digest:raise RuntimeError('Pinned Python build source differs: '+name)
    output.mkdir();empty=output/'empty-user-props';empty.mkdir()
    arguments=['/nologo','/t:Build','/m:2','/nodeReuse:false','/v:minimal',
        '/p:Configuration=Release','/p:Platform=x64','/p:PlatformToolset=v143',
        '/p:WindowsTargetPlatformVersion=10.0.26100.0','/p:KillPython=false',
        '/p:IncludeExternals=true','/p:IncludeCTypes=true','/p:IncludeSSL=true',
        '/p:IncludeTkinter=true','/p:IncludeTests=true','/p:IncludeUwp=false',
        '/p:SupportSigning=false','/p:PythonForBuild='+sys.executable,
        '/p:GitTag=v3.12.16','/p:GitVersion=source-archive',
        '/p:UserRootDir='+str(empty)+'\\']
    if openssl_lts:
        ssl=source/'externals/openssl-bin-3.5.9/amd64'
        arguments += ['/p:opensslOutDir='+str(ssl)+'\\','/p:opensslIncludeDir='+str(ssl/'include')]
    if any(any(c in str(p) for c in '%!&|<>\r\n') for p in (source,kit,empty,sys.executable)):
        raise RuntimeError('Unsafe build path')
    command='"'+str(kit/names[0])+'" "'+str(source/'PCbuild/pcbuild.proj')+'" '+subprocess.list2cmdline(arguments)
    script=output/'build.cmd'
    script.write_text('@echo off\nset "VSCMD_SKIP_SENDTELEMETRY=1"\ncall "'+str(kit/'BuildEnv/SetupBuildEnv.cmd')+'" amd64\nif errorlevel 1 exit /b %errorlevel%\n'+command+'\nexit /b %errorlevel%\n',encoding='utf-8')
    env={k:v for k,v in os.environ.items() if not k.upper().startswith(('COR_','CORECLR_','COMPLUS_','DOTNET_','MSBUILD','VSCMD','VSINSTALL','VCINSTALL','WINDOWSSDK','WINDOWSTARGET','WDK','PYTHON'))}
    env.update(MSBUILDDISABLENODEREUSE='1',DOTNET_CLI_TELEMETRY_OPTOUT='1',
               GIT_CEILING_DIRECTORIES=str(base),GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='NUL')
    cmd='"'+str(Path(os.environ['SystemRoot'])/'System32/cmd.exe')+'" /d /s /c ""'+str(script)+'""'
    with (output/'build.log').open('wb') as stream:
        run=subprocess.run(cmd,cwd=source,env=env,stdout=stream,stderr=subprocess.STDOUT,
                           timeout=1200,creationflags=0x08000000)
    result={'schema':1,'returncode':run.returncode,'source_manifest_sha256':sha(base/'source-manifest.json'),
            'dependency_manifest_sha256':sha(base/'build-dependency-manifest.json'),
            'kill_python':False,'installed':False,'active_interpreter_replaced':False,'compiler_signatures':signatures,
            'openssl_lts_override':openssl_lts}
    if run.returncode==0:
        exe=source/'PCbuild/amd64/python.exe'
        result['python_sha256']=sha(exe)
        result['version']=subprocess.check_output([str(exe),'-I','--version'],text=True).strip()
        original=json.loads((base/'source-manifest.json').read_text('utf-8'))
        effective={name:sha(source/name) for name in original}
        delta={name:{'before':original[name],'after':digest} for name,digest in effective.items() if original[name]!=digest}
        (base/'effective-source-manifest.json').write_text(json.dumps(effective,indent=2),encoding='utf-8')
        (base/'regenerated-source-delta.json').write_text(json.dumps(delta,indent=2),encoding='utf-8')
        result['effective_source_manifest_sha256']=sha(base/'effective-source-manifest.json')
        result['regenerated_source_files']=len(delta)
    (output/'receipt.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='compiler_signatures'}))
    if run.returncode:print((output/'build.log').read_text(errors='replace')[-8000:])
    return run.returncode


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-lts',action='store_true')
    raise SystemExit(main(parser.parse_args().openssl_lts))
