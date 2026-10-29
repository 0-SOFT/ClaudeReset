"""One deterministic, pinned Roslyn recipe for managed candidates and fixtures."""
from pathlib import Path
from contextlib import ExitStack
import hashlib,json,os,subprocess,sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.windows_pin import PinnedFile
from claude_reset.install_signature import inspect_signature

MANIFEST=b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>'
TARGETS={
    'ClaudeResetGateway':(['src/native/ClaudeResetGateway.cs'],None),
    'ClaudeResetBackend':(['src/native/ClaudeResetBackend.cs','src/native/ClaudeResetGateway.cs'],'ClaudeResetBackend'),
    'BackendBootstrapTests':(['src/native/ClaudeResetBackend.cs','src/native/ClaudeResetGateway.cs',
                              'src/tests/native/BackendBootstrapTests.cs'],'BackendBootstrapTests'),
    'GatewayFunctionalTests':(['src/native/ClaudeResetGateway.cs','src/tests/native/GatewayFunctionalTests.cs'],'GatewayFunctionalTests'),
}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output,targets,*,kit_root=None):
    output=Path(output).resolve();targets=list(targets)
    if output.exists():raise RuntimeError('Preserve existing managed builds')
    if not targets or len(set(targets))!=len(targets) or any(name not in TARGETS for name in targets):
        raise RuntimeError('Only fixed managed candidate targets are supported')
    kit=(ROOT/'work/toolchains/ewdk-26100.6584/extracted' if kit_root is None
         else Path(kit_root).resolve())
    roslyn=kit/'Program Files/Microsoft Visual Studio/2022/BuildTools/MSBuild/Current/Bin/Roslyn'
    framework=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319'
    references=[framework/(name+'.dll') for name in
                ('mscorlib','System','System.Core','System.ServiceProcess','System.Web.Extensions')]
    compiler=roslyn/'csc.exe'
    env={k:v for k,v in os.environ.items() if k.upper() not in ('LIB','LIBPATH','DEVPATH')
         and not k.upper().startswith(('COR_','CORECLR_','COMPLUS_','DOTNET_'))}
    with ExitStack() as held:
        extraction=held.enter_context(PinnedFile(kit.parent/'extraction-manifest.json'))
        manifest_bytes=extraction.path.read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest()!=extraction.sha256:
            raise RuntimeError('Extraction manifest differs from held input')
        manifest=json.loads(manifest_bytes)
        prefix=roslyn.relative_to(kit).as_posix()+'/'
        expected={name:row['sha256'] for name,row in manifest.items() if name.startswith(prefix)}
        actual={p.relative_to(kit).as_posix() for p in roslyn.rglob('*') if p.is_file()}
        if not expected or actual!=set(expected):raise RuntimeError('Roslyn inventory differs from extracted kit')
        pins={}
        for name,digest in expected.items():
            pins[name]=held.enter_context(PinnedFile(kit/name,expected_sha256=digest))
        compiler_pin=pins[compiler.relative_to(kit).as_posix()]
        signature=inspect_signature(compiler_pin)
        ref_pins=[held.enter_context(PinnedFile(p)) for p in references]
        sources=sorted({name for target in targets for name in TARGETS[target][0]})
        source_pins={name:held.enter_context(PinnedFile(ROOT/name,limit=65536)) for name in sources}
        output.mkdir(parents=True)
        for name,pin in source_pins.items():(output/Path(name).name).write_bytes(pin.data)
        (output/'as-invoker.manifest').write_bytes(MANIFEST)
        common=[str(compiler),'/nologo','/noconfig','/nostdlib+','/platform:x64','/target:exe',
                '/optimize+','/deterministic+','/codepage:65001','/pathmap:'+str(output)+'=/src',
                '/win32manifest:as-invoker.manifest',*('/r:'+str(p) for p in references)]
        report=dict(schema=1,recipe_sha256=sha(Path(__file__)),extraction_manifest_sha256=extraction.sha256,
                    compiler_sha256=compiler_pin.sha256,compiler_signature=signature,compiler_files=expected,
                    references={str(pin.path):pin.sha256 for pin in ref_pins},
                    source_sha256={name:pin.sha256 for name,pin in source_pins.items()},
                    manifest_sha256=hashlib.sha256(MANIFEST).hexdigest(),builds={},installed=False,
                    services_started=False,client_admission=False)
        for name in targets:
            sources,entry=TARGETS[name]
            args=[*common,*(['/main:'+entry] if entry else []),'/out:'+name+'.exe',
                  *(Path(p).name for p in sources)]
            result=subprocess.run(args,cwd=output,env=env,capture_output=True,timeout=60,creationflags=0x08000000)
            (output/(name+'.log')).write_bytes(result.stdout+result.stderr)
            if result.returncode:raise RuntimeError('Managed build failed: '+name)
            value=dict(sha256=sha(output/(name+'.exe')),arguments=args[1:])
            if name.endswith('Tests'):
                command=[str(output/(name+'.exe'))]
                if name=='GatewayFunctionalTests':command.append(str(os.getpid()))
                test=subprocess.run(command,cwd=output,env=env,capture_output=True,timeout=60,creationflags=0x08000000)
                (output/(name+'-result.json')).write_bytes(test.stdout)
                if test.returncode or json.loads(test.stdout).get('passed') is not True:
                    raise RuntimeError('Managed functional fixture failed: '+name)
                value['tests']=json.loads(test.stdout)
            report['builds'][name]=value
        for name,pin in source_pins.items():
            if sha(output/Path(name).name)!=pin.sha256:raise RuntimeError('Managed source copy changed')
        if (output/'as-invoker.manifest').read_bytes()!=MANIFEST:raise RuntimeError('Build manifest changed')
        for pin in [extraction,*pins.values(),*ref_pins,*source_pins.values()]:
            if sha(pin.path)!=pin.sha256:raise RuntimeError('Held managed build input changed')
        report['limits']=['Same host/toolchain/reference identity only; cross-host/date acceptance remains open.',
                          'Unsigned candidates; no installed-service or client acceptance.']
        (output/'managed-build-receipt.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        return report
