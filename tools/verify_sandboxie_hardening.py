"""Compile the prepared service's actual GUI dispatch body with IPC test stubs."""
from pathlib import Path
import argparse,hashlib,json,subprocess,os
R=Path(__file__).resolve().parents[1];B=R/'work/sandboxie-hardening'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--compiler',type=Path,default=R/'work/toolchains/zig-pypi-0.13.0/ziglang/zig.exe')
parser.add_argument('--prepared-root',type=Path,default=B)
args=parser.parse_args();B=args.prepared_root
manifest=json.loads((B/'manifest.json').read_text())
service_sources={'Sandboxie/core/svc/'+name:metadata['prepared_sha256']
                 for name,metadata in manifest['files'].items()}
def bind_fixture(result,fixture):
    result['service_source_sha256']=service_sources
    result['test_sha256']=hashlib.sha256((R/'src/tests/native'/fixture).read_bytes()).hexdigest()
    return result
for name,metadata in manifest['files'].items():
    if hashlib.sha256((B/'prepared/Sandboxie/core/svc'/name).read_bytes()).hexdigest()!=metadata['prepared_sha256']:
        raise ValueError('Prepared service file changed since manifest: '+name)
def extract(file,signature,destination):
    source=(B/'prepared/Sandboxie/core/svc'/file).read_text()
    start=source.index(signature);body=source.index('{',start);depth=1;end=body+1
    while depth:
        if source[end]=='{':depth+=1
        elif source[end]=='}':depth-=1
        end+=1
    fragment=source[start:end]+'\n';(B/destination).write_text(fragment)
    return hashlib.sha256(fragment.encode()).hexdigest()
hashes={'gui':extract('GuiServer.cpp','bool GuiServer::QueueCallbackSlave2(void)','GuiDispatchUnderTest.inc'),
        'pipe':extract('PipeServer.cpp','MSG_HEADER *PipeServer::CallTarget(','PipeDispatchUnderTest.inc'),
        'queue':extract('queueserver.cpp','MSG_HEADER *QueueServer::Handler(','QueueDispatchUnderTest.inc'),
        'handles':extract('ProcessServer.cpp','BOOL ProcessServer::RunSandboxedDupAndCloseHandles(','HandleTransferUnderTest.inc')}
compiler=args.compiler;exe=B/'BrokerDispatchTests.exe'
cmd=[str(compiler),'c++','-std=c++17','-include','stdlib.h','-include','initializer_list',
     '-I'+str(B/'prepared/Sandboxie/core/svc'),'-I'+str(B),str(R/'src/tests/native/BrokerDispatchTests.cpp'),'-o',str(exe)]
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'work/toolchains/zig-cache'))
build=subprocess.run(cmd,capture_output=True,timeout=180,creationflags=0x08000000,env=env)
if build.returncode:raise RuntimeError(build.stderr.decode(errors='replace')[-5000:])
p=subprocess.run([str(exe)],capture_output=True,timeout=15,creationflags=0x08000000)
if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
result=json.loads(p.stdout);result.update(dispatch_source_sha256=hashes,
    full_service_build_verified=False,production_clients_permitted=False,full_tunnel_verified=False)
bind_fixture(result,'BrokerDispatchTests.cpp')
(B/'native-dispatch-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
windows_exe=B/'HandleTransferWindowsTests.exe'
build=subprocess.run([str(compiler),'c++','-std=c++17','-I'+str(B),
    str(R/'src/tests/native/HandleTransferWindowsTests.cpp'),'-o',str(windows_exe)],
    capture_output=True,timeout=60,creationflags=0x08000000,env=env)
if build.returncode:raise RuntimeError(build.stderr.decode(errors='replace')[-5000:])
run=subprocess.run([str(windows_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
if run.returncode:raise RuntimeError('Windows handle transfer failed: '+run.stdout.decode(errors='replace'))
windows_result=json.loads(run.stdout);windows_result.update(full_tunnel_verified=False,production_clients_permitted=False,
    transfer_source_sha256=hashes['handles'])
bind_fixture(windows_result,'HandleTransferWindowsTests.cpp')
(B/'windows-handle-transfer-result.json').write_text(json.dumps(windows_result,indent=2));print(json.dumps(windows_result))
bootstrap_exe=B/'BootstrapSecurityWindowsTests.exe'
build=subprocess.run([str(compiler),'c++','-std=c++17','-municode','-I'+str(B/'prepared/Sandboxie/core/svc'),
    str(R/'src/tests/native/BootstrapSecurityWindowsTests.cpp'),'-ladvapi32','-o',str(bootstrap_exe)],
    capture_output=True,timeout=60,creationflags=0x08000000,env=env)
if build.returncode:raise RuntimeError(build.stderr.decode(errors='replace')[-5000:])
run=subprocess.run([str(bootstrap_exe)],capture_output=True,timeout=15,creationflags=0x08000000)
if run.returncode:raise RuntimeError('Creation-time security test failed: '+run.stdout.decode(errors='replace')+run.stderr.decode(errors='replace'))
bootstrap_result=json.loads(run.stdout)
bind_fixture(bootstrap_result,'BootstrapSecurityWindowsTests.cpp')
bootstrap_result['security_header_sha256']=manifest['files']['CrBootstrapSecurity.h']['prepared_sha256']
bootstrap_result['launch_header_sha256']=manifest['files']['CrBootstrapLaunch.h']['prepared_sha256']
(B/'windows-bootstrap-security-result.json').write_text(json.dumps(bootstrap_result,indent=2));print(json.dumps(bootstrap_result))

from verify_queue_event_ownership import main as verify_queue_event
verify_queue_event(B,B/'queue-event-ownership',compiler)
from verify_queue_reply_ownership import main as verify_queue_reply
verify_queue_reply(B,B/'queue-reply-ownership',compiler)

from verify_queue_request_lifecycle import main as verify_queue_lifecycle
verify_queue_lifecycle(B,B/'queue-request-lifecycle',compiler)
