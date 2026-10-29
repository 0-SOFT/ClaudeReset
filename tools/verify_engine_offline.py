"""Check the pinned engine's version and synthetic configs without starting it."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.windows_job import environment
from claude_reset.backend_attestation import inspect_sing_box


def main():
    lock = json.loads((ROOT/'third_party/sources/sing-box-lock.json').read_text())
    base = ROOT/'work/dependencies'/('sing-box-'+lock['version'])
    source = base/'extracted'/('sing-box-'+lock['version']+'-windows-amd64')/'sing-box.exe'
    if hashlib.sha256(source.read_bytes()).hexdigest() != lock['executable_sha256']:
        raise RuntimeError('Pinned engine bytes differ')
    fixture = ROOT/'work/release-execution-2026-10-26'/('engine-offline-'+uuid.uuid4().hex)
    fixture.mkdir(); exe = fixture/'engine.exe'; shutil.copyfile(source,exe)
    def run(args):
        return subprocess.run([str(exe),*args],cwd=fixture,env=environment(fixture),capture_output=True,
                              timeout=20,creationflags=0x08000000)
    version = run(['version','--name'])
    if version.returncode or version.stdout.decode().strip()!=lock['version']:
        raise RuntimeError('Engine version command failed')
    results = []
    for inbound in ('http','socks','mixed'):
        for grpc in (False,True):
            config = {'log':{'disabled':True},
                'inbounds':[{'type':inbound,'tag':'fixture-in','listen':'127.0.0.1','listen_port':1080}],
                'outbounds':[{'type':'vless','tag':'fixture-out','server':'1.1.1.1','server_port':443,
                    'uuid':'12345678-1234-1234-1234-123456789abc',
                    'tls':{'enabled':True,'server_name':'fixture.invalid',
                        'utls':{'enabled':True,'fingerprint':'chrome'},
                        'reality':{'enabled':True,'public_key':'A'*43,'short_id':'aabb'}}}],
                'route':{'final':'fixture-out'}}
            if grpc: config['outbounds'][0]['transport']={'type':'grpc','service_name':'fixture'}
            inspect_sing_box(config)
            path = fixture/(inbound+('-grpc' if grpc else '')+'.json')
            path.write_text(json.dumps(config),encoding='utf-8')
            result = run(['check','-c',str(path)])
            if result.returncode: raise RuntimeError('Synthetic engine check failed: '+result.stderr.decode(errors='replace')[-2000:])
            results.append({'inbound':inbound,'grpc':grpc,'accepted':True})
    receipt = {'schema':1,'passed':True,'engine_sha256':lock['executable_sha256'],
        'source_commit':lock['source_commit'],'version':lock['version'],'configs':results,
        'optional_cronet_dll_present':False,'engine_run_command_used':False,'tunnel_started':False,
        'client_network_opened':False,'limits':['Static engine check only; no installed service or network containment acceptance.']}
    (fixture/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'passed':True,'config_checks':len(results),'fixture':str(fixture),'tunnel_started':False}))


if __name__ == '__main__': main()
