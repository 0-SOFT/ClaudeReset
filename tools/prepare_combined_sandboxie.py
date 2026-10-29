"""Apply both reviewed hardening layers to a complete pinned upstream copy."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from prepare_sandboxie_hardening import prepare as prepare_service
from prepare_sandboxie_helper_hardening import prepare as prepare_driver
from prepare_runtime_trust import prepare as prepare_runtime_trust
from prepare_managed_config import prepare as prepare_managed_config
from prepare_wfp_lifecycle import prepare as prepare_wfp_lifecycle
from prepare_sandboxie_build_paths import prepare as prepare_build_paths

ROOT=Path(__file__).resolve().parents[1]


def main(source, output, runtime_public_key=None, runtime_key_sha256=None):
    source,output=source.resolve(),output.resolve()
    if output.exists(): raise RuntimeError('Existing combined candidate preserved; choose a fresh output')
    if not (source/'Sandboxie/SandboxDrv.sln').is_file(): raise RuntimeError('Complete upstream source required')
    prepare_service(source,output/'service')
    prepare_driver(source,output/'driver')
    prepare_managed_config(source,output/'managed-config')
    prepare_wfp_lifecycle(source,output/'wfp-lifecycle')
    prepare_build_paths(source,output/'build-paths')
    layers = ['service', 'driver', 'managed-config', 'wfp-lifecycle', 'build-paths']
    if bool(runtime_public_key) != bool(runtime_key_sha256):
        raise RuntimeError('Runtime public key and its reviewed fingerprint are required together')
    if runtime_public_key:
        prepare_runtime_trust(source, output/'runtime-trust', runtime_public_key, runtime_key_sha256)
        layers.append('runtime-trust')
    tree=output/'source'
    shutil.copytree(source,tree)
    changed={}
    for layer in layers:
        prepared=output/layer/'prepared'
        for p in sorted(prepared.rglob('*')):
            if not p.is_file(): continue
            relative=p.relative_to(prepared).as_posix()
            if relative in changed: raise RuntimeError('Hardening layers overlap; manual review required')
            before=tree/relative
            changed[relative]={'upstream_sha256':hashlib.sha256(before.read_bytes()).hexdigest() if before.exists() else None,
                               'prepared_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'layer':layer}
            before.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,before)
    patch=(output/'service/claudereset-strict-brokers.patch').read_bytes()+(output/'driver/claudereset-helper-driver.patch').read_bytes()
    patch += (output/'managed-config/managed-config.patch').read_bytes()
    patch += (output/'wfp-lifecycle/wfp-lifecycle.patch').read_bytes()
    patch += (output/'build-paths/build-paths.patch').read_bytes()
    if runtime_public_key: patch += (output/'runtime-trust/runtime-trust.patch').read_bytes()
    (output/'combined.patch').write_bytes(patch)
    # Validate patch syntax against the pristine complete tree without changing it.
    check=subprocess.run(['git','apply','--check',str(output/'combined.patch')],cwd=source,capture_output=True,timeout=30)
    if check.returncode:raise RuntimeError(check.stderr.decode(errors='replace'))
    manifest={p.relative_to(tree).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(tree.rglob('*')) if p.is_file()}
    (output/'source-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    receipt={'schema':1,'source_tag':'v1.18.8','changes':changed,'patch_check':True,'full_tree_files':len(manifest),
             'runtime_public_key_sha256':runtime_key_sha256,'runtime_key_authority_verified':False,
             'full_build_verified':False,'installed':False,'production_clients_permitted':False}
    (output/'combined-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'combined_tree':str(tree),'changed_files':len(changed),'patch_check':True,'installed':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--output-root',type=Path,required=True)
    parser.add_argument('--runtime-public-key',type=Path)
    parser.add_argument('--runtime-key-sha256')
    args=parser.parse_args();main(args.source_root,args.output_root,args.runtime_public_key,args.runtime_key_sha256)
