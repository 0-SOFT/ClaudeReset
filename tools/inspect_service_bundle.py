"""Read/pin exact review payload bytes; do not authenticate, execute or install."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.install_payload import PinnedPayload
from claude_reset.install_signature import inspect_signature
from claude_reset.install_catalog import inspect_release_catalog
from claude_reset.windows_pin import PinnedFile
from claude_reset.safeio import SafetyError


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--expected-manifest-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--inspect-signatures',action='store_true',
                        help='Collect offline embedded Authenticode evidence; never authorize installation')
    parser.add_argument('--catalog',type=Path,help='Optional release metadata CAT to inspect by held handle')
    parser.add_argument('--expected-catalog-sha256')
    args=parser.parse_args()
    if bool(args.catalog)!=bool(args.expected_catalog_sha256):
        parser.error('--catalog and --expected-catalog-sha256 are required together')
    with PinnedPayload(args.bundle.resolve(),args.expected_manifest_sha256) as bundle:
        result=bundle.report()
        if args.catalog:
            with PinnedFile(args.catalog.resolve(),expected_sha256=args.expected_catalog_sha256,limit=1048576) as pin:
                try:result['release_catalog_evidence']=inspect_release_catalog(pin,bundle)
                except SafetyError as error:
                    result['release_catalog_evidence']={'catalog_sha256':pin.sha256,
                        'catalog_authenticode_verified':False,'error':str(error),
                        'release_authority_verified':False,'installable':False}
        if args.inspect_signatures:
            evidence={}
            for name,pin in sorted(bundle.pins.items()):
                if Path(name).suffix.lower() not in ('.exe','.dll','.sys'):continue
                try:evidence[name]=inspect_signature(pin)
                except SafetyError as error:
                    evidence[name]={'authenticode_verified':False,'error':str(error),
                                    'file_sha256':pin.sha256}
            result['embedded_signature_evidence']=evidence
            result['embedded_authenticode_verified']=all(row['authenticode_verified'] for row in evidence.values())
        with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(result))
