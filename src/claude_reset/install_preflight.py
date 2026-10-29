"""Offline, non-elevating candidate inspection; no installation commands."""
import argparse
import json
from pathlib import Path
from .install_payload import PinnedPayload
from .install_catalog import inspect_release_catalog
from .install_signature import inspect_signature
from .install_inventory import inspect as inspect_slots
from .windows_pin import PinnedFile
from .safeio import SafetyError


def _inventory_evidence(value):
    """Do not export foreign service command lines, accounts or local paths."""
    result={key:value[key] for key in ('schema','root_occupied','fresh_install_blockers',
            'registry_slots','settings_changed','client_admission','limits') if key in value}
    result['services']=[{key:row[key] for key in ('name','exists','type','start','state','pid')
                         if key in row} for row in value.get('services',[])]
    return result


def inspect_candidate(folder,manifest_sha256,catalog,catalog_sha256):
    blockers=['approved_release_authority_missing','installed_acceptance_incomplete']
    with PinnedPayload(Path(folder).resolve(),manifest_sha256) as payload:
        result=payload.report()
        with PinnedFile(Path(catalog).resolve(),expected_sha256=catalog_sha256,limit=1048576) as pin:
            try:catalog_evidence=inspect_release_catalog(pin,payload)
            except SafetyError as error:
                catalog_evidence=dict(catalog_sha256=pin.sha256,catalog_authenticode_verified=False,
                                      manifest_membership_verified=False,error=str(error))
                blockers.append('release_catalog_unverified')
        signatures={}
        for name,pin in sorted(payload.pins.items()):
            if Path(name).suffix.lower() not in ('.exe','.dll','.sys'):continue
            try:signatures[name]=inspect_signature(pin)
            except SafetyError as error:
                signatures[name]=dict(file_sha256=pin.sha256,authenticode_verified=False,error=str(error))
        if not signatures or any(row.get('authenticode_verified') is not True for row in signatures.values()):
            blockers.append('embedded_signatures_unverified')
        try:
            inventory=_inventory_evidence(inspect_slots())
            if inventory['fresh_install_blockers']:blockers.append('installation_slots_occupied')
        except SafetyError as error:
            inventory=dict(inspected=False,error=str(error));blockers.append('installation_inventory_unavailable')
        payload.report()
        return dict(result,status='candidate_preflight_blocked',passed=False,
                    release_catalog_evidence=catalog_evidence,embedded_signature_evidence=signatures,
                    installation_inventory=inventory,blockers=blockers,
                    release_authority_verified=False,kernel_load_verified=False,
                    installable=False,client_admission=False,settings_changed=False,
                    limits=['Read-only candidate evidence; no installation, migration or elevation command.',
                            'SCM and registry-slot snapshots are not WFP, client or Cowork acceptance.',
                            'Valid signatures still require approved product authority and installed acceptance.'])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--expected-manifest-sha256',required=True)
    parser.add_argument('--catalog',type=Path,required=True)
    parser.add_argument('--expected-catalog-sha256',required=True)
    args=parser.parse_args(argv)
    try:
        result=inspect_candidate(args.bundle,args.expected_manifest_sha256,args.catalog,args.expected_catalog_sha256)
    except (SafetyError,OSError,ValueError) as error:
        result=dict(status='candidate_preflight_failed',passed=False,error_type=type(error).__name__,
                    installable=False,client_admission=False,settings_changed=False)
        print(json.dumps(result,ensure_ascii=True));return 1
    print(json.dumps(result,ensure_ascii=True,indent=2));return 2
