"""Exact release authority checks for the future authenticated installer.

The trust anchor belongs to the independently trusted installer, never a bundle,
CLI argument, environment variable or adjacent policy file. No authority has
been approved for this development tree: the default anchor remains absent.
Matching authority still does not authorize installation or client admission.
"""
from pathlib import Path
import hashlib
import re
from .backend_spec import document
from .install_payload import FILES,PinnedPayload
from .install_signature import inspect_signature,_check_digest
from .install_catalog import inspect_release_catalog
from .install_runtime_signature import RUNTIME_IMAGES,inspect_runtime_signature_set
from .windows_pin import PinnedFile
from .safeio import SafetyError

TRUSTED_POLICY_SHA256=None
SIGNED_FILES=frozenset(name for name in FILES if Path(name).suffix.lower() in ('.exe','.dll','.sys'))


def _digest(value):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def _signers(value):
    if (not isinstance(value,list) or not 1<=len(value)<=8
            or any(not _digest(v) for v in value) or len(value)!=len(set(value))):
        raise SafetyError('Explicit distinct signer certificate digests required')


def validate_policy(value):
    fields={'schema','product','kind','manifest_sha256','catalog_sha256','catalog_signers','payload_signers'}
    if isinstance(value,dict) and type(value.get('schema')) is int and value['schema']==2:
        fields |= {'runtime_public_key_sha256','runtime_signatures'}
    if (not isinstance(value,dict) or set(value)!=fields or type(value['schema']) is not int
            or value['schema'] not in (1,2) or value['product']!='ClaudeReset'
            or value['kind']!='exact_release_authority'
            or not _digest(value['manifest_sha256']) or not _digest(value['catalog_sha256'])
            or not isinstance(value['payload_signers'],dict) or set(value['payload_signers'])!=SIGNED_FILES):
        raise SafetyError('Exact release authority policy required')
    _signers(value['catalog_signers'])
    for signers in value['payload_signers'].values():_signers(signers)
    if value['schema']==2:
        if (not _digest(value['runtime_public_key_sha256'])
                or type(value['runtime_signatures']) is not dict
                or set(value['runtime_signatures'])!=RUNTIME_IMAGES
                or any(not _digest(v) for v in value['runtime_signatures'].values())):
            raise SafetyError('Exact runtime key and complete signature catalog required')
    return value


def verify_release_authority(payload,catalog,policy,*,runtime_signatures=None,runtime_public_key=None):
    anchor=TRUSTED_POLICY_SHA256
    if not _digest(anchor):raise SafetyError('No independently approved release authority is compiled')
    if (not isinstance(payload,PinnedPayload) or not isinstance(catalog,PinnedFile) or not catalog.handle
            or not isinstance(policy,PinnedFile) or not policy.handle or policy.sha256!=anchor):
        raise SafetyError('Held release and independently pinned authority policy required')
    payload.report();_check_digest(policy)
    if (not isinstance(policy.data,bytes) or len(policy.data)>65536
            or hashlib.sha256(policy.data).hexdigest()!=anchor):
        raise SafetyError('Bounded policy bytes must match the compiled authority anchor')
    value=validate_policy(document(policy.data,65536))
    if value['schema']==1 and (runtime_signatures is not None or runtime_public_key is not None):
        raise SafetyError('Legacy authority policy cannot approve runtime signatures')
    if value['schema']==2 and (runtime_signatures is None or runtime_public_key is None):
        raise SafetyError('Runtime authority policy requires held runtime inputs')
    manifest=payload.manifest
    manifest_hash=payload.manifest_sha256
    pins=dict(payload.pins)
    hashes={name:pin.sha256 for name,pin in pins.items()}
    catalog_hash=catalog.sha256

    def stable():
        payload.report()
        if (payload.manifest is not manifest or payload.manifest_sha256!=manifest_hash
                or manifest.sha256!=manifest_hash or set(payload.pins)!=set(pins)
                or any(payload.pins[name] is not pin or pin.sha256!=hashes[name] for name,pin in pins.items())
                or catalog.sha256!=catalog_hash or policy.sha256!=anchor
                or TRUSTED_POLICY_SHA256!=anchor):
            raise SafetyError('Release authority inputs changed during verification')
        for pin in (manifest,catalog,policy,*pins.values()):_check_digest(pin)
    stable()
    if payload.manifest_sha256!=value['manifest_sha256'] or catalog.sha256!=value['catalog_sha256']:
        raise SafetyError('Authority policy belongs to different release bytes')
    evidence=inspect_release_catalog(catalog,payload)
    if (evidence.get('catalog_authenticode_verified') is not True
            or evidence.get('manifest_membership_verified') is not True
            or evidence.get('catalog_sha256')!=catalog.sha256
            or evidence.get('manifest_sha256')!=payload.manifest_sha256
            or evidence.get('signer_certificate_sha256') not in value['catalog_signers']):
        raise SafetyError('Release catalog signer or membership is not approved')
    checked={}
    for name in sorted(SIGNED_FILES):
        pin=payload.pins[name];row=inspect_signature(pin)
        if (row.get('authenticode_verified') is not True or row.get('file_sha256')!=pin.sha256
                or row.get('signer_certificate_sha256') not in value['payload_signers'][name]):
            raise SafetyError('Payload signer is not approved for its exact component')
        checked[name]=dict(file_sha256=pin.sha256,signer_certificate_sha256=row['signer_certificate_sha256'])
    runtime=None
    if value['schema']==2:
        runtime=inspect_runtime_signature_set(payload,runtime_signatures,runtime_public_key,
                    value['runtime_public_key_sha256'],value['runtime_signatures'])
    stable()
    return dict(schema=1,authority_policy_sha256=anchor,manifest_sha256=payload.manifest_sha256,
                catalog_sha256=catalog.sha256,catalog_signer_certificate_sha256=evidence['signer_certificate_sha256'],
                payload_signers=checked,release_authority_verified=True,kernel_load_verified=False,
                runtime_signature_evidence=runtime,runtime_key_authority_verified=runtime is not None,
                embedded_key_binding_verified=False,staged_sidecars_verified=False,
                installable=False,client_admission=False,settings_changed=False)
