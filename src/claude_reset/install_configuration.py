"""Compile private installation inputs; no files, registry, services or network I/O.

The result contains credentials in memory. Its diagnostic representation contains
only identities/hashes. It is not a signed release or permission to apply policy.
"""
import hashlib
import json
from . import backend_spec
from .install_payload import catalog
from .broker_policy import closed_policy
from .safeio import SafetyError

BOXES=('ClaudeReset.Desktop','ClaudeReset.Code','ClaudeReset.Editor','ClaudeReset.Web','ClaudeReset.Tools')
FILES=('Backend/backend.json','Engine/engine.json','Policy/Sandboxie.ini')


class Configuration:
    __slots__=('_files',)
    def __init__(self,files):self._files=tuple(files)
    def __repr__(self):return '<Prepared private installation configuration; client_admission=False>'
    def files(self):return self._files
    def report(self):
        return {'schema':1,'files':{name:{'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
                                   for name,data in self._files},
                'client_admission':False,'installable':False,'settings_changed':False,
                'local_roots_verified':False,'effective_policy_verified':False,
                'cowork_guest_boundary_verified':False}


def compile_configuration(spec_bytes,engine_bytes,payload,local_roots):
    """Bind all inputs before producing the complete closed initial INI.

    Actual local-volume checks, protected staging, registry IniPath, signatures,
    runtime readback and all client/Cowork acceptance remain adapter obligations.
    No caller-supplied INI fragment, path, command or network permit is accepted.
    """
    payload=catalog(payload)
    spec=backend_spec.decode(spec_bytes)
    backend_spec.bind_config(spec,engine_bytes)
    for field,name in [('engine_sha256','Engine/engine.exe'),
                       ('runtime_sha256','Runtime/ClaudeResetRuntime.exe'),
                       ('gateway_sha256','Gateway/ClaudeResetGateway.exe')]:
        if spec[field]!=payload[name]['sha256']:
            raise SafetyError('Private configuration does not match the pinned release payload')
    # Global controls must be explicit: the managed driver imports no implicit
    # default templates. Per-box sections cannot introduce templates or permits.
    policy='[GlobalSettings]\nNetworkEnableWFP=y\nEnableObjectFiltering=y\n'
    for name in BOXES:policy+='\n'+closed_policy(name,local_roots)
    canonical=json.dumps(spec,sort_keys=True,separators=(',',':')).encode('utf-8')
    return Configuration(zip(FILES,(canonical,engine_bytes,b'\xff\xfe'+policy.encode('utf-16-le'))))
