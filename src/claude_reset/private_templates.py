"""Prepare templates for an exclusively owned Sandboxie runtime, never install.

Only a pinned reviewed vendor input is accepted. This must not be applied to a
shared/user Sandboxie installation. File ACLs, ownership of the runtime, process
readback and broker acceptance are separate mandatory controller checks.
"""
import hashlib
from .safeio import SafetyError

REVIEWED_INPUTS = {'c9e06a889ed23f1689b8dfca1210015c256ea71477b2e33b34feb0dc6fb07933': 23}


def close_default_windows(data):
    if not isinstance(data, bytes):
        raise SafetyError('Template bytes required')
    digest=hashlib.sha256(data).hexdigest()
    if digest not in REVIEWED_INPUTS:
        raise SafetyError('Unreviewed Sandboxie template version')
    section=None;seen=0;removed=[];kept=[]
    for line in data.splitlines(keepends=True):
        value=line.strip()
        if value.startswith(b'[') and value.endswith(b']'):
            section=value.lower()
            if section==b'[templatedefaultpaths]':seen+=1
        if section==b'[templatedefaultpaths]' and value.lower().startswith(b'openwinclass='):
            removed.append(value.split(b'=',1)[1].decode('utf-8'));continue
        kept.append(line)
    if seen!=1 or len(removed)!=REVIEWED_INPUTS[digest]:
        raise SafetyError('Reviewed template structure changed')
    output=b''.join(kept)
    return output,{'source_sha256':digest,'output_sha256':hashlib.sha256(output).hexdigest(),
                  'removed_default_window_exceptions':len(removed),
                  'requires_exclusive_owned_runtime':True,'installed':False,
                  'production_clients_permitted':False,'full_tunnel_verified':False}
