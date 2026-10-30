import ctypes as C
import hashlib
import json
import uuid
from dataclasses import asdict

import pytest
from wfp_fakes import fake

from claude_reset.network import strict_wfp as s
from claude_reset.safeio import SafetyError
from claude_reset.windows import wfp


def image(tmp_path):
    p = tmp_path / 'engine.exe'; p.write_bytes(b'fixture')
    return s.Identity('app', str(p))


def test_legacy_filter_keys_and_serialization_remain_unchanged(tmp_path):
    ident = image(tmp_path)
    rule = s.Rule(ident, 'connect_v4')
    old = dict(identity=asdict(ident), layer='connect_v4', action=s.BLOCK, address=None, port=None, persistent=True)
    assert asdict(rule) == old
    assert rule.key.value() == str(uuid.uuid5(s.NAMESPACE, json.dumps(old, sort_keys=True)))
    old_pin = dict(identity=asdict(ident), role='pinned_endpoint', layer='connect_v4')
    assert s.Rule(ident, 'connect_v4', s.PERMIT, '1.1.1.1', 443).key.value() == str(uuid.uuid5(s.NAMESPACE, json.dumps(old_pin, sort_keys=True)))


