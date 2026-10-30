"""Compare Windows environment names without exporting or changing values."""
from __future__ import annotations

from typing import Any

from ..errors import SafetyError

__all__ = ['folded']


def folded(value: object) -> dict[str, Any]:
    if not isinstance(value,dict):
        raise SafetyError('Environment has an unknown schema')
    result={}
    for name,item in value.items():
        if not isinstance(name,str):
            raise SafetyError('Environment variable name has an unknown schema')
        key=name.upper()
        if key in result:
            raise SafetyError('Environment variable names collide on Windows')
        result[key]=item
    return result
