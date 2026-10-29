"""Compare Windows environment names without exporting or changing values."""
from .safeio import SafetyError


def folded(value):
    if not isinstance(value,dict):raise SafetyError('Environment has an unknown schema')
    result={}
    for name,item in value.items():
        if not isinstance(name,str):raise SafetyError('Environment variable name has an unknown schema')
        key=name.upper()
        if key in result:raise SafetyError('Environment variable names collide on Windows')
        result[key]=item
    return result
