"""Explicit reproducible-build inputs for frozen candidates, not runtime policy."""
import hashlib,importlib.metadata,os,sys
from pathlib import Path


def environment(output,source_date_epoch):
    if source_date_epoch is not None and (type(source_date_epoch) is not int or not 0<=source_date_epoch<=0xFFFFFFFF):
        raise ValueError('PE source date epoch must be an explicit unsigned 32-bit integer')
    env=dict(os.environ)
    for name in list(env):
        if name.upper() in ('SOURCE_DATE_EPOCH','PYTHONHASHSEED','PYTHONPATH','PYTHONHOME','PYTHONSTARTUP','PYTHONINSPECT','PYINSTALLER_CONFIG_DIR'):
            del env[name]
    env['PYINSTALLER_CONFIG_DIR']=str(Path(output).resolve()/'pyinstaller-cache')
    if source_date_epoch is not None:
        env['SOURCE_DATE_EPOCH']=str(source_date_epoch);env['PYTHONHASHSEED']='0'
    receipt=dict(schema=1,source_date_epoch=source_date_epoch,pythonhashseed='0' if source_date_epoch is not None else None,
                 isolated_build_cache=True,recipe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 python_version=sys.version,pyinstaller_version=importlib.metadata.version('pyinstaller'))
    return env,receipt
