"""What the L1 install writes or registers on purpose, so the reset can tell it from foreign launch settings.

Only exact values are recognised: the three proxy variables pointing at the local relay and the
installed runner path. Anything else in those settings still needs review.
"""
import os

from .. import config, layout
from ..model.records import exact

__all__ = ['OWNED_ENV', 'owned_launch_settings', 'runner_path']

OWNED_ENV = (*((name, config.RELAY_URL) for name in config.PROXY_VARIABLES), ('NO_PROXY', config.NO_PROXY))


def runner_path():
    return layout.l1_program() / config.RUNNER_EXE


def owned_launch_settings(settings):
    """True when claudeCode.environmentVariables / claudeProcessWrapper hold only ClaudeReset's own values."""
    env, wrapper = settings.get(config.VSCODE_ENVIRONMENT), settings.get(config.VSCODE_WRAPPER)
    if env not in (None, []):
        if not isinstance(env, list) or not all(exact(i, ('name', 'value')) for i in env):
            return False
        if sorted((i['name'], i['value']) for i in env) != sorted(OWNED_ENV):
            return False
    if wrapper not in (None, ''):
        if not isinstance(wrapper, str) or os.path.normcase(os.path.normpath(wrapper)) != os.path.normcase(str(runner_path())):
            return False
    return True
