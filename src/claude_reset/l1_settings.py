"""What the L1 install writes or registers on purpose, so the reset can tell it from foreign launch settings.

Only exact values are recognised: the three proxy variables pointing at the local relay and the
installed runner path. Anything else in those settings still needs review.
"""
import os
from pathlib import Path

RELAY_URL = 'http://127.0.0.1:25082'
OWNED_ENV = (('HTTP_PROXY', RELAY_URL), ('HTTPS_PROXY', RELAY_URL), ('NO_PROXY', 'localhost,127.0.0.1,::1'))
RUNNER = 'ClaudeResetRun.exe'
OWNED_PACKAGE_NAME = 'ClaudeReset.NetworkIsolation'
OWNED_TASKS = ('ClaudeReset L1 Controller', 'ClaudeReset-SnowProxy', 'ClaudeReset L1 Recovery')


def runner_path():
    return Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'ClaudeReset-L1' / RUNNER


def owned_launch_settings(settings):
    """True when claudeCode.environmentVariables / claudeProcessWrapper hold only ClaudeReset's own values."""
    env, wrapper = settings.get('claudeCode.environmentVariables'), settings.get('claudeCode.claudeProcessWrapper')
    if env not in (None, []):
        if not isinstance(env, list) or not all(isinstance(i, dict) and set(i) == {'name', 'value'} for i in env):
            return False
        if sorted((i['name'], i['value']) for i in env) != sorted(OWNED_ENV):
            return False
    if wrapper not in (None, ''):
        if not isinstance(wrapper, str) or os.path.normcase(os.path.normpath(wrapper)) != os.path.normcase(str(runner_path())):
            return False
    return True
