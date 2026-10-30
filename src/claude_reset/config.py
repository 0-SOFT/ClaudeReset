"""Product constants that several modules share. Each value is defined here once.

Names that already exist on installed computers (tasks, packages, services, Program Files folders) are
fixed: changing one needs a migration of those computers.
"""

__all__ = ['BACKEND_API_PORT', 'BACKEND_PORT', 'BACKEND_TASK', 'BACKEND_URL', 'BACKEND_WORKER', 'CHROME_PROFILES',
           'CLAUDE_HOST', 'CONTROLLER_EXE', 'CONTROLLER_TASK', 'DESKTOP_PACKAGE', 'DESKTOP_POLICY_KEY',
           'DESKTOP_PROXY_VALUE', 'ENGINE_ROUTE_TAG', 'L1_PROGRAM', 'LOCAL_BACKEND_IDENTITY', 'LOOPBACK', 'NO_PROXY',
           'OWNED_PACKAGE', 'OWNED_PACKAGE_NAME', 'OWN_PORTS', 'PRODUCT_NAME', 'PROXY_VARIABLES', 'PYTHONW',
           'RECOVERY_TASK', 'RECOVERY_WATCH', 'RELAY_PORT', 'RELAY_URL', 'RUNNER_EXE', 'VSCODE_ENVIRONMENT',
           'VSCODE_WRAPPER', 'loopback_url']

PRODUCT_NAME = 'ClaudeReset'
PUBLISHER = '0-soft'             # the installer's publisher in Windows' list of apps

LOOPBACK = '127.0.0.1'
BACKEND_PORT = 25080       # local proxy of the selected tunnel engine
BACKEND_API_PORT = 25081   # the engine's loopback control API
RELAY_PORT = 25082         # the L1 relay protected clients connect to
OWN_PORTS = (BACKEND_PORT, BACKEND_API_PORT, RELAY_PORT)


def loopback_url(port):
    return f'http://{LOOPBACK}:{port}'


BACKEND_URL = loopback_url(BACKEND_PORT)
RELAY_URL = loopback_url(RELAY_PORT)
PROXY_VARIABLES = ('HTTP_PROXY', 'HTTPS_PROXY')
NO_PROXY = 'localhost,127.0.0.1,::1'
CLAUDE_HOST = 'claude.ai'
USER_AGENT = PRODUCT_NAME          # the program's own HTTP checks; no version, nothing that identifies the PC

CONTROLLER_TASK = 'ClaudeReset L1 Controller'
RECOVERY_TASK = 'ClaudeReset L1 Recovery'
# Names installed by 1.0.x. They carry the name of the tunnel first used on the development computer;
# installed tasks, engine configurations, WFP sublayers and reports still hold them, so they stay as values.
BACKEND_TASK = 'ClaudeReset-SnowProxy'
ENGINE_ROUTE_TAG = 'snow-only'                              # the engine's single outbound and final route
LOCAL_BACKEND_IDENTITY = 'installed_reviewed_snow_vless_reality'  # tunnel identity in controller plans

CONTROLLER_EXE = 'ClaudeReset.exe'
RUNNER_EXE = 'ClaudeResetRun.exe'
L1_PROGRAM = 'ClaudeReset-L1'           # Program Files folder of the installed L1 controller and runner
BACKEND_WORKER = 'proxy_worker.py'       # the backend task's script, in the backend's working folder
RECOVERY_WATCH = 'l1_recovery_watch.py'  # the script the recovery task runs (tools/)
CHROME_PROFILES = 'ChromeProfiles'       # fresh Chrome profiles of the Claude site, in the state root
PYTHONW = 'pythonw.exe'

DESKTOP_PACKAGE = ('Claude_pzs8sxrjxfjjc', 'Claude')        # (package family, application id)
# Claude Desktop's proxy policy, under HKCU and HKLM; the controller points it at the relay.
DESKTOP_POLICY_KEY = r'SOFTWARE\Policies\Claude'
DESKTOP_PROXY_VALUE = 'egressProxyUrl'
OWNED_PACKAGE_NAME = 'ClaudeReset.NetworkIsolation'
OWNED_PACKAGE = ('ClaudeReset.NetworkIsolation_79st3xwgefr0c', 'IsolatedTools')


# Settings of the Claude Code extension that the program writes into VS Code.
VSCODE_ENVIRONMENT = 'claudeCode.environmentVariables'
VSCODE_WRAPPER = 'claudeCode.claudeProcessWrapper'
