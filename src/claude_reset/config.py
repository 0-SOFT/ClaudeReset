"""Product constants that several modules share. Each value is defined here once.

Names that already exist on installed computers (tasks, packages, services, Program Files folders) are
fixed: changing one needs a migration of those computers.
"""
from types import MappingProxyType

PRODUCT_NAME = 'ClaudeReset'

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

CONTROLLER_TASK = 'ClaudeReset L1 Controller'
RECOVERY_TASK = 'ClaudeReset L1 Recovery'
# Names installed by 1.0.x. They carry the name of the tunnel first used on the development computer;
# installed tasks, engine configurations, WFP sublayers and reports still hold them, so they stay as values.
BACKEND_TASK = 'ClaudeReset-SnowProxy'
ENGINE_ROUTE_TAG = 'snow-only'                              # the engine's single outbound and final route
LOCAL_BACKEND_IDENTITY = 'installed_reviewed_snow_vless_reality'  # tunnel identity in controller plans
LEGACY_WFP_MARKS = MappingProxyType({'desktop': b'ClaudeReset-Snow-Desktop-v1', 'code': b'ClaudeReset-Code-Snow-v1',
                                     'owned': b'ClaudeReset-Owned-Identity-Snow-v1'})

CONTROLLER_EXE = 'ClaudeReset.exe'
RUNNER_EXE = 'ClaudeResetRun.exe'
PYTHONW = 'pythonw.exe'

DESKTOP_PACKAGE = ('Claude_pzs8sxrjxfjjc', 'Claude')        # (package family, application id)
# Claude Desktop's proxy policy, under HKCU and HKLM; the controller points it at the relay.
DESKTOP_POLICY_KEY = r'SOFTWARE\Policies\Claude'
DESKTOP_PROXY_VALUE = 'egressProxyUrl'
OWNED_PACKAGE_NAME = 'ClaudeReset.NetworkIsolation'
OWNED_PACKAGE = ('ClaudeReset.NetworkIsolation_79st3xwgefr0c', 'IsolatedTools')

BACKEND_SERVICE = 'ClaudeResetBackend'
GATEWAY_SERVICE = 'ClaudeResetGateway'
BACKEND_FIXTURE_SERVICE = 'ClaudeResetBackendFixture'   # disposable services of the service tests
GATEWAY_FIXTURE_SERVICE = 'ClaudeResetGatewayFixture'
# Windows services of the prepared service bundle, in inventory order: our two, then the Sandboxie broker.
BUNDLE_SERVICES = (BACKEND_SERVICE, GATEWAY_SERVICE, 'SbieSvc', 'SbieDrv')

# Settings of the Claude Code extension that the program writes into VS Code.
VSCODE_ENVIRONMENT = 'claudeCode.environmentVariables'
VSCODE_WRAPPER = 'claudeCode.claudeProcessWrapper'
