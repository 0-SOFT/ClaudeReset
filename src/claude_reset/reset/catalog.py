"""Version-bound ownership manifests. Unknown state is never a deletion wildcard."""
import re
from ..model.compatibility import CLIENTS
from .. import layout
CLI_VERSIONS = CLIENTS['code']['reset_versions']
EXTENSION_VERSIONS = CLIENTS['vscode']['reset_versions']
DESKTOP_VERSIONS = CLIENTS['desktop']['reset_versions']

CODE_ENTRIES = frozenset('''
.credentials.json .claude.json settings.json settings.local.json CLAUDE.md
projects history.jsonl agent-memory memory sessions file-history session-env
shell-snapshots paste-cache uploads feedback tasks todos plans backups ide
cache debug telemetry statsig statsig-cache stats-cache.json statsig.cached.evaluations
.last-cleanup
plugins skills commands hooks rules downloads update-lock locks .locks
mcp-needs-auth-cache.json remote-control-state.json bridge-state.json
'''.split())

# Application registration and key generations are deliberately preserved together.
# Account switching is separate from deleting an old CNG key (specification §7).
DESKTOP_REGISTRATION = frozenset({'ant-device-registry.json', 'ant-device-key-generation.json'})
DESKTOP_STATE = frozenset('''
config.json claude_desktop_config.json ant-did bridge-state.json remote-control-state.json
ssh-remote-server-state.json .hybrid-token-handoff custom3p-anthropic-console.json
custom3p-anthropic-console.json.journal Network Cookies Cookies-journal Cookies-wal Cookies-shm
Local\x00Storage Session\x00Storage IndexedDB Service\x00Worker CacheStorage WebStorage
Partitions Cache Code\x00Cache GPUCache DawnCache DawnGraphiteCache DawnWebGPUCache
sentry Crashpad Preferences Secure\x00Preferences Local\x00State DIPS DIPS-wal DIPS-shm
Reporting\x00and\x00NEL Trust\x00Tokens Trust\x00Tokens-journal SharedStorage
SharedStorage-wal shared_proto_db blob_storage VideoDecodeStats
buddy-tokens.json declarative_performance_observer.db-journal
File\x00System GPUPersistentCache GrShaderCache InterestGroups InterestGroups-wal
InterestGroups-shm lockfile ShaderCache Shared\x00Dictionary
'''.replace('\x00', '§').split())
DESKTOP_STATE = frozenset(s.replace('§', ' ') for s in DESKTOP_STATE)
DESKTOP_WORK = frozenset({'local-agent-mode-sessions', 'claude-code-sessions', 'git-shadow',
                          'scratch-workspaces', 'design', 'pending-uploads'})
DESKTOP_PRESERVE = DESKTOP_REGISTRATION | DESKTOP_WORK | frozenset('''
vm_bundles claude-code-vm claude-code logs Logs extensions extensions-install
window-state.json cowork-gb-cache.json cowork-enabled-cli-ops.json mcp-user-tool-toggles.json
git-worktrees.json extensions-blocklist.json ccd-session-presets.json plan-usage-history.json
fcache spaces-present rpm declarative_performance_observer.db
'''.split())

# Reviewed in the exact 3.6556.2 bundle. Conf replays path + '.journal';
# developer_settings is a separate, plain JSON allowDevTools preference.
DESKTOP_JOURNAL_VERSIONS = CLIENTS['desktop']['journal_versions']
DESKTOP_JOURNAL_STATE = frozenset({'config.json.journal'})
DESKTOP_DEVELOPER_PRESERVE = frozenset({'developer_settings.json'})

AUTH_VARS = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN',
             'ANTHROPIC_PROFILE', 'ANTHROPIC_FEDERATION_RULE_ID', 'ANTHROPIC_ORGANIZATION_ID',
             'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY',
             'ANTHROPIC_BASE_URL', 'CLAUDE_CODE_API_KEY_HELPER_TTL_MS',
             'CLAUDE_SECURESTORAGE_CONFIG_DIR', 'CLAUDE_CODE_FORCE_WINDOWS_CREDMAN')
AUTH_SETTINGS = frozenset({'apiKeyHelper', 'forceLoginMethod', 'forceLoginOrgUUID',
                           'awsAuthRefresh', 'awsCredentialExport', 'companyAnnouncements'})


def code_recovery_file(name):
    if name == layout.CODE_CONFIG:
        return True
    # Never treat an arbitrary user document sharing this prefix as recovery state.
    return bool(re.fullmatch(r'\.claude\.json\.(?:(?:backup|bak)(?:[.-][0-9][0-9T_-]{0,40})?|(?:tmp|corrupted)\.[0-9][0-9T_-]{0,40}|bk_[0-9][0-9T_-]{0,40})', name))
