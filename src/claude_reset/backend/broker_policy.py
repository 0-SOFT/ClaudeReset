"""Fixed isolation settings of the experimental process boundary (tools/prepare_managed_config.py).

The tested restrictions are not a complete IPC allowlist; closing LSA policy lookup prevents
bootstrap on the tested Windows version. Nothing here grants production network permission.
"""
from types import MappingProxyType

ISOLATION_SETTINGS = MappingProxyType({
    'ClaudeResetStrictBroker':'y','DropAdminRights':'y','NoSecurityIsolation':'n','DisableObjectFilter':'n',
    'UseRuleSpecificity':'n','UseSecurityMode':'n','RestrictDevices':'n','UsePrivacyMode':'n',
    'BlockNetworkFiles':'y','OriginalToken':'n','UnrestrictedToken':'n','OpenToken':'n',
    'UnfilteredToken':'n','ReplicateToken':'n','UnstrippedToken':'n','KeepTokenIntegrity':'n',
    'NtNamespaceIsolation':'y','NoAddProcessToJob':'n','OpenWndStation':'n',
    'RunServicesAsSystem':'n','RunRpcssAsSystem':'n','MsiInstallerExemptions':'n'})
FORBIDDEN_SETTINGS = ('BreakoutProcess','BreakoutFolder','BreakoutDocument','DisableWinNtHook',
                      'OpenWinClass','OpenPipePath','Template','IncludeBox',
                      'OpenIpcPath','ReadIpcPath','ApproveWinNtSysCall')
