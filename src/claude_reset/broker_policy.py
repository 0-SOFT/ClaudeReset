"""Compile a closed, provider-independent experimental process-boundary policy.

No installation, service reload, client launch or network permission occurs here.
The tested restrictions are not a complete IPC allowlist. In particular, closing
LSA policy lookup prevents bootstrap on the tested Windows version; that unresolved
broker must not be silently treated as safe or grant production permission.
"""
from __future__ import annotations
import re
from .safeio import SafetyError

RPC_DENIES = ('AppV-ISV-*','AudioClientRpc','AudioSrv','C2RClientAPI_Server_System*',
    'ClickToRun_Pipeline*','dhcpcsvc','dhcpcsvc6','DNSResolver','LiveIdSvc','LSARPC_ENDPOINT',
    'lsasspirpc','MidiSrvClientRpc','NCWTSAudioServer','nlaapi','OSPPCTransportEndpoint-*',
    'RasManLrpc','RasmanRpc','samss lpc','senssvc','SLCTransportEndpoint-*','splwow64_*_0',
    'splwow64_*_2000','spoolss','SPPCTransportEndpoint-*','tapsrvlpc','umpdproxy_*_0',
    'umpdproxy_*_2000','umpo','webcache_*','wpcsvc')
DEVICE_DENIES = ('Http\\*','NetBT_Tcpip_*','QWAVEdrv*','Nsi*','Tcp*','Udp*','Ip*','RawIp*',
    'NamedPipe\\*_doPDF*','NamedPipe\\Adobe LM Service*','NamedPipe\\AudioSrv',
    'NamedPipe\\ProtectedPrefix\\LocalService\\FTHPIPE','NamedPipe\\ROUTER',
    'NamedPipe\\ShimViewer','NamedPipe\\spooler*','NamedPipe\\spoolss',
    'NamedPipe\\UIA_PIPE_*','NamedPipe\\XTIERRPCPIPE')
ISOLATION_SETTINGS = {'ClaudeResetStrictBroker':'y','DropAdminRights':'y','NoSecurityIsolation':'n','DisableObjectFilter':'n',
    'UseRuleSpecificity':'n','UseSecurityMode':'n','RestrictDevices':'n','UsePrivacyMode':'n',
    'BlockNetworkFiles':'y','OriginalToken':'n','UnrestrictedToken':'n','OpenToken':'n',
    'UnfilteredToken':'n','ReplicateToken':'n','UnstrippedToken':'n','KeepTokenIntegrity':'n',
    'NtNamespaceIsolation':'y','NoAddProcessToJob':'n','OpenWndStation':'n',
    'RunServicesAsSystem':'n','RunRpcssAsSystem':'n','MsiInstallerExemptions':'n'}
FORBIDDEN_SETTINGS = ('BreakoutProcess','BreakoutFolder','BreakoutDocument','DisableWinNtHook',
                      'OpenWinClass','OpenPipePath','Template','IncludeBox',
                      'OpenIpcPath','ReadIpcPath','ApproveWinNtSysCall')


def closed_policy(box_name, local_drive_roots):
    if not isinstance(box_name, str) or not re.fullmatch(r'ClaudeReset[.][A-Za-z0-9_]{1,20}', box_name):
        raise SafetyError('An owned ClaudeReset box name is required')
    if not isinstance(local_drive_roots, list) or not local_drive_roots:
        raise SafetyError('Explicit local drive roots are required')
    roots = []
    for root in local_drive_roots:
        if not isinstance(root, str) or not re.fullmatch(r'[A-Za-z]:\\', root):
            raise SafetyError('Only whole local drive roots are supported; no folder whitelist or network paths')
        roots.append(root.upper())
    if len(set(roots)) != len(roots):
        raise SafetyError('Duplicate drive roots')
    lines = [f'[{box_name}]', 'Enabled=y', 'ConfigLevel=9', 'AutoRecover=n', 'AutoDelete=n',
             *[key+'='+value for key,value in ISOLATION_SETTINGS.items()], 'NetworkAccess=*,Block',
             *['OpenFilePath=' + root + '*' for root in sorted(roots)],
             r'ClosedFilePath=\Device\Mup*', r'ClosedFilePath=\Device\LanmanRedirector*',
             *['ClosedIpcPath=\\RPC Control\\'+name for name in RPC_DENIES],
             r'ClosedIpcPath=\NLAPublicPort',
             *['ClosedFilePath=\\Device\\'+name for name in DEVICE_DENIES],
             r'ClosedKeyPath=HKEY_LOCAL_MACHINE\SYSTEM\ControlSet*\Services\Tcpip*',
             r'ClosedKeyPath=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip*',
             r'ClosedKeyPath=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList*',
             'ClosedClsid=*', 'ClosedClsid={4991D34B-80A1-4291-83B6-3328366B9097}',
             'ClosedClsid={0F87369F-A4E5-4CFC-BD3E-73E6154572DD}']
    return '\n'.join(lines) + '\n'


def inspect_local_roots(roots):
    """Installer preflight: a drive letter can refer to a mapped network share."""
    import ctypes as C
    from ctypes import wintypes as W
    closed_policy('ClaudeReset.Preflight',roots)
    kernel=C.WinDLL('kernel32',use_last_error=True)
    kernel.GetDriveTypeW.argtypes=[W.LPCWSTR];kernel.GetDriveTypeW.restype=W.UINT
    for root in roots:
        if kernel.GetDriveTypeW(root) not in (2,3,6):
            raise SafetyError('Only present local fixed/removable/RAM volumes can receive file access')
    return sorted(root.upper() for root in roots)


def gate_rule(port):
    """A rule value, never an authorization to install it without a live lease."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise SafetyError('An exact local gateway port is required')
    return f'*,Allow;Address=127.0.0.1;Port={port};Protocol=TCP'


def verify_network_rules(actual, *, gateway_port=None):
    expected = ['*,Block']
    if gateway_port is not None:
        expected.append(gate_rule(gateway_port))
    # Reject inherited positive rules and unknown templates as well as missing
    # denies. Checking the text file alone is insufficient: use driver readback.
    if actual != expected:
        raise SafetyError('Effective driver network rules differ from the requested scope')
    return {'network_rule_readback_matches': True, 'full_tunnel_verified': False,
            'production_open_supported': False,
            'remaining': ['controller_lifetime_lease', 'complete_ipc_boundary',
                          'control_files_and_broker_integrity',
                          'working_client_compatibility', 'cowork_guest_boundary',
                          'local_network_metadata','lsa_lookup_bootstrap']}


def verify_effective_settings(actual, *, gateway_port=None, runtime_open_windows=None):
    """Require driver-resolved settings, not just the generated INI file.

    Even matching settings are not sufficient evidence to open real clients.
    QueryConf omits default window classes appended during process initialization.
    Require the process-specific QueryPathList('wo') result separately. The caller
    must bind both observations to its live process and immutable configuration.
    """
    if not isinstance(actual,dict):raise SafetyError('Driver settings unavailable')
    for key,value in {**ISOLATION_SETTINGS,'NetworkEnableWFP':'y'}.items():
        if actual.get(key)!=[value]:raise SafetyError('Unexpected inherited isolation setting: '+key)
    for key in FORBIDDEN_SETTINGS:
        if actual.get(key)!=[]:raise SafetyError('Unreviewed process or broker exception: '+key)
    if runtime_open_windows != []:
        raise SafetyError('Process window exceptions missing or unreviewed')
    return verify_network_rules(actual.get('NetworkAccess'),gateway_port=gateway_port)
