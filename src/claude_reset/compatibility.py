"""Reviewed capabilities, not blanket approval based on a familiar version string.

User-specific executable hashes belong to the selected private profile. This
manifest records source/schema compatibility; network admission still requires
live installed-boundary attestation and never follows from reset support.
"""
SCHEMA = 1
CLIENTS = {
    'code': {
        'reset_versions': frozenset({'2.1.274', '2.1.274.0'}),
        'launch_verified_versions': frozenset(),
        'network_verified_versions': frozenset(),
        'privacy_verified_versions': frozenset(),
    },
    'vscode': {
        # 2.1.301, 2.1.310 and 2.1.311 were added by the owner's decision of 28 Oct 2026 after a read-only structural
        # run on real installs (2.1.310: only 'close the processes' remained). The runtime gates stay in force for every
        # version: unknown database keys, SecretStorage entries and unknown profile entries still block the reset.
        'reset_versions': frozenset({'2.1.301', '2.1.307', '2.1.308', '2.1.309', '2.1.310', '2.1.311'}),
        'launch_verified_versions': frozenset(),
        'network_verified_versions': frozenset(),
        'privacy_verified_versions': frozenset(),
    },
    'desktop': {
        # 4.29.0.0 and 2.31226.1.0: owner's decision of 28 Oct 2026 (file-level reset only; the account-key reset below stays
        # bound to the exact app.asar/native-module hash pairs and still refuses these versions).
        'reset_versions': frozenset({'3.1623.4', '3.1623.4.0', '3.6556.1', '3.6556.1.0', '3.6556.2', '3.6556.2.0',
                                     '4.29.0', '4.29.0.0', '2.31226.1', '2.31226.1.0'}),
        'journal_versions': frozenset({'3.6556.2', '3.6556.2.0', '4.29.0', '4.29.0.0', '2.31226.1', '2.31226.1.0'}),
        # Exact (app.asar, native binding) identities for the account-key reset
        # adapter only. These do not approve launch, networking or privacy.
        'native_reset_hashes': {
            '3.1623.4.0': (
                '68b9db416f68d88620423f8de55d9a77c033ad5a531c02dda34775c45755f534',
                '7a81cf0ad4ce21042303e35acf079cf8be180a63ae177d8414ed34b817ca83eb'),
            '3.6556.1.0': (
                'bf6735ef514a3c87efb1aa5d83cd1c43a9ea35295322622e9d81d8e261becf98',
                '6a0ff2868548883c66ef8fdc3444909ffeaeb95ea7419f0bf6278e2f7961d417'),
            '3.6556.2.0': (
                '3e9cb8e8034e75d9e1996f960169877c556e17a454041a25233b372493fec9ac',
                '84262e180eca096b3f444deb8c268e4b3f1c49ef5da94f30e6d3346daf6c3d74'),
        },
        'launch_verified_versions': frozenset(),
        'network_verified_versions': frozenset(),
        'privacy_verified_versions': frozenset(),
    },
}
DEPENDENCIES = {
    'sing-box': {'windows_amd64_images': {
        '1.14.4': '8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9',
    }},
    'sandboxie': {'source_tag':'v1.18.8', 'installed_hardening_accepted':False,
                 'source_integrity_manifests':('tools/prepare_sandboxie_hardening.py', 'tools/prepare_sandboxie_helper_hardening.py')},
    'ewdk': {'kit':'26100.6584', 'visual_studio':'2022', 'build_verified':False},
}

# Historical, hash-bound code review used by the legacy local guard. These
# hashes are NOT a live network/launch/privacy acceptance claim.
LEGACY_REVIEW = {
    'desktop': {'version':'3.6556.2.0',
                'exe':'3e25bd63028e315b3dd1f375e02e5958a6cb6567d885e6005a517d2394686afa',
                'asar':CLIENTS['desktop']['native_reset_hashes']['3.6556.2.0'][0]},
    'launch': {'chrome':'de999bce6a1c954df71a8f15bf751b336172f55ac1a0325bb0580cbc2121268c',
               'vscode':'325fb30ba28d17fa6ba4df58043727b2469aca9d641793a65e413721b2110ec6'},
    'standalone_code':'4e4c1746aff835bb05e5ed14cda72d21ee6fbda4147aa99b3135718614da117e',
    'dedicated_extension':('2.1.309','5441781f2b6bbd07354b4a74560ee88c68c9bf05d6db3c7e24c452c91673dc53'),
}


def supports(component, version, capability='reset'):
    fields = {'reset':'reset_versions', 'launch':'launch_verified_versions',
              'network':'network_verified_versions', 'privacy':'privacy_verified_versions'}
    if capability not in fields:
        return False
    return version in CLIENTS.get(component, {}).get(fields[capability], ())
