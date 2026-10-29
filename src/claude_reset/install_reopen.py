"""Reopen recorded installation directories for recovery, without mutation authority.

No directory creation, service control or client admission. The returned store
only holds the generation and lock; rollback still requires revocation/readback.
"""
from . import install_store as m
from .install_bootstrap import DirectoryReceipts,ORDER
from .install_transaction import TERMINAL
from .safeio import SafetyError


def open_recovery_store(generation,package_sha256):
    m.Transaction(None,generation,package_sha256)  # validate requested identity
    m._require_admin()
    result=m.Store()
    try:
        parent=m.Directory(m.program_files());result.directories['parent']=parent
        m._verify_parent(parent)
        root=m.Directory(parent.path/'ClaudeReset');result.directories['root']=root
        installer=m.Directory(root.path/'Installer');result.directories['Installer']=installer
        m.verify_paths([root.path,installer.path],[root.path,installer.path])
        metadata=[installer.path/name for name in
                  ('install.lock','install-journal.json','directory-receipts.json')]
        m.verify_paths(metadata,[])
        result.journal=m._LocalFile(installer.path)
        transaction=result.journal.load()
        if (transaction is None or transaction['generation']!=generation
                or transaction['package_sha256']!=package_sha256 or transaction['state'] in TERMINAL):
            raise SafetyError('Recovery requires the matching unfinished installation')
        rows=DirectoryReceipts(result.journal).load()['directories']
        if len(rows)!=len(ORDER):raise SafetyError('Incomplete bootstrap needs separate bootstrap recovery')
        for row in rows:
            name=row['name']
            if name not in result.directories:result.directories[name]=m.Directory(root.path/name)
            held=result.directories[name]
            if held.receipt_identity!=row['identity']:raise SafetyError('Recorded installation directory was replaced')
        paths=[d.path for key,d in result.directories.items() if key!='parent']
        m.verify_paths(paths,paths)
        # Optional recovery evidence must also be administrator-controlled.
        for name in ('stage-receipts.json','service-receipts.json','configuration-receipts.json','runtime-signature-receipts.json',
                     'policy-binding-receipt.json','service-removal-receipts.json','boundary-receipt.json',
                     'reservation-receipt.json','service-marker-receipts.json','service-reconciliation-log.json',
                     'pending-creation-cleanup.json','boundary-reconciliation-log.json','reservation-reconciliation-log.json'):
            path=installer.path/name
            try:path.lstat()
            except FileNotFoundError:continue
            m.verify_paths([path],[])
        return result
    except BaseException:result.close();raise
