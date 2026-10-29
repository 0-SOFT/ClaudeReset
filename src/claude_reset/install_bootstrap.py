"""Recover only an empty, recorded directory bootstrap, never an installation.

No service, policy or network mutation; no elevation or adoption of legacy roots.
A crash before ownership was durably recorded remains a manual recovery blocker.
"""
from copy import deepcopy
import json
import os
import uuid
from .backend_spec import document
from .safeio import SafetyError
from .windows_pin import PinnedFile
from . import install_store as store_module

ORDER=('root',*store_module.FOLDERS)


def validate(value,transaction):
    if (not isinstance(value,dict) or set(value)!={'schema','generation','package_sha256','directories'}
            or type(value['schema']) is not int or value['schema']!=1
            or any(value[k]!=transaction[k] for k in ('generation','package_sha256'))):
        raise SafetyError('Invalid bootstrap ownership receipt')
    rows=value['directories']
    if not isinstance(rows,list) or not 2<=len(rows)<=len(ORDER):
        raise SafetyError('Invalid bootstrap directory sequence')
    for index,row in enumerate(rows):
        if (not isinstance(row,dict) or set(row)!={'name','identity'} or row['name']!=ORDER[index]
                or not isinstance(row['identity'],list) or len(row['identity'])!=5
                or any(type(n) is not int or not 0<=n<=0xffffffff for n in row['identity'])):
            raise SafetyError('Invalid bootstrap directory identity')
    return deepcopy(value)


class DirectoryReceipts:
    def __init__(self,journal):
        self.journal=journal
        self.path=journal.directory/'directory-receipts.json'

    def transaction(self):
        if not self.journal.lock:raise SafetyError('Bootstrap lock is not held')
        value=self.journal.load()
        if value is None:raise SafetyError('Bootstrap journal is missing')
        return value

    def load(self):
        transaction=self.transaction()
        with PinnedFile(self.path,limit=65536) as pin:
            return validate(document(pin.data),transaction)

    def save(self,value):
        value=validate(value,self.transaction())
        temporary=self.journal.directory/('directories-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
            stream.flush();os.fsync(stream.fileno())
        if not self.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Cannot commit directory ownership')
        if self.load()!=value:raise SafetyError('Directory ownership readback differs')

    def begin(self,root,installer):
        if self.path.exists():raise SafetyError('Existing bootstrap receipt cannot be adopted')
        transaction=self.transaction()
        self.save(dict(schema=1,generation=transaction['generation'],package_sha256=transaction['package_sha256'],
            directories=[dict(name='root',identity=root.receipt_identity),
                         dict(name='Installer',identity=installer.receipt_identity)]))

    def record(self,name,directory):
        value=self.load()
        value['directories'].append(dict(name=name,identity=directory.receipt_identity))
        self.save(value)


def recover_bootstrap(generation,package_sha256):
    """Finish only missing empty directories with matching protected ownership.

    Caller still needs authenticated payload and closed-client checks before any
    staging. This function grants no installation or client network admission.
    """
    m=store_module
    expected=m.Transaction(None,generation,package_sha256).value
    m._require_admin()
    result=m.Store()
    try:
        parent=m.Directory(m.program_files());result.directories['parent']=parent
        m._verify_parent(parent)
        m._require_vacant_service_slots()
        root=m.Directory(parent.path/'ClaudeReset');result.directories['root']=root
        installer=m.Directory(root.path/'Installer');result.directories['Installer']=installer
        m.verify_paths([root.path,installer.path],[root.path,installer.path])
        # Verify metadata ACL before acquiring a journal lock or reading it.
        metadata=[installer.path/name for name in
                  ('install.lock','install-journal.json','directory-receipts.json')]
        m.verify_paths(metadata,[])
        result.journal=m._LocalFile(installer.path)
        if result.journal.load()!=expected:
            raise SafetyError('Only the matching empty bootstrap journal can be recovered')
        receipts=DirectoryReceipts(result.journal)
        rows=receipts.load()['directories']
        recorded={r['name']:r['identity'] for r in rows}
        # Hold and validate every recorded directory before making any change.
        for name in ORDER:
            path=root.path if name=='root' else root.path/name
            if name not in recorded:
                try:path.lstat()
                except FileNotFoundError:continue
                raise SafetyError('Unrecorded bootstrap directory; no adoption')
            if name not in result.directories:result.directories[name]=m.Directory(path)
            if result.directories[name].receipt_identity!=recorded[name]:
                raise SafetyError('Bootstrap directory was replaced')
        held=[d.path for key,d in result.directories.items() if key!='parent']
        m.verify_paths(held,held)
        # An empty bootstrap must contain only recorded directories and metadata.
        allowed={d.path for key,d in result.directories.items() if key!='parent'}|set(metadata)
        for key,directory in result.directories.items():
            if key=='parent':continue
            if any(p not in allowed for p in directory.path.iterdir()):
                raise SafetyError('Unexpected bootstrap contents; recovery stopped')
        for name in ORDER[len(rows):]:
            m._require_vacant_service_slots()
            parts=name.split('/')
            parent_dir=root if len(parts)==1 else result.directories[parts[0]]
            acl=m.RUNTIME_READ if parts[0]=='Sandboxie' else m.PRIVATE
            child=m._create_child(parent_dir,parts[-1],acl)
            result.directories[name]=child
            receipts.record(name,child)
        held=[d.path for key,d in result.directories.items() if key!='parent']
        m.verify_paths(held,held)
        m._require_vacant_service_slots()
        return result
    except BaseException:result.close();raise
