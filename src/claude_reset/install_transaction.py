"""Fail-closed installation sequencing, independent of privileged Windows I/O.

The adapter must hold an exclusive protected installation lock for this object's
entire lifetime. Its operations accept no commands from a package or journal.
There is intentionally no production adapter or automatic elevation here yet.
"""
from copy import deepcopy
import re
from .safeio import SafetyError

STEPS = ('inventory_backup', 'close_clients', 'stage_protected_files',
         'install_services', 'verify_installed', 'fixture_acceptance')
TERMINAL = {'prepared_clients_closed', 'rolled_back_clients_closed'}


def validate(value):
    if (not isinstance(value, dict) or set(value) !=
            {'schema', 'generation', 'package_sha256', 'state', 'entries', 'client_admission'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['client_admission'] is not False):
        raise SafetyError('Invalid installation journal')
    for field, length in [('generation', 32), ('package_sha256', 64)]:
        if not isinstance(value[field], str) or not re.fullmatch('[a-f0-9]{%d}' % length, value[field]):
            raise SafetyError('Invalid installation generation or package identity')
    if not isinstance(value['state'], str) or value['state'] not in {'applying', 'recovering', 'recovery_required', *TERMINAL}:
        raise SafetyError('Invalid installation state')
    entries = value['entries']
    if not isinstance(entries, list) or len(entries) > len(STEPS):
        raise SafetyError('Invalid installation operations')
    for index, entry in enumerate(entries):
        if (not isinstance(entry, dict) or set(entry) != {'step', 'state'}
                or entry['step'] != STEPS[index]
                or not isinstance(entry['state'], str)
                or entry['state'] not in {'intent', 'done', 'undone'}):
            raise SafetyError('Journal is not the fixed installation sequence')
        if value['state'] == 'applying' and (entry['state'] == 'undone'
                or entry['state'] == 'intent' and index != len(entries)-1):
            raise SafetyError('Invalid in-progress journal')
    # Recovery can only advance from the end of this fixed sequence. Reject
    # fabricated holes or multiple unknown outcomes before any adapter action.
    active=[];seen_undone=False
    for entry in entries:
        if entry['state']=='undone':seen_undone=True
        elif seen_undone:raise SafetyError('Recovery journal contains a non-contiguous undone suffix')
        else:active.append(entry['state'])
    if any(state!='done' for state in active[:-1]):
        raise SafetyError('Only the last active installation operation can be uncertain')
    if value['state'] == 'prepared_clients_closed' and (
            len(entries) != len(STEPS) or any(e['state'] != 'done' for e in entries)):
        raise SafetyError('Incomplete installation cannot be committed')
    if value['state'] == 'rolled_back_clients_closed' and any(e['state'] != 'undone' for e in entries):
        raise SafetyError('Incomplete recovery cannot be committed')
    return deepcopy(value)


class Transaction:
    """Write intent before mutation; recover even an operation with unknown outcome.

    Adapter contract: save is atomic+durable in protected storage; preflight
    performs signature/catalog verification and rejects unowned collisions;
    apply/undo are fixed operations with ownership checked against generation.
    undo is idempotent and must refuse resources replaced by another owner.
    close_clients is never undone. Revocation and verification cover the exact
    owned client set, not global networking. Cleanup never restores permits.
    """
    def __init__(self, adapter, generation, package_sha256):
        self.adapter = adapter
        self.value = validate({'schema': 1, 'generation': generation,
            'package_sha256': package_sha256, 'state': 'applying',
            'entries': [], 'client_admission': False})

    def save(self):
        self.adapter.save(validate(self.value))

    def verify_closed(self):
        if self.adapter.verify_closed(self.value['generation']) is not True:
            raise SafetyError('Installation requires an explicitly verified closed client boundary')

    def run(self):
        if self.value['state'] != 'applying' or self.value['entries']:
            raise SafetyError('An installation transaction cannot be resumed or reused')
        # A failed read-only preflight must not trigger cleanup against strangers.
        self.adapter.preflight(self.value['generation'], self.value['package_sha256'])
        self.save()
        try:
            for step in STEPS:
                if step not in ('inventory_backup','close_clients'):
                    self.verify_closed()
                self.value['entries'].append({'step': step, 'state': 'intent'})
                self.save()
                self.adapter.apply(step, self.value['generation'])
                if step=='close_clients':self.verify_closed()
                self.value['entries'][-1]['state'] = 'done'
                self.save()
            self.verify_closed()
            self.value['state'] = 'prepared_clients_closed'
            self.save()
            return deepcopy(self.value)
        except Exception as failure:
            # A failed final durable write is not a committed transaction.
            self.value['state'] = 'applying'
            try:
                self.recover()
            except Exception as recovery_failure:
                raise SafetyError('Installation failed; protected recovery is required') from recovery_failure
            raise SafetyError('Installation failed; owned changes rolled back with clients closed') from failure

    @classmethod
    def from_journal(cls, adapter, value):
        value = validate(value)
        result = cls(adapter, value['generation'], value['package_sha256'])
        result.value = value
        return result

    def recover(self):
        if self.value['state'] in TERMINAL:
            raise SafetyError('Completed transactions require a separate explicit operation')
        # Revocation is mandatory before touching services/files. If journal
        # persistence fails, still attempt revocation, but do not mutate further.
        self.value['state'] = 'recovering'
        persistence_error = None
        try: self.save()
        except Exception as error: persistence_error = error
        self.adapter.revoke_owned(self.value['generation'])
        self.verify_closed()
        if persistence_error is not None: raise persistence_error
        try:
            for entry in reversed(self.value['entries']):
                if entry['state'] == 'undone': continue
                if entry['step'] != 'close_clients':
                    self.verify_closed()
                    self.adapter.undo(entry['step'], self.value['generation'])
                entry['state'] = 'undone'
                self.save()
            self.verify_closed()
            self.value['state'] = 'rolled_back_clients_closed'
            self.save()
        except Exception:
            self.value['state'] = 'recovery_required'
            self.save()
            raise
        return deepcopy(self.value)
