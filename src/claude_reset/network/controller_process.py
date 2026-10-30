"""Which controller generation runs, and its close: the request is bound to the retained process."""
from ..errors import SafetyError
from .. import layout
from ..windows.process import RetainedProcess


def _identity(row, state_root):
    """Require the supported start protocol, including its exact state scope."""
    if (not isinstance(row, dict) or type(row.get('schema')) is not int
            or row['schema'] != 1 or row.get('operation') != 'start'
            or row.get('state_root') != str(state_root)
            or not isinstance(row.get('request_id'), str)
            or len(row['request_id']) != 32
            or any(c not in '0123456789abcdef' for c in row['request_id'])
            or not isinstance(row.get('instance'), str) or not row['instance']
            or type(row.get('pid')) is not int or not 0 < row['pid'] <= 0xffffffff
            or type(row.get('process_created')) is not int or row['process_created'] <= 0):
        raise SafetyError('Controller identity unavailable')
    return tuple(row[k] for k in ('instance', 'pid', 'process_created',
                                 'schema', 'operation', 'state_root', 'request_id'))


def generation(pid):
    with RetainedProcess(pid) as process:
        return process.created


def close_and_wait(folder, read, write, requested, *, process_factory=None):
    process_factory = process_factory or RetainedProcess
    state = read(folder / layout.CONTROLLER_STATUS, folder)
    identity = _identity(state, folder.parent)
    instance, pid, created = identity[:3]
    with process_factory(pid) as process:
        if process.created != created:
            raise SafetyError('Controller generation changed')
        # Bind the request to the status used to open the retained handle.
        def unchanged():
            fresh = read(folder / layout.CONTROLLER_STATUS, folder)
            return _identity(fresh, folder.parent) == identity
        if not unchanged():
            raise SafetyError('Controller identity changed')
        write(folder / 'close.request', {'requested': requested, 'instance': instance}, folder)
        return process.wait(90000) and unchanged()
