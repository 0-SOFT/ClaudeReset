"""Autostart of the L1 controller: the frozen program copied into Program Files and a logon task that starts it."""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import time
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from .. import config, layout
from ..elevation import launch
from ..elevation import request as uac
from ..errors import SafetyError, error_info
from ..model.ids import utc_now
from ..safeio import atomic_json
from ..windows import tasks
from . import controller

__all__ = ['ASIDE', 'clear_asides', 'directory', 'elevated', 'install', 'remove', 'remove_file', 'swap_in',
           'task_definition', 'task_state', 'task_xml']

ASIDE = '.old-'


def directory():
    return layout.l1_program()


def task_xml(executable, report, user):
    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(user)}</UserId><Delay>PT1M</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="A"><UserId>{escape(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Hidden>true</Hidden></Settings>
  <Actions Context="A"><Exec><Command>{escape(str(executable))}</Command><Arguments>--strict-guard-serve --report "{escape(str(report))}"</Arguments></Exec></Actions>
</Task>
'''


def swap_in(temporary, destination):
    """Put a new file in place even if the old one is a running program.

    A running image cannot be overwritten or deleted, but Windows lets it be renamed; the new file then
    takes the name and the old one is cleared later. This is what lets an update be installed while the
    controller or a wrapper started by an open Claude Code session is still running."""
    try:
        os.replace(temporary, destination)
    except PermissionError:
        os.replace(destination, destination.with_name(destination.name + ASIDE + str(int(time.time()))))
        os.replace(temporary, destination)


def clear_asides(folder):
    """Delete renamed-away old files that are no longer running; the rest wait for the next call."""
    for old in folder.glob('*' + ASIDE + '*'):
        try:
            old.unlink()
        except OSError:
            pass


def remove_file(path):
    try:
        path.unlink(missing_ok=True)
    except PermissionError:
        os.replace(path, path.with_name(path.name + ASIDE + str(int(time.time()))))


def install(paths, report_path, *, request_id=None, scheduler=tasks.Scheduler(),
            folder=None):   # None: directory(), the Program Files folder looked up on each call
    """Elevated: copy the frozen program into Program Files and register the logon task.

    scheduler is the Task Scheduler and folder the program folder."""
    result = {'schema': 1, 'finished': False, 'utc': utc_now()}
    result.update(uac.admit_child(paths, 'autostart', request_id))
    try:
        if not getattr(sys, 'frozen', False):
            raise SafetyError('Autostart needs the frozen ClaudeReset.exe')
        target = folder or directory()
        target.mkdir(exist_ok=True)
        if os.path.islink(target) or (os.lstat(target).st_file_attributes & 0x400):
            raise SafetyError('Autostart folder is a reparse point')
        clear_asides(target)
        executable = target / config.CONTROLLER_EXE
        temporary = target / 'ClaudeReset.exe.new'
        shutil.copyfile(sys.executable, temporary)
        swap_in(temporary, executable)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        # The wrapper that starts Claude inside the package; absent in a build without it.
        runner = Path(sys.executable).with_name(config.RUNNER_EXE)
        if runner.is_file():
            temporary = target / (config.RUNNER_EXE + '.new')
            shutil.copyfile(runner, temporary)
            swap_in(temporary, target / config.RUNNER_EXE)
            result['runner_sha256'] = hashlib.sha256((target / config.RUNNER_EXE).read_bytes()).hexdigest()
        user = os.environ['USERDOMAIN'] + '\\' + os.environ['USERNAME']
        report = layout.controller(paths) / 'autostart-report.json'
        expected_xml = task_xml(executable, report, user)
        scheduler.create(config.CONTROLLER_TASK, expected_xml)
        definition = task_definition(expected_xml, scheduler=scheduler)
        result.update(registered=definition == 'matching', definition_state=definition,
                      executable_sha256=digest, task=config.CONTROLLER_TASK)
    except Exception as exc:
        result['error'] = error_info(exc)
    result['finished'] = True
    uac.child_event(paths, {key: result[key] for key in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def _definition_tree(xml):
    if not isinstance(xml, str) or len(xml) > 65536 or '<!DOCTYPE' in xml.upper():
        raise ValueError('Task definition unavailable')

    def node(element):
        return (element.tag, sorted(element.attrib.items()),
                element.text if element.text and element.text.strip() else '',
                element.tail if element.tail and element.tail.strip() else '',
                tuple(node(child) for child in element))
    return node(ET.fromstring(xml))


def task_definition(expected_xml, *, scheduler=tasks.Scheduler()):
    """Conservative definition snapshot, never process-exit or replay authority.

    Only namespace/attribute ordering and formatting whitespace are normalized.
    Scheduler-added defaults remain a mismatch until explicitly supported.
    """
    try:
        actual = scheduler.xml(config.CONTROLLER_TASK)
        if actual is not None:
            return 'matching' if _definition_tree(actual) == _definition_tree(expected_xml) else 'different'
    except (OSError, ValueError, TypeError, RecursionError, ET.ParseError, SafetyError):
        pass
    return 'unknown'


def task_state(*, scheduler=tasks.Scheduler()):
    """Exact task lookup; CLI failure and localized text never prove absence."""
    return scheduler.lookup(config.CONTROLLER_TASK)


def remove(paths, report_path, *, request_id=None, scheduler=tasks.Scheduler(),
           folder=None):   # None: directory(), the Program Files folder looked up on each call
    """Elevated: unregister the logon task and delete only the program copy this feature installed.

    scheduler and folder as for install."""
    result = {'schema': 1, 'finished': False, 'utc': utc_now()}
    result.update(uac.admit_child(paths, 'autostart-off', request_id))
    try:
        scheduler.delete(config.CONTROLLER_TASK)
        state = task_state(scheduler=scheduler)
        result['task_state_after'] = state
        result['task_present_after'] = {'present': True, 'absent': False, 'unknown': None}[state]
        target = folder or directory()
        executable = target / config.CONTROLLER_EXE
        result['program_removed'] = False
        if state != 'absent':
            raise SafetyError('Task absence was not verified')
        if executable.is_file():
            remove_file(executable)
        remove_file(target / config.RUNNER_EXE)
        clear_asides(target)
        if target.is_dir() and not any(target.iterdir()):
            target.rmdir()
        result['program_removed'] = (not executable.exists() and
                                     not (target / config.RUNNER_EXE).exists() and
                                     not any(target.glob('*' + ASIDE + '*')))
    except Exception as exc:
        result['error'] = error_info(exc)
    result['finished'] = True
    uac.child_event(paths, {key: result[key] for key in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def elevated(paths, enable=True, *, dispatch=launch.dispatch_request):
    return controller.elevated(paths, 'autostart' if enable else 'autostart-off', dispatch=dispatch)
