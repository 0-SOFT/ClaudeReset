"""Point the Claude Code extension (shared VS Code) at the L1 relay, or undo it.

Writes only claudeCode.environmentVariables and claudeCode.claudeProcessWrapper in the user
settings.json, never http.proxy (that would reroute VS Code itself). The wrapper starts the
extension's claude.exe inside the owned package so commands and MCP servers it launches inherit
the network restriction; it is set only when the installed runner exists. The original file is
saved DPAPI-encrypted before the first change.
Usage: vscode_claude_proxy.py set|remove|status [--no-wrapper]
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from claude_reset.model import jsonc
from claude_reset.layout import Paths
from claude_reset.safeio import atomic_bytes
from claude_reset.windows.system import DPAPI

from claude_reset import config
from claude_reset.network import l1_settings

GATE = config.RELAY_URL
WANTED = [{'name': name, 'value': value} for name, value in l1_settings.OWNED_ENV]
KEY = 'claudeCode.environmentVariables'
WRAPPER_KEY = 'claudeCode.claudeProcessWrapper'
WRAPPER = Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'ClaudeReset-L1' / 'ClaudeResetRun.exe'


def main():
    action = sys.argv[1]
    path = Path(os.environ['APPDATA']) / 'Code/User/settings.json'
    settings = jsonc.read(path, path.parent)
    current = settings.get(KEY)
    wrapper = settings.get(WRAPPER_KEY)
    if action == 'status':
        print(json.dumps({'set': current == WANTED, 'current': current, 'wrapper': wrapper,
                          'wrapper_set': wrapper == str(WRAPPER), 'runner_installed': WRAPPER.is_file()})); return 0
    paths = Paths.current()
    backup = paths.state / 'strict-guard' / 'vscode-settings-before.dpapi'
    if not backup.exists():
        atomic_bytes(backup, DPAPI().encrypt(path.read_bytes()), backup.parent)
    names = {item.get('name') for item in current or [] if isinstance(item, dict)}
    others = [item for item in current or [] if isinstance(item, dict) and item.get('name') not in {w['name'] for w in WANTED}]
    if action == 'set':
        jsonc.set_property(path, path.parent, KEY, others + WANTED)
        if '--no-wrapper' not in sys.argv and WRAPPER.is_file():
            jsonc.set_property(path, path.parent, WRAPPER_KEY, str(WRAPPER))
    elif action == 'remove':
        if wrapper:
            # An empty string is the neutral value: the extension treats it as unset.
            jsonc.set_property(path, path.parent, WRAPPER_KEY, '')
        if others:
            jsonc.set_property(path, path.parent, KEY, others)
        elif current is not None:
            # Keep the file valid and minimal: an empty list is the neutral value.
            jsonc.set_property(path, path.parent, KEY, [])
    else:
        raise SystemExit('usage: set|remove|status')
    print(json.dumps({'action': action, 'now': jsonc.read(path, path.parent).get(KEY),
                      'wrapper': jsonc.read(path, path.parent).get(WRAPPER_KEY), 'previous_names': sorted(n for n in names if n)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
