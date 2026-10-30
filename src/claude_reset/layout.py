"""Where ClaudeReset and the Claude clients keep their files: every folder and file name and path rule,
and the choice of the state root that holds the program's archives.

Names that already exist on users' computers are fixed; renaming one needs a migration. The state root
selection holds a path only, never service instructions or credentials. Discovery reads directory
metadata and never decrypts or migrates old archives.
"""
from __future__ import annotations
from dataclasses import dataclass
import os
from pathlib import Path

from . import config
from .model.jsonc import strict_loads
from .errors import SafetyError
from .safeio import atomic_json, guarded, local_volume
from .windows.folders import physical_local_appdata
from .model.records import StateSelection, exact

# ClaudeReset's own places
# The program's own files: this package, the folder with launcher.py, and the program (or repository) root.
PACKAGE_DIR = Path(__file__).resolve().parent
SOURCE_DIR = PACKAGE_DIR.parent
PROGRAM_DIR = SOURCE_DIR.parent
PRODUCT = config.PRODUCT_NAME           # folder in LOCALAPPDATA and in Program Files (service bundle)
L1_PROGRAM = 'ClaudeReset-L1'           # Program Files folder of the installed L1 controller and runner
TOOL_HOME = '.claude-reset'             # in the user profile: builds, backend, window settings, flags
IPC_HOME = '.claude-reset-ipc'          # in the user profile: requests to the Desktop package worker
STATE_SELECTION = 'state-root.json'     # in TOOL_HOME: the explicitly selected state root
DEFAULT_STATE = 'state'                 # in TOOL_HOME: state root of a new installation
CONTROLLER = 'strict-guard'             # in the state root: controller status, consent, UAC requests
CONTROLLER_STATUS = 'status.json'       # in CONTROLLER: the controller's last report
EXTENSION_EXCLUDED_FLAG = 'exclude-vscode-extension.flag'   # in the controller folder: the owner kept the VS Code extension out of L1
RUNS = 'runs'                           # in the state root: one folder per reset run
KEY_RUNS = 'key-runs'
COWORK_RUNS = 'cowork-runs'
CUSTOMIZATION_RUNS = 'customization-runs'
CHROME_PROFILES = 'ChromeProfiles'
EDITOR_PROFILES = 'ClaudeOnlyVSCode'
CONNECTION_PROFILE = 'connection.dpapi'
OPERATION_LOCK = 'operation.lock'
PLAN_FILE = 'plan.dpapi'                # files inside a run folder
JOURNAL_FILE = 'journal.dpapi'
MEMORY_FILE = 'memory.dpapi'
RESULT_FILE = 'result.json'
PROFILE_MARKER = 'claude-reset-profile.json'   # marks a browser or editor profile the program created
# Files of the local tunnel engine's worker in its backend folder
BACKEND_PROFILE = 'profile.json'
BACKEND_STATUS = 'worker-status.json'
BACKEND_ENGINE_CONFIG = 'snow-config.dpapi'   # historical name kept on installed computers (D4)
# Entries whose presence shows that a folder already holds ClaudeReset state.
STATE_MARKERS = (RUNS, KEY_RUNS, COWORK_RUNS, CUSTOMIZATION_RUNS, CHROME_PROFILES, EDITOR_PROFILES,
                 CONNECTION_PROFILE, CONTROLLER, OPERATION_LOCK)

# Places of the Claude clients
CODE_HOME = '.claude'
CODE_CONFIG = '.claude.json'
CODE_SETTINGS = 'settings.json'             # in CODE_HOME and in project .claude folders
CODE_LOCAL_SETTINGS = 'settings.local.json'
EDITOR_SETTINGS = 'settings.json'           # VS Code user settings
STANDALONE_CLI = '.local/bin/claude.exe'
VSCODE_EXTENSIONS = '.vscode/extensions'
EXTENSION_CLI = 'anthropic.claude-code-*-win32-x64/resources/native-binary/claude.exe'
DESKTOP_DATA = 'Claude-Data'
DESKTOP_ROAMING = 'Claude'                 # Desktop profile in APPDATA
DESKTOP_3P = 'Claude-3p'                   # Desktop with a third-party provider


def environment_program_files() -> Path:
    """Program Files as the environment names it; the L1 controller has always been located this way."""
    return Path(os.environ.get('ProgramFiles', r'C:\Program Files'))


def l1_program() -> Path:
    return environment_program_files() / L1_PROGRAM


def controller_folder(state_root) -> Path:
    return Path(state_root) / CONTROLLER


def ipc_home(home=None) -> Path:
    return Path(home or Path.home()) / IPC_HOME


@dataclass
class Paths:
    home: Path
    roaming: Path
    local: Path
    state: Path

    @classmethod
    def current(cls, state_root=None):
        if os.name != 'nt':
            raise SafetyError('This build targets Windows')
        home, local = Path.home(), Path(os.environ['LOCALAPPDATA'])
        state = resolve(home, physical_local_appdata(), local, explicit=state_root)
        result = cls(home, Path(os.environ['APPDATA']), local, state)
        result.validate()
        return result

    def validate(self):
        for p in (self.home, self.roaming, self.local, self.state):
            guarded(p, p, allow_root=True)
        if self.state == self.home or self.state.is_relative_to(self.home / CODE_HOME):
            raise SafetyError('Invalid application-state location')


# --- places derived from Paths (any object with home/roaming/local/state works) --------------------

def app_local(paths, name) -> Path:
    """A file in the program's own LOCALAPPDATA folder."""
    return guarded(paths.local / PRODUCT / name, paths.local)


def tool_home(paths) -> Path:
    return paths.home / TOOL_HOME


def controller(paths) -> Path:
    return guarded(controller_folder(paths.state), paths.state)


def run_folder(paths, kind, run_id) -> Path:
    """The folder of one run of the given kind (RUNS, KEY_RUNS, COWORK_RUNS, CUSTOMIZATION_RUNS)."""
    return guarded(paths.state / kind / run_id, paths.state)


def code_home(paths) -> Path:
    return paths.home / CODE_HOME


def code_config(paths) -> Path:
    return paths.home / CODE_CONFIG


def desktop_data(paths) -> Path:
    return paths.local / DESKTOP_DATA / config.DESKTOP_PACKAGE[0].lower()


def desktop_package(paths) -> Path:
    return paths.local / 'Packages' / config.DESKTOP_PACKAGE[0]


def standalone_cli(paths) -> Path:
    return paths.home / STANDALONE_CLI


def vscode_extensions(paths) -> Path:
    return paths.home / VSCODE_EXTENSIONS


# --- the state root ---------------------------------------------------------------------------------

def selection_file(home):
    # Outside AppData redirection. This belongs to ClaudeReset, not Claude/Codex.
    return local_volume(Path(home)) / TOOL_HOME / STATE_SELECTION


def default_state(home):
    return Path(home) / TOOL_HOME / DEFAULT_STATE


def validate_root(path, home):
    path = local_volume(Path(path))
    if not path.is_absolute() or str(path).startswith(('\\\\', '//')):
        raise SafetyError('State root must be an absolute local path')
    path = guarded(path, path, allow_root=True)
    home = Path(home)
    if path == Path(path.anchor) or path == home or path.is_relative_to(home / CODE_HOME):
        raise SafetyError('Invalid application-state location')
    if path.exists() and not path.is_dir():
        raise SafetyError('State root is not a directory')
    return path


def discover(home, physical_local, environment_local):
    home, local = Path(home), Path(physical_local)
    candidates = [local / PRODUCT, Path(environment_local) / PRODUCT]
    packages = guarded(local / 'Packages', local)
    if packages.exists():
        for package in sorted(packages.glob('OpenAI.Codex_*')):
            guarded(package, packages)
            candidates.append(package / 'LocalCache/Local' / PRODUCT)
    found, seen = [], set()
    for candidate in candidates:
        path = validate_root(candidate, home)
        key = os.path.normcase(str(path))
        if key in seen:
            continue
        seen.add(key)
        markers = [name for name in STATE_MARKERS if guarded(path / name, path).exists()] if path.exists() else []
        # Any existing entry can represent unrecognized state. Never hide it by
        # silently choosing a new empty directory on schema drift.
        nonempty = path.exists() and next(path.iterdir(), None) is not None
        found.append({'path':str(path), 'exists':path.exists(), 'nonempty':nonempty, 'markers':markers})
    return found


def read_selection(home):
    file = selection_file(home)
    guarded(file, file.parent)
    if not file.exists():
        return None
    # Bound the actual read, including growth after a metadata snapshot.
    with file.open('rb') as stream:
        raw = stream.read(8193)
    data = strict_loads(raw, limit=8192, too_large='State selection exceeds size limit',
                        invalid='Invalid state selection', reject_constants=True)
    if (not exact(data, StateSelection)
            or type(data['schema']) is not int or data['schema'] != 1
            or not isinstance(data['state_root'], str)):
        raise SafetyError('Unknown state selection schema')
    path = validate_root(data['state_root'], home)
    if not path.is_dir():
        raise SafetyError('Selected state root is missing; refusing to create a replacement')
    return path


def resolve(home, physical_local, environment_local, explicit=None):
    if explicit is not None:
        return validate_root(explicit, home)
    selected = read_selection(home)
    if selected is not None:
        return selected
    candidates = discover(home, physical_local, environment_local)
    existing = [row for row in candidates if row['nonempty']]
    if existing:
        raise SafetyError('Existing application state requires an explicit selection. Use --state-inspect, then --state-select PATH; archives will not be moved.')
    # New installations use a nonredirected per-user location outside AppData.
    # Persisting the first selection is a separate explicit operation.
    return validate_root(default_state(home), home)


def select(home, path):
    selected = validate_root(path, home)
    # Selection is not migration. Require an existing directory so a typo cannot
    # switch the user to a fresh empty archive store.
    if not selected.is_dir():
        raise SafetyError('Choose an existing state directory; no data is moved')
    file = selection_file(home)
    guarded(file, file.parent)
    atomic_json(file, {'schema':1,'state_root':str(selected)}, file.parent)
    return {'selected':True, 'state_root':str(selected), 'archives_moved':False, 'network_authorized':False}


def inspect(home, physical_local, environment_local):
    selected = read_selection(home)
    candidates = discover(home, physical_local, environment_local)
    return {'schema':1,'read_only':True,'selection_file':str(selection_file(home)),
            'selected':str(selected) if selected else None,'candidates':candidates,
            'default_new_state':str(default_state(home)),
            'selection_required':selected is None and any(row['nonempty'] for row in candidates),
            'archives_moved':False,'network_authorized':False}
