"""Detect known out-of-profile authentication storage without reading credentials.

No Credential Manager enumeration, deletion or migration is authorized here.
Absence of these indicators is not proof that a client never used OS storage.
"""
from pathlib import Path
from ..model import jsonc
from ..errors import SafetyError
from ..safeio import guarded
from ..windows.environment import folded
from .. import config
from .. import layout
from ..model.notes import Note

VARIABLES = frozenset({'CLAUDE_SECURESTORAGE_CONFIG_DIR', 'CLAUDE_CODE_FORCE_WINDOWS_CREDMAN'})
BLOCKER = Note('plan.secure_storage')


def _environment(value):
    return bool(VARIABLES.intersection(folded(value)))


def _feature(value):
    features = value.get('cachedGrowthBookFeatures', {})
    if not isinstance(features, dict):
        raise SafetyError('Secure-storage feature metadata has an unknown schema')
    return 'tengu_windows_credman' in features and features['tengu_windows_credman'] is not False


def indicators(paths, profiles, components, env, presence):
    if not set(components).intersection({'code', 'vscode'}):
        return []
    found = set()
    if _environment(env) or any(name.rsplit(':', 1)[-1] in VARIABLES for name in folded(presence)):
        found.add('environment')
    roots = {Path(p.path) for p in profiles if p.component == 'code' and p.selected}
    # The extension's embedded CLI can use the standard Code authentication
    # state even when only the editor component was selected for reset.
    if 'vscode' in components:
        roots.add(layout.code_home(paths))
    for root in roots:
        configs = [(root / '.config.json', root), (root / layout.CODE_CONFIG, root)]
        if root == layout.code_home(paths):
            configs.append((layout.code_config(paths), paths.home))
        for path, boundary in configs:
            if _feature(jsonc.read(path, boundary)):
                found.add('cached_feature')
        for name in (layout.CODE_SETTINGS, layout.CODE_LOCAL_SETTINGS):
            if _environment(jsonc.read(root / name, root).get('env', {})):
                found.add('code_settings')
    for profile in profiles:
        if profile.component != 'vscode' or not profile.selected:
            continue
        root = Path(profile.path)
        editors = [root]
        named = guarded(root / 'profiles', root)
        if named.exists():
            editors += [guarded(p, root) for p in named.iterdir() if p.is_dir()]
        for editor in editors:
            obj = jsonc.read(editor / layout.EDITOR_SETTINGS, root)
            values = obj.get(config.VSCODE_ENVIRONMENT, [])
            if not isinstance(values, list):
                raise SafetyError('Extension environment has an unknown schema')
            pairs = {}
            for item in values:
                if not isinstance(item, dict) or not isinstance(item.get('name'), str) or 'value' not in item:
                    raise SafetyError('Extension environment has an unknown schema')
                name = item['name']
                if name in pairs:
                    raise SafetyError('Duplicate extension environment variable')
                pairs[name] = item['value']
            if _environment(pairs):
                found.add('extension_settings')
    return sorted(found)
