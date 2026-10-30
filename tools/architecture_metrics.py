"""Static architecture metrics for src/claude_reset (see docs/DEVELOPMENT.md).

Reads sources with ast only; nothing is imported or executed. tests/test_architecture.py uses the same
functions as a ratchet, so a metric can only improve between commits.

    python tools/architecture_metrics.py            # summary as JSON
    python tools/architecture_metrics.py --details  # with the offending names, for fixing
"""
import argparse
import ast
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
import io
import itertools
import json
from pathlib import Path
import re
import sys
import tokenize

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'claude_reset'

# Entry scripts of the application and its services; tools/ and packaging/ are seeds too.
ENTRY_SCRIPTS = ('src/launcher.py', 'src/launcher_run.py', 'src/backend_runtime_main.py', 'src/installer_preflight_main.py')
TOOL_GLOBS = ('tools/*.py', 'packaging/**/*.py')

# Modules whose job is to hold user-facing text; Cyrillic and long literals there are expected.
TEXT_MODULES = ('ui.text',)
# Presentation outside ui/: the command line.
UI_MODULES = ('cli',)
# Layer rank by top-level name: an import may only point to the same or a lower rank.
# errors and config are leaves everyone may use; windows is the platform; model holds the domain types.
LAYERS = {'errors': 0, 'config': 0, 'windows': 1, 'safeio': 1, 'model': 2, 'layout': 2,
          'reset': 3, 'network': 3, 'backend': 3, 'privacy': 3, 'elevation': 3,
          'services': 4, 'ui': 5, 'cli': 5}
OS_LIBRARIES = ('ctypes', 'winreg', 'subprocess')
PLATFORM_PREFIX = 'windows'

CONFIG_LITERAL = re.compile(
    r'(\\|/|\.exe$|\.json$|\.dll$|\.sys$|^HK|SOFTWARE|^[A-Z_]{4,}$|Claude|claude|127\.0\.0|https?://'
    r'|\{[0-9A-Fa-f-]{36}\}|^[0-9a-f-]{36}$|\.dpapi|AnthropicClaude|\.vhdx|Local|AppData|ProgramData'
    r'|Program Files|_PROXY|PROXY|Sandbox|snow|0-soft|\.claude)')
POWERSHELL = re.compile(r'\$\w+|Get-\w+|New-\w+|Set-\w+|ConvertTo-Json|Register-ScheduledTask')
CYRILLIC = re.compile(r'[А-Яа-яЁё]{3}')
IDENTIFIER = re.compile(r'[a-z][a-z0-9_]{1,40}')


def private(name):
    return name.startswith('_') and not name.startswith('__') and not name.endswith('_')


@dataclass
class Module:
    name: str            # dotted, relative to the package: 'core', 'windows.wfp'; the package itself is ''
    path: Path
    source: str
    tree: ast.Module
    is_package: bool
    edges: set = field(default_factory=set)        # module-level imports of package modules
    lazy: set = field(default_factory=set)         # imports inside functions
    imported_names: dict = field(default_factory=dict)   # target module -> names imported from it
    aliases: dict = field(default_factory=dict)    # local name -> package module it refers to
    external: set = field(default_factory=set)     # top-level names of external modules imported

    @property
    def top(self):
        return self.name.split('.')[0]

    @property
    def lines(self):
        return self.source.count('\n') + (0 if self.source.endswith('\n') else 1)


def load(root=ROOT):
    base = root / 'src' / PACKAGE
    modules = {}
    for path in sorted(base.rglob('*.py')):
        if '__pycache__' in path.parts:
            continue
        rel = path.relative_to(base).with_suffix('')
        parts = list(rel.parts)
        is_package = parts[-1] == '__init__'
        if is_package:
            parts = parts[:-1]
        source = path.read_text('utf-8')
        modules['.'.join(parts)] = Module('.'.join(parts), path, source, ast.parse(source), is_package)
    for module in modules.values():
        _collect_imports(module, modules)
    return modules


def _resolve(node, module, modules):
    """Package modules an import statement refers to, with the names taken from each."""
    found = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name == PACKAGE or alias.name.startswith(PACKAGE + '.'):
                target = alias.name[len(PACKAGE) + 1:]
                while target and target not in modules:
                    target = target.rpartition('.')[0]
                found.append((target, None, alias.asname))
        return found
    if node.level:
        package = module.name if module.is_package else module.name.rpartition('.')[0]
        for _ in range(node.level - 1):
            package = package.rpartition('.')[0]
        base = '.'.join(p for p in (package, node.module or '') if p)
    elif node.module and (node.module == PACKAGE or node.module.startswith(PACKAGE + '.')):
        base = node.module[len(PACKAGE) + 1:]
    else:
        return found
    for alias in node.names:
        sub = '.'.join(p for p in (base, alias.name) if p)
        if sub in modules:
            found.append((sub, None, alias.asname or alias.name))
        elif base in modules:
            found.append((base, alias.name, None))
    return found


def _collect_imports(module, modules):
    def visit(node, depth):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.If) and 'TYPE_CHECKING' in ast.unparse(child.test):
                continue
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                if isinstance(child, ast.Import):
                    module.external.update(a.name.split('.')[0] for a in child.names)
                elif not child.level and child.module:
                    module.external.add(child.module.split('.')[0])
                for target, name, alias in _resolve(child, module, modules):
                    if target == module.name:
                        continue
                    (module.lazy if depth else module.edges).add(target)
                    if name:
                        module.imported_names.setdefault(target, set()).add(name)
                    if alias:
                        module.aliases[alias] = target
            inner = depth + isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            visit(child, inner)
    visit(module.tree, 0)
    module.external.discard(PACKAGE)
    module.lazy -= module.edges


# --- dependency structure -------------------------------------------------------------------------

def graph(modules, lazy=True):
    return {name: (m.edges | m.lazy) if lazy else set(m.edges) for name, m in modules.items()}


def strongly_connected(graph_):
    index, low, stack, on_stack, result, counter = {}, {}, [], set(), [], [0]
    sys.setrecursionlimit(max(10000, sys.getrecursionlimit()))

    def connect(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in graph_.get(v, ()):
            if w not in index:
                connect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            component = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                component.append(w)
                if w == v:
                    break
            if len(component) > 1:
                result.append(sorted(component))
    for v in sorted(graph_):
        if v not in index:
            connect(v)
    return sorted(result, key=lambda c: (-len(c), c))


def _reaches(graph_, start, goal):
    seen, queue = {start}, deque([start])
    while queue:
        node = queue.popleft()
        if node == goal:
            return True
        for nxt in graph_.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return False


def cycle_closing_lazy(modules):
    full = graph(modules)
    return sorted((m.name, t) for m in modules.values() for t in m.lazy if _reaches(full, t, m.name))


def layer_violations(modules):
    found = []
    for module in modules.values():
        rank = LAYERS.get(module.top)
        if rank is None:
            continue
        for target in module.edges | module.lazy:
            target_rank = LAYERS.get(target.split('.')[0])
            if target_rank is not None and target_rank > rank:
                found.append((module.name, target))
    return sorted(found)


def _script_imports(path):
    tree = ast.parse(path.read_text('utf-8', errors='replace'))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
            names.update(f'{node.module}.{a.name}' for a in node.names)
    return names


def unreachable(modules, root=ROOT):
    """Package modules that no entry script, tool or packaging script can reach: only tests use them."""
    seeds = set()
    scripts = [root / s for s in ENTRY_SCRIPTS] + [p for g in TOOL_GLOBS for p in root.glob(g)]
    for script in scripts:
        if script.is_file():
            for name in _script_imports(script):
                if name.startswith(PACKAGE + '.'):
                    target = name[len(PACKAGE) + 1:]
                    while target and target not in modules:
                        target = target.rpartition('.')[0]
                    if target:
                        seeds.add(target)
    full, seen, stack = graph(modules), set(), list(seeds)
    while stack:
        node = stack.pop()
        if node not in seen:
            seen.add(node)
            stack.extend(full.get(node, ()))
    for name in list(seen):     # a reachable submodule keeps its packages alive
        while name:
            name = name.rpartition('.')[0]
            seen.add(name)
    return sorted(set(modules) - seen)


# --- encapsulation ---------------------------------------------------------------------------------

def private_imports(modules):
    found = []
    for module in modules.values():
        for target, names in module.imported_names.items():
            found.extend((module.name, target, n) for n in sorted(names) if private(n))
        for node in ast.walk(module.tree):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and private(node.attr)
                    and module.aliases.get(node.value.id) not in (None, module.name)):
                found.append((module.name, module.aliases[node.value.id], node.attr))
    return sorted(found)


def foreign_private_attributes(modules):
    """obj._x where obj is neither self/cls nor a module: another object's internals."""
    found = []
    for module in modules.values():
        skip = set(module.aliases) | module.external | {'self', 'cls'}
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.Attribute) or not private(node.attr):
                continue
            base = node.value
            if isinstance(base, ast.Name):
                if base.id not in skip:
                    found.append((module.name, f'{base.id}.{node.attr}'))
            elif isinstance(base, ast.Attribute) and ast.unparse(base).startswith('self.'):
                found.append((module.name, f'{ast.unparse(base)}.{node.attr}'))
    return sorted(found)


MUTABLE_CALLS = ('dict', 'list', 'set', 'defaultdict', 'OrderedDict', 'Counter', 'bytearray')


def _mutable(value):
    if isinstance(value, (ast.Dict, ast.List, ast.Set, ast.DictComp, ast.ListComp, ast.SetComp)):
        return True
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return value.func.id in MUTABLE_CALLS
    # The left operand decides the type: frozenset(...) | {...} is a frozenset, [...] + (...) fails.
    return isinstance(value, ast.BinOp) and _mutable(value.left)


def mutable_constants(modules):
    """Module-level CONSTANT names bound to a dict, list or set that any importer could change."""
    found = []
    for module in modules.values():
        for node in module.tree.body:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
            for target in targets:
                if (isinstance(target, ast.Name) and target.id != '__all__' and target.id.lstrip('_').isupper()
                        and node.value is not None and _mutable(node.value)):
                    found.append((module.name, target.id))
    return sorted(found)


def missing_all(modules, prefixes=('windows', 'model', 'services')):
    result = []
    for module in modules.values():
        if module.top in prefixes and not module.is_package:
            names = {t.id for n in module.tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
            if '__all__' not in names:
                result.append(module.name)
    return sorted(result)


# --- platform and literals -------------------------------------------------------------------------

def os_library_users(modules, library):
    return sorted(m.name for m in modules.values() if library in m.external and m.top != PLATFORM_PREFIX)


def argtypes_declarations(modules):
    return sum(1 for m in modules.values() for n in ast.walk(m.tree)
               if isinstance(n, ast.Attribute) and n.attr == 'argtypes' and isinstance(n.ctx, ast.Store))


def dll_loads(modules, dll='kernel32'):
    pattern = re.compile(rf"WinDLL\('{dll}'|windll\.{dll}\b")
    return sorted(m.name for m in modules.values() if pattern.search(m.source))


def _docstring_ids(tree):
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _is_text_module(module):
    return module.name in TEXT_MODULES or any(module.name.startswith(t + '.') for t in TEXT_MODULES)


def _is_ui_module(module):
    return module.name in UI_MODULES or module.top == 'ui'


def config_literals(modules, threshold=3):
    holders = defaultdict(set)
    for module in modules.values():
        if _is_text_module(module) or module.name == 'config':
            continue
        docs = _docstring_ids(module.tree)
        for node in ast.walk(module.tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs
                    and len(node.value) >= 5 and not CYRILLIC.search(node.value) and CONFIG_LITERAL.search(node.value)):
                holders[node.value].add(module.name)
    return {value: sorted(names) for value, names in sorted(holders.items()) if len(names) >= threshold}


def embedded_powershell(modules):
    """PowerShell scripts written inside modules above the platform layer."""
    found = []
    for module in modules.values():
        if module.top == PLATFORM_PREFIX:
            continue
        for node in ast.walk(module.tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 150
                    and POWERSHELL.search(node.value)):
                found.append((module.name, node.lineno, node.value.count('\n') + 1))
    return found


def _pattern_ids(tree):
    """Regular expressions that match localized Windows output are data, not texts for people:
    arguments of re.* calls and the values of *PATTERNS tables."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and getattr(node.func.value, 'id', None) == 're':
            ids.update(id(n) for arg in node.args[:1] for n in ast.walk(arg))
        elif isinstance(node, ast.Assign) and any(getattr(t, 'id', '').endswith('PATTERNS') for t in node.targets):
            ids.update(id(n) for n in ast.walk(node.value))
    return ids


def cyrillic_outside_ui(modules):
    found = []
    for module in modules.values():
        if _is_ui_module(module):
            continue
        skip = _docstring_ids(module.tree) | _pattern_ids(module.tree)
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip and CYRILLIC.search(node.value):
                found.append((module.name, node.lineno))
    return found


# --- functions, duplication, types ------------------------------------------------------------------

def _complexity(fn):
    total = 1
    for node in ast.walk(fn):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.ExceptHandler, ast.With, ast.AsyncFor,
                             ast.comprehension, ast.Assert)):
            total += 1
        elif isinstance(node, ast.BoolOp):
            total += len(node.values) - 1
        elif isinstance(node, ast.Match):
            total += len(node.cases)
    return total


def functions(modules):
    rows = []
    for module in modules.values():
        for node in ast.walk(module.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                annotated = node.returns is not None or any(a.annotation is not None for a in node.args.args)
                rows.append(dict(module=module.name, name=node.name, line=node.lineno, complexity=_complexity(node),
                                 length=node.end_lineno - node.lineno + 1, annotated=annotated,
                                 public=not node.name.startswith('_')))
    return rows


def near_clones(modules, threshold=0.55, minimum=80):
    shingles = []
    for module in modules.values():
        for node in ast.walk(module.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seq = []
                for x in ast.walk(node):
                    label = type(x).__name__
                    if isinstance(x, ast.Attribute):
                        label += '.' + x.attr
                    elif isinstance(x, ast.Call) and isinstance(x.func, ast.Name):
                        label += ':' + x.func.id
                    seq.append(label)
                if len(seq) >= minimum:
                    shingles.append(((module.name, node.name, node.lineno), len(seq),
                                     {tuple(seq[i:i + 4]) for i in range(len(seq) - 3)}, node.end_lineno))
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            x = parent[x]
        return x
    pairs = 0
    for (ka, la, sa, ea), (kb, lb, sb, eb) in itertools.combinations(shingles, 2):
        if ka[:2] == kb[:2] or min(la, lb) / max(la, lb) < 0.6:
            continue
        # A function nested in another is part of it, not a copy of it.
        if ka[0] == kb[0] and (ka[2] <= kb[2] <= ea or kb[2] <= ka[2] <= eb):
            continue
        if len(sa & sb) / len(sa | sb) >= threshold:
            pairs += 1
            parent[find(ka)] = find(kb)
    groups = defaultdict(list)
    for key in parent:
        groups[find(key)].append(key)
    return pairs, sorted((sorted(g) for g in groups.values() if len(g) > 1), key=lambda g: (-len(g), g))


def status_literals(modules):
    values = Counter()
    for module in modules.values():
        for node in ast.walk(module.tree):
            if isinstance(node, ast.keyword) and node.arg == 'status' and isinstance(node.value, ast.Constant):
                values[node.value.value] += 1
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and key.value == 'status' and isinstance(value, ast.Constant):
                        values[value.value] += 1
    return values


def type_definitions(modules):
    counts = Counter()
    for module in modules.values():
        for node in ast.walk(module.tree):
            if isinstance(node, ast.ClassDef):
                bases = [ast.unparse(b) for b in node.bases]
                if any('dataclass' in ast.unparse(d) for d in node.decorator_list):
                    counts['dataclass'] += 1
                for kind in ('Enum', 'TypedDict', 'Protocol', 'NamedTuple'):
                    if any(kind in b for b in bases):
                        counts[kind] += 1
    return counts


def text_checks_on_exceptions(modules):
    """'...' in str(exc): an error recognized by its message."""
    found = []
    for module in modules.values():
        for node in ast.walk(module.tree):
            if (isinstance(node, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
                    and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == 'str'
                            for c in node.comparators)):
                found.append((module.name, node.lineno))
    return found


def field_set_checks(modules):
    """set(value) != {...} or != KEYS: a JSON document validated by hand against a fixed field list.

    Equality of two computed collections (set(found) != set(expected)) is not a field check."""
    found = []
    for module in modules.values():
        for node in ast.walk(module.tree):
            if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Call) and isinstance(node.left.func, ast.Name)
                    and node.left.func.id == 'set' and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops)
                    and any(isinstance(c, ast.Set) or (isinstance(c, ast.Name) and c.id.isupper()) for c in node.comparators)):
                found.append((module.name, node.lineno))
    return found


def broad_handlers(modules):
    swallowed, base = [], []
    for module in modules.values():
        for node in ast.walk(module.tree):
            if isinstance(node, ast.ExceptHandler) and node.type is not None and ast.unparse(node.type) in ('Exception', 'BaseException'):
                if not any(isinstance(x, ast.Raise) for x in ast.walk(node)):
                    swallowed.append((module.name, node.lineno))
                    if ast.unparse(node.type) == 'BaseException':
                        base.append((module.name, node.lineno))
    return swallowed, base


LINE_LIMIT = 120
# Modules written during stage 5 of the refactoring plan: one statement per line, lines up to LINE_LIMIT.
# Stage 6 reformats the rest and extends the rule to every module.
STYLE_CLEAN = ('backend.attestation', 'cli', 'elevation.claims', 'elevation.launch', 'elevation.request', 'model.report',
               'model.reset', 'network.autostart', 'network.controller', 'network.controller_process',
               'network.controller_status', 'network.gate_rules', 'network.l1_check', 'network.l1_common',
               'network.legacy_guard', 'network.relay', 'reset.discovery', 'reset.planner', 'services.protection',
               'ui.proxy_flow', 'ui.reset_flow', 'windows.api', 'windows.display', 'windows.mutex', 'windows.policy',
               'windows.process', 'windows.registry', 'windows.runas')


def style_problems(module):
    """(line, kind): code lines over LINE_LIMIT characters and lines that hold more than one statement.

    Lines of a string literal that spans several lines are its text, not code layout."""
    tokens = list(tokenize.generate_tokens(io.StringIO(module.source).readline))
    text_rows, depth, start = set(), 0, None
    for tok in tokens:
        if tok.type == tokenize.FSTRING_START:
            depth, start = depth + 1, start if depth else tok.start[0]
        elif tok.type == tokenize.FSTRING_END:
            depth -= 1
            if not depth and tok.end[0] > start:
                text_rows.update(range(start, tok.end[0] + 1))
        elif tok.type == tokenize.STRING and tok.end[0] > tok.start[0]:
            text_rows.update(range(tok.start[0], tok.end[0] + 1))
    lines = module.source.splitlines()
    found = [(number, 'long') for number, line in enumerate(lines, 1)
             if len(line) > LINE_LIMIT and number not in text_rows]
    # A statement that does not start its line follows `;` or a header such as `if x:` or `else:`.
    for node in ast.walk(module.tree):
        if isinstance(node, ast.stmt):
            line = lines[node.lineno - 1]
            column = len(line.encode('utf-8')[:node.col_offset].decode('utf-8'))
            if line[:column].strip():
                found.append((node.lineno, 'shared'))
    return sorted(found)


def multi_statement_lines(modules):
    total = 0
    for module in modules.values():
        tokens = tokenize.generate_tokens(io.StringIO(module.source).readline)
        total += sum(1 for t in tokens if t.type == tokenize.OP and t.string == ';')
    return total


# --- tests -----------------------------------------------------------------------------------------

# Library modules the package imports under these names; a patch reaching one through a package module
# (app.tk, uac.os) replaces the library, not the package's own code.
LIBRARY_NAMES = frozenset({'tk', 'ttk', 'scrolledtext', 'messagebox', 'filedialog', 'simpledialog', 'os', 'sys',
                           'subprocess', 'socket', 'time', 'ctypes', 'C', 'winreg', 'json', 'shutil', 'webbrowser',
                           'threading', 'datetime', 'tempfile', 'Path'})   # C: ctypes, as the windows modules import it


def patches_package(target, aliases):
    """The patched object is the package's own: a dotted 'claude_reset...' path, or a name imported from the package
    and not a library module reached through it."""
    if isinstance(target, ast.Constant):
        return (isinstance(target.value, str) and target.value.startswith(PACKAGE + '.')
                and not LIBRARY_NAMES.intersection(target.value.split('.')))
    chain = []
    while isinstance(target, ast.Attribute):
        chain.append(target.attr)
        target = target.value
    return isinstance(target, ast.Name) and target.id in aliases and not LIBRARY_NAMES.intersection(chain)


def test_coupling(root=ROOT):
    """monkeypatch.setattr calls (all, and those replacing the package's own code) and test access to private
    names of the package."""
    setattr_calls = package_calls = private_access = 0
    for path in sorted((root / 'src' / 'tests').glob('*.py')):
        tree = ast.parse(path.read_text('utf-8', errors='replace'))
        aliases = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(PACKAGE):
                for a in node.names:
                    if private(a.name):
                        private_access += 1
                    if node.module == PACKAGE or a.name[:1].islower():
                        aliases.add(a.asname or a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.startswith(PACKAGE + '.'):
                        aliases.add(a.asname or a.name.split('.')[-1])
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'setattr':
                if ast.unparse(node.func.value) == 'monkeypatch':
                    setattr_calls += 1
                    package_calls += bool(node.args) and patches_package(node.args[0], aliases)
                    if (len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
                            and private(node.args[1].value)):
                        private_access += 1
            elif (isinstance(node, ast.Attribute) and private(node.attr) and isinstance(node.value, ast.Name)
                  and node.value.id in aliases):
                private_access += 1
    return setattr_calls, package_calls, private_access


# --- summary ---------------------------------------------------------------------------------------

def measure(root=ROOT, *, clones=True, details=False):
    modules = load(root)
    funcs = functions(modules)
    cycles = strongly_connected(graph(modules))
    closing = cycle_closing_lazy(modules)
    priv = private_imports(modules)
    foreign = foreign_private_attributes(modules)
    dead = unreachable(modules, root)
    literals = config_literals(modules)
    shells = embedded_powershell(modules)
    cyr = cyrillic_outside_ui(modules)
    statuses = status_literals(modules)
    types = type_definitions(modules)
    swallowed, base = broad_handlers(modules)
    setattr_calls, package_patches, test_private = test_coupling(root)
    statements = sum(1 for m in modules.values() for n in ast.walk(m.tree) if isinstance(n, ast.stmt))
    public = [f for f in funcs if f['public']]
    # The platform, the domain types and the scenarios are typed completely (plan section 6).
    core = [f for f in public if f['module'].split('.')[0] in ('windows', 'model', 'services')]
    result = {
        'modules': len(modules),
        'lines': sum(m.lines for m in modules.values()),
        'statements': statements,
        'functions': len(funcs),
        'cycles': len(cycles),
        'modules_in_cycles': sum(len(c) for c in cycles),
        # The command line loads each command's modules only when that command runs (the one allowed place).
        'function_level_imports': sum(len(m.lazy) for m in modules.values() if m.name != 'cli'),
        'cycle_closing_imports': len(closing),
        'layer_violations': len(layer_violations(modules)),
        'private_imports': len(priv),
        'foreign_private_attributes': len(foreign),
        'modules_without_all': len(missing_all(modules)),
        'mutable_constants': len(mutable_constants(modules)),
        # Shared state rebound from functions; the window language is an object passed to its parts instead.
        'global_statements': sum(1 for m in modules.values() for n in ast.walk(m.tree) if isinstance(n, ast.Global)),
        'ctypes_modules': len(os_library_users(modules, 'ctypes')),
        'winreg_modules': len(os_library_users(modules, 'winreg')),
        'subprocess_modules': len(os_library_users(modules, 'subprocess')),
        'argtypes_declarations': argtypes_declarations(modules),
        'kernel32_loaders': len(dll_loads(modules)),
        'config_literals': len(literals),
        'embedded_powershell': len(shells),
        'embedded_powershell_lines': sum(s[2] for s in shells),
        'complexity_over_20': sum(1 for f in funcs if f['complexity'] > 20),
        'complexity_over_40': sum(1 for f in funcs if f['complexity'] > 40),
        'functions_over_100_lines': sum(1 for f in funcs if f['length'] > 100),
        'status_literals': len(statuses),
        'enums': types['Enum'],
        'typed_dicts': types['TypedDict'],
        'dataclasses': types['dataclass'],
        'annotated_public_functions_pct': round(100 * sum(f['annotated'] for f in public) / max(len(public), 1)),
        'annotated_core_functions_pct': round(100 * sum(f['annotated'] for f in core) / max(len(core), 1)),
        'cyrillic_outside_ui': len(cyr),
        'exception_text_checks': len(text_checks_on_exceptions(modules)),
        'field_set_checks': len(field_set_checks(modules)),
        'broad_handlers_swallowing': len(swallowed),
        'base_exception_swallowed': len(base),
        'semicolons': multi_statement_lines(modules),
        'long_lines': sum(kind == 'long' for m in modules.values() for _, kind in style_problems(m)),
        'shared_statement_lines': sum(kind == 'shared' for m in modules.values() for _, kind in style_problems(m)),
        'style_in_rewritten_modules': sum(len(style_problems(modules[n])) for n in STYLE_CLEAN if n in modules),
        'test_only_modules': len(dead),
        'test_only_lines': sum(modules[n].lines for n in dead),
        'monkeypatch_setattr': setattr_calls,
        'monkeypatch_package': package_patches,
        'test_private_access': test_private,
    }
    if clones:
        pairs, groups = near_clones(modules)
        result['near_clone_pairs'], result['near_clone_groups'] = pairs, len(groups)
    if details:
        result['details'] = {
            'cycles': cycles, 'cycle_closing_imports': closing, 'layer_violations': layer_violations(modules),
            'private_imports': priv, 'foreign_private_attributes': foreign, 'modules_without_all': missing_all(modules),
            'mutable_constants': mutable_constants(modules),
            'ctypes_modules': os_library_users(modules, 'ctypes'), 'test_only_modules': dead,
            'config_literals': literals, 'embedded_powershell': shells, 'status_literals': dict(statuses.most_common()),
            'complex_functions': sorted((f for f in funcs if f['complexity'] > 20), key=lambda f: -f['complexity']),
            'cyrillic_outside_ui': sorted(Counter(m for m, _ in cyr).items()),
            'exception_text_checks': text_checks_on_exceptions(modules), 'base_exception_swallowed': base,
            'style_in_rewritten_modules': {n: style_problems(modules[n]) for n in STYLE_CLEAN
                                           if n in modules and style_problems(modules[n])},
        }
        if clones:
            result['details']['near_clone_groups'] = groups
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--details', action='store_true')
    parser.add_argument('--no-clones', action='store_true', help='skip the slow near-clone search')
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding='utf-8')
    print(json.dumps(measure(args.root, clones=not args.no_clones, details=args.details), ensure_ascii=False, indent=1, default=list))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
