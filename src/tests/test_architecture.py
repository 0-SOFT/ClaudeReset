"""Architecture ratchet (docs/DEVELOPMENT.md, the architecture metrics).

Each limit is the current value of a metric from tools/architecture_metrics.py. A change may keep or improve
it; a regression fails here. When a refactoring step improves a metric, lower its limit in the same commit.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('architecture_metrics', ROOT / 'tools/architecture_metrics.py')
metrics_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics_tool)

# Upper limits: lower is better.
AT_MOST = {
    'cycles': 0,
    'modules_in_cycles': 0,
    'cycle_closing_imports': 0,
    'layer_violations': 0,
    'private_imports': 0,
    'foreign_private_attributes': 0,
    'modules_without_all': 0,
    'mutable_constants': 0,
    'global_statements': 0,
    'ctypes_modules': 0,
    'winreg_modules': 0,
    'subprocess_modules': 0,
    'argtypes_declarations': 1,
    'kernel32_loaders': 0,
    'config_literals': 3,
    'owned_names_retyped': 0,
    'embedded_powershell': 0,
    'complexity_over_20': 20,
    'complexity_over_40': 0,
    'functions_over_100_lines': 0,
    # Stage 8 (decision A): a window is a frame that composes its pages and tabs. The largest class is the main
    # window's frame, Shell (29 methods); the plan's bound is 30.
    'modules_over_800_lines': 0,
    'largest_class_methods': 29,
    'status_literals': 0,
    'cyrillic_outside_ui': 0,
    'exception_text_checks': 0,
    'field_set_checks': 0,
    'broad_handlers_swallowing': 11,
    'base_exception_swallowed': 1,
    'semicolons': 0,
    'long_lines': 404,
    'shared_statement_lines': 0,
    'style_in_rewritten_modules': 0,
    'test_only_modules': 0,
    'near_clone_groups': 0,
    'monkeypatch_setattr': 116,
    'monkeypatch_package': 55,
    'test_private_access': 0,
    # Stage 8: the two windows split into a frame and page and tab modules (+564 lines: module headers, lines
    # wrapped to 120 characters).
    'lines': 19230,
    # Scenarios hand the windows typed results. What is left are the ports protection.L1 (check, report, install,
    # restart, remove) and reset.Actions (close_claude, stop_cowork, archive_extras, wipe): they pass the domains'
    # own operation reports to the scenarios, which turn them into results.
    'services_dict_results': 9,
    # Stage 7 of the quality plan: a collaborator's default is the real thing, bound in the signature. What is left
    # keeps None because the default cannot exist when the function is defined (it depends on another argument, is
    # read or created on each call); each such parameter says why on its line (test below).
    'none_default_collaborators': 19,
    'module_class_attributes': 0,
}
# Lower limits: higher is better.
AT_LEAST = {
    'enums': 31,
    'dataclasses': 37,
    'annotated_public_functions_pct': 40,
    'annotated_core_functions_pct': 100,
}


@pytest.fixture(scope='module')
def measured():
    return metrics_tool.measure(ROOT)


@pytest.mark.parametrize('name', sorted(AT_MOST))
def test_metric_does_not_regress(measured, name):
    assert measured[name] <= AT_MOST[name], f'{name} rose to {measured[name]} (limit {AT_MOST[name]}); see --details'


@pytest.mark.parametrize('name', sorted(AT_LEAST))
def test_typed_metric_does_not_regress(measured, name):
    assert measured[name] >= AT_LEAST[name], f'{name} fell to {measured[name]} (limit {AT_LEAST[name]})'


def test_cycle_detection_sees_imports_inside_functions(tmp_path):
    package = tmp_path / 'src/claude_reset'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('')
    (package / 'a.py').write_text('from . import b\n')
    (package / 'b.py').write_text('def f():\n    from . import a\n')
    modules = metrics_tool.load(tmp_path)
    assert metrics_tool.strongly_connected(metrics_tool.graph(modules)) == [['a', 'b']]
    assert metrics_tool.strongly_connected(metrics_tool.graph(modules, lazy=False)) == []
    assert metrics_tool.cycle_closing_lazy(modules) == [('b', 'a')]


def test_layer_rule_rejects_an_upward_import(tmp_path):
    package = tmp_path / 'src/claude_reset'
    (package / 'windows').mkdir(parents=True)
    (package / '__init__.py').write_text('')
    (package / 'windows/__init__.py').write_text('')
    (package / 'windows/api.py').write_text('from ..services import x\n')
    (package / 'services.py').write_text('x = 1\n')
    modules = metrics_tool.load(tmp_path)
    assert metrics_tool.layer_violations(modules) == [('windows.api', 'services')]


def test_style_rule_counts_long_code_lines_and_shared_lines_but_not_string_text(tmp_path):
    package = tmp_path / 'src/claude_reset'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('')
    long_text = 'x' * 130
    lines = ['S = """', long_text, '"""', f"T = '{long_text}'", 'if S: T = 1', 'U = 1; V = 2']
    (package / 'a.py').write_text('\n'.join(lines) + '\n')
    module = metrics_tool.load(tmp_path)['a']
    assert metrics_tool.style_problems(module) == [(4, 'long'), (5, 'shared'), (6, 'shared')]


def test_scenario_rule_counts_dict_results_but_not_documents(tmp_path):
    package = tmp_path / 'src/claude_reset'
    (package / 'services').mkdir(parents=True)
    (package / '__init__.py').write_text('')
    (package / 'services/__init__.py').write_text('')
    lines = ['def plain() -> dict:', '    return {}',
             'def pair():', '    return None, {"status": 1}',
             'def typed() -> "Result":', '    def inner():', '        return {}', '    return Result()',
             'class Result:', '    def to_json(self) -> dict:', '        return {}',
             '    def check(self) -> tuple[int, dict | None]:', '        return 1, None']
    (package / 'services/a.py').write_text('\n'.join(lines) + '\n')
    modules = metrics_tool.load(tmp_path)
    assert metrics_tool.services_dict_results(modules) == [('services.a', 'Result.check'), ('services.a', 'pair'),
                                                           ('services.a', 'plain')]


def test_seam_rules_count_none_replacements_and_modules_in_class_bodies(tmp_path):
    package = tmp_path / 'src/claude_reset'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('')
    (package / 'b.py').write_text('')
    lines = ['import os', 'from . import b',
             'def either(run=None):', '    return run or os.getcwd',
             'def branch(read=None):', '    if read is None:', '        read = os.getcwd',
             'def kept(home=None):   # None: read on each call', '    return os.getcwd() if home is None else home',
             'def data(flag=None):', '    if flag is None:', '        return 0',
             'def _private(run=None):', '    return run or os.getcwd',
             'class Holder:', '    b = b', '    os = os', '    name = "b"']
    (package / 'a.py').write_text('\n'.join(lines) + '\n')
    modules = metrics_tool.load(tmp_path)
    assert metrics_tool.none_default_collaborators(modules) == [
        ('a', 'branch', 5, ['read'], False), ('a', 'either', 3, ['run'], False), ('a', 'kept', 8, ['home'], True)]
    assert metrics_tool.module_class_attributes(modules) == [('a', 'Holder', 'b'), ('a', 'Holder', 'os')]


def test_size_rules_count_the_methods_of_each_class_and_the_long_modules(tmp_path):
    package = tmp_path / 'src/claude_reset'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('')
    lines = ['class Big:', '    def a(self):', '        pass', '    def b(self):', '        pass',
             '    class Inner:', '        def c(self):', '            pass', 'class Small:', '    x = 1']
    (package / 'a.py').write_text('\n'.join(lines) + '\n')
    (package / 'b.py').write_text('x = 1\n' * 801)
    modules = metrics_tool.load(tmp_path)
    assert metrics_tool.class_methods(modules) == [(2, 'a', 'Big'), (1, 'a', 'Inner'), (0, 'a', 'Small')]
    measured = metrics_tool.measure(tmp_path, clones=False)
    assert measured['modules_over_800_lines'] == 1 and measured['largest_class_methods'] == 2


def test_every_kept_none_default_says_why():
    """A parameter that keeps None as its default carries `# None: <reason>` on its line."""
    found = metrics_tool.none_default_collaborators(metrics_tool.load(ROOT))
    assert [row[:4] for row in found if not row[4]] == []


def test_lint_is_clean():
    """ruff (ruff.toml): imports in order and used, no undefined or shadowed names."""
    if subprocess.run([sys.executable, '-m', 'ruff', '--version'], capture_output=True).returncode:
        pytest.skip('ruff is not installed (requirements-lock.txt)')
    folders = [name for name in ('src', 'tools', 'packaging', 'maintainer') if (ROOT / name).is_dir()]
    result = subprocess.run([sys.executable, '-m', 'ruff', 'check', *folders], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout
