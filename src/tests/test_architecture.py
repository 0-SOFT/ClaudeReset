"""Architecture ratchet (docs/DEVELOPMENT.md, the architecture metrics).

Each limit is the current value of a metric from tools/architecture_metrics.py. A change may keep or improve
it; a regression fails here. When a refactoring step improves a metric, lower its limit in the same commit.
"""
import importlib.util
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
    'embedded_powershell': 0,
    'complexity_over_20': 24,
    'complexity_over_40': 0,
    'functions_over_100_lines': 0,
    'status_literals': 0,
    'cyrillic_outside_ui': 0,
    'exception_text_checks': 0,
    'field_set_checks': 0,
    'broad_handlers_swallowing': 64,
    'base_exception_swallowed': 7,
    'semicolons': 0,
    'long_lines': 651,
    'shared_statement_lines': 0,
    'style_in_rewritten_modules': 0,
    'test_only_modules': 0,
    'near_clone_groups': 0,
    'monkeypatch_setattr': 150,
    'monkeypatch_package': 72,
    'test_private_access': 0,
    'lines': 20512,
}
# Lower limits: higher is better.
AT_LEAST = {
    'enums': 25,
    'dataclasses': 17,
    'annotated_public_functions_pct': 39,
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
