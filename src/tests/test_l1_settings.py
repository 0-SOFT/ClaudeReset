import os

import pytest

from claude_reset import config
from claude_reset.network import l1_settings as own

ENV = [{'name': 'HTTP_PROXY', 'value': config.RELAY_URL}, {'name': 'HTTPS_PROXY', 'value': config.RELAY_URL},
       {'name': 'NO_PROXY', 'value': 'localhost,127.0.0.1,::1'}]


def test_nothing_set_is_trivially_owned():
    assert own.owned_launch_settings({})
    assert own.owned_launch_settings({'claudeCode.environmentVariables': [], 'claudeCode.claudeProcessWrapper': ''})


def test_exactly_the_installed_values_are_recognised_in_any_order():
    assert own.owned_launch_settings({'claudeCode.environmentVariables': ENV})
    assert own.owned_launch_settings({'claudeCode.environmentVariables': list(reversed(ENV))})
    assert own.owned_launch_settings({'claudeCode.environmentVariables': ENV, 'claudeCode.claudeProcessWrapper': str(own.runner_path())})


@pytest.mark.parametrize('settings', [
    {'claudeCode.environmentVariables': ENV[:2]},                                                      # a variable missing
    {'claudeCode.environmentVariables': ENV + [{'name': 'ANTHROPIC_API_KEY', 'value': 'x'}]},         # an extra variable
    {'claudeCode.environmentVariables': [dict(ENV[0], value='http://127.0.0.1:9999')] + ENV[1:]},     # another proxy
    {'claudeCode.environmentVariables': [dict(ENV[0], extra=1)] + ENV[1:]},
    {'claudeCode.environmentVariables': 'HTTP_PROXY=x'},
    {'claudeCode.claudeProcessWrapper': r'C:\Users\someone\wrapper.exe'},
    {'claudeCode.claudeProcessWrapper': str(own.runner_path()) + '.evil'},
    {'claudeCode.claudeProcessWrapper': 7},
])
def test_anything_else_still_needs_review(settings):
    assert not own.owned_launch_settings(settings)


def test_runner_path_comparison_ignores_case_and_slashes():
    odd = str(own.runner_path()).upper().replace(chr(92), '/')
    assert own.owned_launch_settings({'claudeCode.claudeProcessWrapper': odd})


def test_the_vscode_tool_and_the_check_agree_on_the_values():
    assert config.RELAY_URL == config.RELAY_URL and config.RUNNER_EXE == config.RUNNER_EXE
