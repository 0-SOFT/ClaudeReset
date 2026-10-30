"""The client process catalog reproduces the lists the reset, Cowork, key and customization steps used to keep."""
import pytest

from claude_reset.model import clients
from claude_reset.model.clients import ProcessKind as K


def test_component_owners_match_the_former_lists():
    assert clients.owners('code', 'vscode', 'desktop') == {'Claude.exe', 'claude.exe', 'claude-desktop.exe', 'claude-child',
                                                          'cowork-svc.exe', 'Code.exe', 'Code - Insiders.exe'}
    assert clients.owners('code', 'vscode') == {'claude.exe', 'claude-child', 'Code.exe', 'Code - Insiders.exe'}
    assert clients.owners('desktop') == {'Claude.exe', 'claude-desktop.exe', 'cowork-svc.exe'}
    assert clients.CLAUDE_PROCESSES == {'Claude.exe', 'claude.exe', 'claude-desktop.exe', 'claude-child'}
    assert clients.owners('unknown') == frozenset()


@pytest.mark.parametrize('kind,components,expected', [
    ('claude.exe', [], True), ('claude-child', ['chrome'], True),
    ('Code.exe', ['code'], False), ('Code.exe', ['vscode'], True),
    ('Claude.exe', ['code', 'vscode'], False), ('cowork-svc.exe', ['desktop'], True),
    ('chrome-managed', ['code'], False), ('chrome-managed', ['chrome'], True),
    ('node.exe', ['code', 'vscode', 'chrome', 'desktop'], False)])
def test_blocking_processes_follow_the_selected_components(kind, components, expected):
    assert clients.blocking(kind, components) is expected


def test_desktop_and_command_line_differ_only_by_case():
    # Windows reports both image names as they are on disk; the case tells Desktop from the CLI.
    assert K.DESKTOP != K.CODE_CLI and K.DESKTOP.lower() == K.CODE_CLI
    assert clients.image_names({K.DESKTOP, K.CODE_CLI}) == {'claude.exe'}
