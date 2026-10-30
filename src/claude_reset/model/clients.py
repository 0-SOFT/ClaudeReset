"""Processes of the Claude clients and the reset component whose data each one holds.

A kind is the image name Windows reports for a process, with its case: Claude Desktop runs as
'Claude.exe' and the Claude Code command line as 'claude.exe'. The runtime inventory reports Node
processes started by Claude Code as 'claude-child' and the dedicated Chrome as 'chrome-managed'.
"""
from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from types import MappingProxyType

__all__ = ['Component', 'ProcessKind', 'COMPONENT_PROCESSES', 'CLOSABLE_APPS', 'CLAUDE_PROCESSES', 'CHROME_IMAGE',
           'owners', 'blocking', 'image_names']


class Component(StrEnum):
    CODE = 'code'
    VSCODE = 'vscode'
    CHROME = 'chrome'
    DESKTOP = 'desktop'


class ProcessKind(StrEnum):
    DESKTOP = 'Claude.exe'
    DESKTOP_HELPER = 'claude-desktop.exe'
    COWORK_SERVICE = 'cowork-svc.exe'
    CODE_CLI = 'claude.exe'
    CODE_CHILD = 'claude-child'
    EDITOR = 'Code.exe'
    EDITOR_INSIDERS = 'Code - Insiders.exe'
    MANAGED_CHROME = 'chrome-managed'


COMPONENT_PROCESSES = MappingProxyType({
    Component.CODE: frozenset({ProcessKind.CODE_CLI, ProcessKind.CODE_CHILD}),
    Component.VSCODE: frozenset({ProcessKind.EDITOR, ProcessKind.EDITOR_INSIDERS}),
    Component.DESKTOP: frozenset({ProcessKind.DESKTOP, ProcessKind.DESKTOP_HELPER, ProcessKind.COWORK_SERVICE}),
    Component.CHROME: frozenset({ProcessKind.MANAGED_CHROME}),
})
# Claude programs the reset may close itself; the shared editor is never closed.
CLOSABLE_APPS = (ProcessKind.DESKTOP, ProcessKind.CODE_CLI, ProcessKind.DESKTOP_HELPER)
# Everything that closes with them, including Claude Code's Node children.
CLAUDE_PROCESSES = frozenset(CLOSABLE_APPS) | {ProcessKind.CODE_CHILD}
CHROME_IMAGE = 'chrome.exe'


def owners(*components: str) -> frozenset[ProcessKind]:
    """Process kinds that hold the data of the given components; unknown component names hold none."""
    return frozenset().union(*(COMPONENT_PROCESSES.get(c, frozenset()) for c in components))


def blocking(kind: str, components: Iterable[str]) -> bool:
    """Whether a running process of this kind must close before a reset of these components.

    Claude Code processes always block: every reset touches Claude Code data."""
    return kind in owners(Component.CODE, *components)


def image_names(kinds: Iterable[str]) -> frozenset[str]:
    """Lower-case image names, for inventories that compare names without case."""
    return frozenset(str(kind).lower() for kind in kinds)
