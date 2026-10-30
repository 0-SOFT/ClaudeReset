"""The report of a multi-step operation: each step in order, then how the operation ended.

It is a plain dict, so it is written to JSON and read back exactly as the reports have always been."""
from __future__ import annotations

from .status import Step

__all__ = ['OperationReport']


class OperationReport(dict):
    def __init__(self, action: str) -> None:
        super().__init__(schema=1, action=action, finished=False, steps=[])

    def ok(self, step: str, **details: object) -> None:
        self['steps'].append({'step': step, 'status': Step.OK, **details})

    def stop(self, status: str, step: str, **details: object) -> OperationReport:
        """The step that ended the operation early; returns the finished report."""
        self['steps'].append({'step': step, 'status': Step.STOPPED, **details})
        self.update(status=status, finished=True)
        return self
