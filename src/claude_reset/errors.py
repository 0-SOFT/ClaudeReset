"""Errors of the program. Every refusal is a SafetyError; a subclass says what kind of refusal it is.

The message is for people and logs. Code that needs to react to a kind of failure checks the class or its
`code`, never the text: texts change and are translated.
"""

__all__ = ['BrowsersOpenError', 'LimitExceeded', 'PlatformError', 'SafetyError', 'SchemaError', 'UnsafePathError',
           'WfpError', 'error_info']


class SafetyError(RuntimeError):
    """The program refused or stopped an operation instead of risking an unsafe result.

    `code` names the kind of refusal; a specific code (code=...) also selects the text people read.
    """
    code = 'refused'

    def __init__(self, *args, code=None):
        super().__init__(*args)
        if code is not None:
            self.code = code


class UnsafePathError(SafetyError):
    """A path escapes its approved root, passes a reparse point or uses a Windows alias."""
    code = 'unsafe_path'


class SchemaError(SafetyError):
    """A stored or supplied document does not have the exact expected form."""
    code = 'schema'


class LimitExceeded(SafetyError):
    """An input is larger than the program accepts."""
    code = 'limit'


class BrowsersOpenError(SafetyError):
    """Chrome or Edge is running, so their site data cannot be changed safely."""
    code = 'browsers_open'


class PlatformError(SafetyError):
    """A Windows call failed; `api` names it and `status` is its result code when there is one."""
    code = 'platform'

    def __init__(self, message, *, api=None, status=None, code=None):
        super().__init__(message, code=code)
        self.api, self.status = api, status


class WfpError(PlatformError):
    """A Windows Filtering Platform call failed."""
    code = 'wfp'


def error_info(exc, limit=200):
    """The text a report keeps about an unexpected exception: its type and the start of its message."""
    return type(exc).__name__ + ': ' + str(exc)[:limit]
