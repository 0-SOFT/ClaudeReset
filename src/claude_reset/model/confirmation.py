"""A person's explicit confirmation of an irreversible step.

The window and the command line ask for it in the person's language (typing a word, for example) and pass
the member below; the operations accept nothing else, so a missing or mistyped confirmation never reaches them.
"""
from enum import Enum

__all__ = ['Confirmation']


class Confirmation(Enum):
    ERASE = 'erase'   # delete Claude data or site data that cannot be restored
