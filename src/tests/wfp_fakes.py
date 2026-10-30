"""Test doubles of WFP sessions: native calls go to a Python function instead of fwpuclnt."""
from claude_reset.windows.wfp_session import Session


def fake(base=Session):
    """A subclass of a session class whose native calls go to self.native(name, *args, allowed=())."""
    class Fake(base):
        def __init__(self, handle=1, *, dynamic=False, in_transaction=False):
            # Session's own constructor opens BFE; a double sets only the state the session methods read.
            self.handle, self.dynamic, self._transaction, self._parent = handle, dynamic, in_transaction, None

        def call(self, name, *args, allowed=()):
            return self.native(name, *args, allowed=allowed) or 0

        def native(self, name, *args, allowed=()):
            return 0

        def free(self, pointer):
            pass
    Fake.__name__ = 'Fake' + base.__name__
    return Fake


FakeSession = fake()
