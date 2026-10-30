"""A test double whose methods answer from a table; the tests give it to the code instead of patching modules."""


class Scripted:
    """Each answer is a value, or a function of the call's arguments; every call is recorded in `calls`.
    A call without an answer gets `unscripted(name)`: None here, a refusal in stricter doubles."""

    def __init__(self, **answers):
        self.answers, self.calls = dict(answers), []

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)

        def call(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            if name not in self.answers:
                return self.unscripted(name)
            answer = self.answers[name]
            return answer(*args, **kwargs) if callable(answer) else answer
        return call

    def unscripted(self, name):
        return None


class Strict(Scripted):
    """A double that refuses any call it has no answer for: the code under test asked for something unexpected."""

    def unscripted(self, name):
        raise AssertionError(f'unexpected call: {name}')
