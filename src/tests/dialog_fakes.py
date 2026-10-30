"""Scripted dialogs for the specialist window: answers by dialog name, every question recorded."""
from scripted import Scripted


class Dialogs(Scripted):
    """Stands in for expert_window.Dialogs. A dialog without an answer returns None, as a cancelled one does."""


def script(window, **answers):
    """Give the window scripted dialogs (once) and set these answers; returns the dialogs."""
    if not isinstance(vars(window).get('dialogs'), Dialogs):
        window.dialogs = Dialogs()
    window.dialogs.answers.update(answers)
    return window.dialogs
