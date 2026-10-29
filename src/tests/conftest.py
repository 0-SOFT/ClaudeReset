"""Shared fixtures."""
import tkinter as tk

import pytest


@pytest.fixture(scope='session')
def tk_root():
    """One hidden Tk interpreter for the whole run: on Windows a second tk.Tk() in the same process
    intermittently fails to read init.tcl, which silently skipped window tests. The product creates one root."""
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip('no Tk display available')
    root.withdraw()
    yield root
    root.destroy()
