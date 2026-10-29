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


@pytest.fixture(autouse=True)
def no_real_file_dialogs(monkeypatch):
    """A real file dialog waits for a person and stops the run (a stray key press on a focused test window opened one).
    Tests that need a chosen file patch these themselves."""
    from tkinter import filedialog
    for name in ('askopenfilename', 'asksaveasfilename', 'askdirectory'):
        monkeypatch.setattr(filedialog, name, lambda **_: '')
