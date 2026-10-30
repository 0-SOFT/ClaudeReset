"""The tabs of the specialist window (ui/expert_window.py), one module per tab or group of tabs.

Each tab object is made with the window (`App`), builds its widgets on the frame the window gives it and handles its
own buttons. What several tabs share — the reset plan, the chosen components, the server step, background work,
dialogs and the program's areas — is the window's, and a tab reaches it through `self.app`.
"""
