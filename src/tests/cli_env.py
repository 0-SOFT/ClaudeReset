"""The command line run against test folders: the environment points Paths.current at them."""


def folders(monkeypatch, paths):
    """Point the user profile and AppData variables at the folders of paths (missing ones next to its state);
    returns the --state-root arguments for the same state folder."""
    home = getattr(paths, 'home', None) or paths.state.parent / 'home'
    roaming = getattr(paths, 'roaming', None) or home / 'AppData/Roaming'
    local = getattr(paths, 'local', None) or home / 'AppData/Local'
    # Windows resolves the known folders under the profile, so they exist there whatever the variables say.
    for known in ('AppData/Roaming', 'AppData/Local'):
        (home / known).mkdir(parents=True, exist_ok=True)
    for name, value in (('USERPROFILE', home), ('HOME', home), ('APPDATA', roaming), ('LOCALAPPDATA', local)):
        value.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(name, str(value))
    return ['--state-root', str(paths.state)]
