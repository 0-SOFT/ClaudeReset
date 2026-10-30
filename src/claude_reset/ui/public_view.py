"""Make any result safe to show or save: no passwords, exit addresses, user name or home folder.

Used for everything the windows display as raw data and for every saved report, on top of the
domain redaction the producing functions already do.
"""
import ipaddress
import os
import re

__all__ = ['HIDDEN', 'redact']

SECRET_KEYS = re.compile(r'(?i)(pass(word|wd)?|secret|token|private.?key|uuid|user(name)?|login|cookie|credential|auth)$')
ADDRESS = re.compile(r'(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])|(?<![\w:])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])')
URL_CREDENTIALS = re.compile(r'(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:"\']+:[^\s/@"\']*@')
HIDDEN = '•••'


def _public_address(text):
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return address.is_global


def _text(value, home, user, version=False):
    value = URL_CREDENTIALS.sub(r'\1' + HIDDEN + '@', value)
    if home:
        value = re.sub(re.escape(home), '%USERPROFILE%', value, flags=re.I)
        value = re.sub(re.escape(home.replace('\\', '/')), '%USERPROFILE%', value, flags=re.I)
    if user and len(user) > 2:
        value = re.sub(r'(?i)(?<![\w])' + re.escape(user) + r'(?![\w])', '<пользователь>', value)
    if version:  # client versions such as 4.29.0.0 look like addresses but are needed in reports
        return value
    return ADDRESS.sub(lambda m: '<адрес>' if _public_address(m.group(0)) else m.group(0), value)


def redact(value, *,
           home=None,   # None: USERPROFILE, read on each call
           user=None,   # None: USERNAME, read on each call
           version=False):
    """A copy of value with secrets and identifying details replaced; structure and keys are kept."""
    home = home if home is not None else os.environ.get('USERPROFILE', '')
    user = user if user is not None else os.environ.get('USERNAME', '')
    if isinstance(value, dict):
        return {key: (HIDDEN if isinstance(key, str) and SECRET_KEYS.search(key) and item not in (None, '', [], {})
                      and not isinstance(item, bool)
                      else redact(item, home=home, user=user,
                                  version=version or (isinstance(key, str) and 'version' in key.lower())))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, home=home, user=user, version=version) for item in value]
    if isinstance(value, str):
        return _text(value, home, user, version)
    return value
