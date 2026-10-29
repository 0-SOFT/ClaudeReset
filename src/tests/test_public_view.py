"""Shown and saved results carry no secrets, exit addresses, user name or home folder."""
import json

from claude_reset.public_view import HIDDEN, redact

HOME, USER = r'C:\Users\alice', 'alice'


def test_secret_keys_are_hidden_but_flags_and_empty_values_stay():
    result = redact({'password': 'hunter2', 'username': 'bob', 'token': 'abc', 'proxy_uuid': 'u-1',
                     'password_saved': True, 'login': '', 'nested': [{'secret': 'x'}]}, home=HOME, user=USER)
    assert result == {'password': HIDDEN, 'username': HIDDEN, 'token': HIDDEN, 'proxy_uuid': HIDDEN,
                      'password_saved': True, 'login': '', 'nested': [{'secret': HIDDEN}]}


def test_public_addresses_hidden_private_and_versions_kept():
    text = 'exit 9.9.9.9 via 127.0.0.1:25080 lan 192.168.1.5 v6 2001:4860:4860::8888 desktop 4.29.0.0'
    assert redact(text, home=HOME, user=USER) == 'exit <адрес> via 127.0.0.1:25080 lan 192.168.1.5 v6 <адрес> desktop <адрес>'
    versions = redact({'client_versions': {'desktop': '4.29.0.0', 'vscode_extensions': ['2.1.0']}, 'exit': '9.9.9.9'},
                      home=HOME, user=USER)
    assert versions == {'client_versions': {'desktop': '4.29.0.0', 'vscode_extensions': ['2.1.0']}, 'exit': '<адрес>'}


def test_user_folder_name_and_url_credentials():
    value = {'path': r'C:\Users\alice\.claude\x', 'other': 'c:/users/alice/AppData', 'note': 'owner alice here',
             'proxy': 'socks5://alice:pw@10.0.0.1:1080'}
    result = redact(value, home=HOME, user=USER)
    assert result['path'] == r'%USERPROFILE%\.claude\x' and result['other'] == '%USERPROFILE%/AppData'
    assert result['note'] == 'owner <пользователь> here'
    assert result['proxy'] == 'socks5://' + HIDDEN + '@10.0.0.1:1080'
    assert 'alice' not in json.dumps(result) and 'pw' not in json.dumps(result)
