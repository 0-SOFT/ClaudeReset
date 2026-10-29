import hashlib
import pytest
from claude_reset import private_templates as policy
from claude_reset.safeio import SafetyError


def reviewed(monkeypatch,data,count):
    monkeypatch.setattr(policy,'REVIEWED_INPUTS',{hashlib.sha256(data).hexdigest():count})


def test_only_default_window_exceptions_removed_other_sections_preserved(monkeypatch):
    data=(b'# vendor\r\n[TemplateDefaultPaths]\r\nOpenFilePath=C:\\*\r\n'
          b'OpenWinClass=MdiClass\r\nOpenWinClass=vmware.exe,MKSEmbedded\r\n'
          b'[Template_Optional]\r\nOpenWinClass=Other\r\n')
    reviewed(monkeypatch,data,2)
    output,report=policy.close_default_windows(data)
    assert b'OpenFilePath=C:\\*\r\n' in output
    assert output.endswith(b'[Template_Optional]\r\nOpenWinClass=Other\r\n')
    assert b'MdiClass' not in output and b'MKSEmbedded' not in output
    assert report['requires_exclusive_owned_runtime'] and not report['installed']
    assert not report['full_tunnel_verified'] and not report['production_clients_permitted']
    assert report['output_sha256']==hashlib.sha256(output).hexdigest()


@pytest.mark.parametrize('data',[b'',b'[TemplateDefaultPaths]\nOpenWinClass=*\n','text'])
def test_unknown_vendor_bytes_rejected(data):
    with pytest.raises(SafetyError):policy.close_default_windows(data)


@pytest.mark.parametrize('data,count',[(b'[Other]\nOpenWinClass=X\n',1),
    (b'[TemplateDefaultPaths]\nOpenWinClass=X\n',2),
    (b'[TemplateDefaultPaths]\nOpenWinClass=X\n[TemplateDefaultPaths]\n',1)])
def test_pinned_manifest_must_also_have_expected_structure(monkeypatch,data,count):
    reviewed(monkeypatch,data,count)
    with pytest.raises(SafetyError):policy.close_default_windows(data)
