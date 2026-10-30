import importlib.util
from pathlib import Path

from claude_reset.backend import broker_policy as policy, boxes as install_configuration

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_managed_config', ROOT / 'tools/prepare_managed_config.py')
managed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(managed)


def test_managed_configuration_accepts_the_fixed_policy():
    boxes, settings = managed.managed_policy_contract()
    assert boxes == install_configuration.BOXES
    assert dict(settings) == policy.ISOLATION_SETTINGS
    assert managed.managed_forbidden_settings() == policy.FORBIDDEN_SETTINGS


def test_forbidden_settings_are_never_enabled_by_the_fixed_policy():
    enabled = {name.casefold() for name, value in policy.ISOLATION_SETTINGS.items() if value == 'y'}
    assert not enabled & {name.casefold() for name in policy.FORBIDDEN_SETTINGS}
