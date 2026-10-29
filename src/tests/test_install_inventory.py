import pytest
from claude_reset import install_inventory as i
from claude_reset.safeio import SafetyError


def rows(): return [{'name': name, 'exists': False} for name in i.SERVICES]


def test_empty_slots_are_not_full_install_acceptance():
    assert i.fresh_install_blockers(rows(), False) == []


@pytest.mark.parametrize('index', range(4))
def test_existing_slot_never_implies_ownership_even_for_product_path(index):
    data = rows(); data[index].update(exists=True, binary='C:\\Program Files\\ClaudeReset\\owned.exe')
    result = i.fresh_install_blockers(data, False)
    assert result[0]['service'] == i.SERVICES[index]
    assert result[0]['code'] == 'service_slot_occupied'


def test_existing_root_is_not_adopted():
    assert i.fresh_install_blockers(rows(), True)[0]['code'] == 'installation_directory_occupied'


@pytest.mark.parametrize('data', [[], rows()[:-1], rows()[::-1], rows()+rows(),
    [{'name': n, 'exists': 0} for n in i.SERVICES], [None]*4])
def test_incomplete_or_ambiguous_inventory_is_not_clean(data):
    with pytest.raises(SafetyError): i.fresh_install_blockers(data, False)


@pytest.mark.parametrize('index', range(4))
@pytest.mark.parametrize('status', [0, 5, 3, 1018])
def test_registry_conflict_or_unknown_is_reported_without_scm_entry(tmp_path, monkeypatch, index, status):
    import ctypes as C
    opened=[]; closed=[]
    class Api:
        def RegOpenKeyExW(self, hive, key, options, access, output):
            assert hive.value == i.W.HANDLE(-2147483646).value
            assert options == 8 and access == 0x20101
            name=key.rsplit('\\',1)[-1];opened.append(name)
            assert key == 'SYSTEM\\CurrentControlSet\\Services\\'+name
            if name != i.SERVICES[index]:return 2
            if status == 0:C.cast(output,C.POINTER(i.W.HANDLE))[0]=123
            return status
        def RegCloseKey(self, handle):
            closed.append(handle.value);return 0
    monkeypatch.setattr(i,'_registry_native',Api)
    monkeypatch.setattr(i,'services',rows)
    monkeypatch.setattr(i,'program_files',lambda:tmp_path)
    result=i.inspect()
    assert opened == list(i.SERVICES) and closed == ([123] if status == 0 else [])
    assert result['services'] == rows() and result['schema'] == 2
    assert result['settings_changed'] is False and result['client_admission'] is False
    assert len(result['fresh_install_blockers']) == 1
    blocker=result['fresh_install_blockers'][0]
    assert blocker['service'] == i.SERVICES[index]
    assert blocker['code'] == ('service_registry_slot_occupied' if status == 0 else
                               'service_registry_slot_unverified')
    row=result['registry_slots'][index]
    assert row['exists'] is (True if status == 0 else None)
    assert row['inspected'] is (status == 0)


@pytest.mark.parametrize('invalid_handle', [False, True])
def test_registry_success_requires_handle_and_successful_close(monkeypatch, invalid_handle):
    import ctypes as C
    closed=[]
    class Api:
        def RegOpenKeyExW(self,hive,key,options,access,output):
            if not invalid_handle:C.cast(output,C.POINTER(i.W.HANDLE))[0]=123
            return 0
        def RegCloseKey(self,handle):closed.append(handle.value);return 6
    monkeypatch.setattr(i,'_registry_native',Api)
    result=i.registry_slots()
    assert all(row['inspected'] is False for row in result)
    assert all(row['exists'] is (None if invalid_handle else True) for row in result)
    assert closed == ([] if invalid_handle else [123]*4)


def test_all_registry_slots_absent_is_only_a_snapshot(tmp_path,monkeypatch):
    class Api:
        def RegOpenKeyExW(self,*args):return 2
        def RegCloseKey(self,*args):pytest.fail('No handle was opened')
    monkeypatch.setattr(i,'_registry_native',Api)
    monkeypatch.setattr(i,'services',rows)
    monkeypatch.setattr(i,'program_files',lambda:tmp_path)
    result=i.inspect()
    assert result['fresh_install_blockers'] == []
    assert all(row['inspected'] and row['exists'] is False for row in result['registry_slots'])
    assert result['client_admission'] is False
