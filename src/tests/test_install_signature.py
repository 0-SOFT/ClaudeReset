import ctypes as C
import hashlib
import struct
from pathlib import Path
import pytest
from claude_reset.windows import authenticode as sig
from claude_reset.windows.pin import PinnedFile
from claude_reset.safeio import SafetyError
from scripted import Strict


class Provider:
    def __init__(self, pin, status=0, close_status=0, missing=False, crash=False):
        self.pin = pin; self.status = status; self.close_status = close_status
        self.missing = missing; self.crash = crash; self.actions = []
        self.der = C.create_string_buffer(b'modeled signer DER')
        self.cert = sig.CertContext(1, C.cast(self.der, C.c_void_p), len(self.der.raw), None, None)
        self.leaf = sig.ProviderCert(); self.leaf.size = C.sizeof(self.leaf)
        self.leaf.cert = C.pointer(self.cert)
        self.signer = sig.ProviderSigner(); self.signer.size = C.sizeof(self.signer)
        self.signer.count = 1; self.signer.certs = C.pointer(self.leaf)

    def WinVerifyTrust(self, hwnd, guid, pointer):
        data = C.cast(pointer, C.POINTER(sig.TrustData)).contents
        assert hwnd.value == C.c_void_p(-1).value
        assert data.ui == 2 and data.choice == 1 and data.flags == 0x3080
        assert data.file.contents.handle == self.pin.handle
        assert data.file.contents.path == str(self.pin.path)
        self.actions.append(data.action)
        if data.action == 2: return self.close_status
        data.state = 123
        if self.crash: raise RuntimeError('modeled provider exception')
        return self.status

    def WTHelperProvDataFromStateData(self, state):
        assert state == 123
        return None if self.missing else 456

    def WTHelperGetProvSignerFromChain(self, provider, index, counter, counter_index):
        assert (provider, index, counter, counter_index) == (456, 0, False, 0)
        return C.pointer(self.signer)


@pytest.mark.parametrize('status', [0, 1, -2146762496, -2146885614])
def test_zero_only_success_and_always_close(tmp_path, status):
    path = tmp_path/'fixture.exe'; path.write_bytes(b'inert fixture')
    with PinnedFile(path) as pin:
        api = Provider(pin, status)
        if status:
            with pytest.raises(SafetyError, match='verification failed'): sig.inspect_signature(pin, api=api)
        else:
            evidence = sig.inspect_signature(pin, api=api)
            assert evidence['file_sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
            assert evidence['signer_certificate_sha256'] == hashlib.sha256(api.der.raw).hexdigest()
            assert not evidence['installable'] and not evidence['release_authority_verified']
            assert not evidence['kernel_load_verified'] and not evidence['client_admission']
        assert api.actions == [1, 2] and pin.handle
        with pytest.raises(OSError): path.write_bytes(b'replacement')


@pytest.mark.parametrize('fault', ['missing', 'crash', 'close', 'signer_error', 'test_cert', 'length', 'short_struct'])
def test_provider_faults_fail_closed_and_release_state(tmp_path, fault):
    path = tmp_path/'fixture'; path.write_bytes(b'inert fixture')
    with PinnedFile(path) as pin:
        api = Provider(pin, missing=fault=='missing', crash=fault=='crash', close_status=int(fault=='close'))
        if fault == 'signer_error': api.signer.error = 1
        if fault == 'test_cert': api.leaf.test = True
        if fault == 'length': api.cert.length = 0
        if fault == 'short_struct': api.signer.size = 0
        with pytest.raises((SafetyError, RuntimeError)): sig.inspect_signature(pin, api=api)
        assert api.actions == [1, 2] and pin.handle


def test_closed_pin_does_not_load_provider(tmp_path):
    path = tmp_path/'fixture'; path.write_bytes(b'inert')
    pin = PinnedFile(path); pin.close()
    with pytest.raises(SafetyError, match='open payload pin'): sig.inspect_signature(pin, api=Strict())


def test_native_unsigned_file_refused(tmp_path):
    path = tmp_path/'unsigned.exe'; path.write_bytes(b'inert unsigned fixture')
    with PinnedFile(path) as pin:
        with pytest.raises(SafetyError, match='Offline Authenticode verification failed'):
            sig.inspect_signature(pin)
        assert pin.handle


def test_native_microsoft_compiler_cached_trust():
    # Read-only platform fixture; never an allowed product signing authority.
    path = Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
    if not path.exists(): pytest.skip('Platform compiler fixture absent')
    with PinnedFile(path) as pin:
        try: evidence = sig.inspect_signature(pin)
        except SafetyError as error:
            if '0x80092013' in str(error) or '0x800b010e' in str(error):
                pytest.skip('Cached revocation evidence unavailable: '+str(error))
            raise
        assert evidence['authenticode_verified'] and len(evidence['signer_certificate_sha256']) == 64
        assert not evidence['installable']


def test_native_changed_signed_image_refused(tmp_path):
    path = Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
    if not path.exists(): pytest.skip('Platform compiler fixture absent')
    data = bytearray(path.read_bytes())
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    optional_size = struct.unpack_from('<H', data, pe+20)[0]
    first_section = pe+24+optional_size
    raw_offset = struct.unpack_from('<I', data, first_section+20)[0]
    data[raw_offset] ^= 1
    fixture = tmp_path/'changed.exe'; fixture.write_bytes(data)
    with PinnedFile(fixture) as pin:
        with pytest.raises(SafetyError, match='Offline Authenticode verification failed'):
            sig.inspect_signature(pin)


def test_catalog_digest_mismatch_never_reaches_provider(tmp_path):
    path = tmp_path/'fixture'; path.write_bytes(b'inert')
    with PinnedFile(path) as pin:
        pin.sha256 = '0'*64
        with pytest.raises(SafetyError, match='pinned catalog digest'): sig.inspect_signature(pin, api=Strict())


def test_post_verification_digest_failure_refuses_evidence(tmp_path):
    path = tmp_path/'fixture'; path.write_bytes(b'inert')
    with PinnedFile(path) as pin:
        api = Provider(pin); calls = []
        def changed_after_verify(value):
            calls.append(value)
            if len(calls) == 2: raise SafetyError('modeled input change')
            sig.check_digest(value)
        with pytest.raises(SafetyError, match='modeled input change'):
            sig.inspect_signature(pin, api=api, check=changed_after_verify)
        assert len(calls) == 2 and api.actions == [1, 2]


@pytest.mark.parametrize('kind',['exe','cat'])
@pytest.mark.parametrize('hold_signed',[True,False])
def test_native_file_trust_uses_handle_when_path_names_different_bytes(tmp_path,kind,hold_signed):
    if kind=='exe':signed=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
    else:
        candidates=list(Path('C:/Windows/System32/CatRoot').glob('*/Windows-ClientCore-Win32Bridge-Package*.cat'))
        if not candidates:pytest.skip('Platform signed catalog fixture absent')
        signed=candidates[0]
    if not signed.exists():pytest.skip('Platform signed fixture absent')
    unsigned=tmp_path/('unsigned.'+kind);unsigned.write_bytes(b'inert unsigned fixture')
    held,named=(signed,unsigned) if hold_signed else (unsigned,signed)
    native=sig.wintrust()
    class DifferentPath:
        def __getattr__(self,name):return getattr(native,name)
        def WinVerifyTrust(self,window,guid,pointer):
            data=C.cast(pointer,C.POINTER(sig.TrustData)).contents
            if data.action==1:data.file.contents.path=str(named)
            return native.WinVerifyTrust(window,guid,pointer)
    with PinnedFile(held) as pin:
        if hold_signed:
            try:evidence=sig.inspect_signature(pin,api=DifferentPath())
            except SafetyError as error:
                if '0x80092013' in str(error) or '0x800b010e' in str(error):
                    pytest.skip('Cached revocation evidence unavailable: '+str(error))
                raise
            assert evidence['file_sha256']==pin.sha256 and evidence['authenticode_verified']
            assert not evidence['release_authority_verified']
        else:
            with pytest.raises(SafetyError,match='Offline Authenticode verification failed'):
                sig.inspect_signature(pin,api=DifferentPath())
