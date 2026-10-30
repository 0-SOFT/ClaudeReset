"""Current-user CNG operations. Never accesses PCPKSP files or machine keys."""
from __future__ import annotations
import ctypes as C
from contextlib import contextmanager
from enum import StrEnum
import hashlib
import os
import re
import uuid
from .api import Library
from ..errors import SafetyError
from collections.abc import Iterator

__all__ = ['KEY_PATTERN', 'Provider', 'SelfTest', 'package_identity', 'selftest']


class SelfTest(StrEnum):
    """The native key self-test; a failure raises instead of returning a status."""
    PASSED = 'passed'


PLATFORM = 'Microsoft Platform Crypto Provider'
SILENT = 0x40
NOT_FOUND = frozenset({0x80090016, 0x80090011})
TEST_PREFIX = 'ClaudeReset-Test-'
KEY_PATTERN = re.compile(r'Claude-HwKey-device-registry-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?::g([1-9][0-9]*))?\Z')


def check(status: int) -> None:
    if status:
        raise SafetyError('CNG operation failed: 0x%08X' % (status & 0xffffffff))


def package_identity() -> str | None:
    if os.name != 'nt':
        raise SafetyError('Windows is required')
    fn = Library('kernel32').GetCurrentPackageFamilyName
    count = C.c_uint32()
    rc = fn(C.byref(count), None)
    if rc == 15700:
        return None
    if rc != 122 or not 1 <= count.value <= 256:
        raise SafetyError('Cannot establish native package identity')
    value = C.create_unicode_buffer(count.value)
    check(fn(C.byref(count), value))
    return value.value


class KeyName(C.Structure):
    _fields_ = [('name', C.c_wchar_p), ('algorithm', C.c_wchar_p),
                ('legacy_spec', C.c_uint32), ('flags', C.c_uint32)]


class Provider:
    def __init__(self) -> None:
        if os.name != 'nt':
            raise SafetyError('Windows CNG is required')
        self.dll = Library('ncrypt')
        self.handle = C.c_void_p()
        check(self.dll.NCryptOpenStorageProvider(C.byref(self.handle), PLATFORM, 0))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.handle:
            self.dll.NCryptFreeObject(self.handle)
            self.handle = C.c_void_p()

    @contextmanager
    def key(self, name: str) -> Iterator[C.c_void_p | None]:
        handle = C.c_void_p()
        status = self.dll.NCryptOpenKey(self.handle, C.byref(handle), name, 0, SILENT)
        if (status & 0xffffffff) in NOT_FOUND:
            yield None
            return
        check(status)
        try:
            yield handle
        finally:
            if handle.value:
                self.dll.NCryptFreeObject(handle)

    def names(self) -> list[tuple[str, str, int]]:
        state = C.c_void_p()
        result = []
        try:
            for _ in range(10000):
                pointer = C.c_void_p()
                rc = self.dll.NCryptEnumKeys(self.handle, None, C.byref(pointer), C.byref(state), SILENT)
                if rc & 0xffffffff == 0x8009002a:
                    return result
                check(rc)
                try:
                    item = C.cast(pointer, C.POINTER(KeyName)).contents
                    result.append((item.name, item.algorithm, item.flags))
                finally:
                    self.dll.NCryptFreeBuffer(pointer)
            raise SafetyError('CNG inventory limit exceeded')
        finally:
            if state:
                self.dll.NCryptFreeBuffer(state)

    def public_digest(self, name: str) -> str | None:
        with self.key(name) as key:
            if key is None:
                return None
            return self._public_digest(key)

    def _public_digest(self, key):
        length = C.c_uint32()
        check(self.dll.NCryptExportKey(key, None, 'ECCPUBLICBLOB', None, None, 0, C.byref(length), 0))
        if length.value != 72:
            raise SafetyError('Unsupported CNG public key size')
        blob = C.create_string_buffer(length.value)
        check(self.dll.NCryptExportKey(key, None, 'ECCPUBLICBLOB', None, blob, length.value, C.byref(length), 0))
        data = blob.raw
        if data[:8] != b'ECS1\x20\0\0\0':
            raise SafetyError('Unsupported CNG key algorithm')
        # DER SubjectPublicKeyInfo, id-ecPublicKey / prime256v1 / uncompressed point.
        spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004') + data[8:]
        return hashlib.sha256(spki).hexdigest()

    def delete_selected(self, name: str, expected_digest: str, *, test: bool=False) -> None:
        valid = re.fullmatch(TEST_PREFIX + r'[0-9a-f]{32}', name) if test else KEY_PATTERN.fullmatch(name)
        if not valid or not re.fullmatch(r'[0-9a-f]{64}', expected_digest or ''):
            raise SafetyError('CNG deletion requires an exact reviewed application key')
        with self.key(name) as key:
            if key is None or self._public_digest(key) != expected_digest:
                raise SafetyError('CNG public key changed or is absent')
            # Platform KSP rejects SILENT on DeleteKey (NTE_BAD_FLAGS). The
            # handle was opened silently; use the provider-supported zero flags.
            check(self.dll.NCryptDeleteKey(key, 0))
            key.value = None  # successful DeleteKey also frees the handle
        if self.public_digest(name) is not None:
            raise SafetyError('CNG deletion verification failed')

    def create_test(self, name: str) -> None:
        if not re.fullmatch(TEST_PREFIX + r'[0-9a-f]{32}', name):
            raise SafetyError('Only unique test keys can be created')
        key = C.c_void_p()
        check(self.dll.NCryptCreatePersistedKey(self.handle, C.byref(key), 'ECDSA_P256', name, 0, 0))
        try:
            check(self.dll.NCryptFinalizeKey(key, SILENT))
        finally:
            self.dll.NCryptFreeObject(key)


def selftest(expected_package: str | None=None) -> dict:
    """Real native create/open/delete/recreate using two exclusively owned keys."""
    if package_identity() != expected_package:
        raise SafetyError('Unexpected package identity; no test key created')
    names = [TEST_PREFIX + uuid.uuid4().hex for _ in range(2)]
    created = []
    with Provider() as provider:
        try:
            for name in names:
                provider.create_test(name)
                created.append(name)
            first, other = (provider.public_digest(n) for n in names)
            if not first or not other or first == other:
                raise SafetyError('Native test keys are invalid')
            provider.delete_selected(names[0], first, test=True)
            absent = provider.public_digest(names[0]) is None
            provider.create_test(names[0])
            changed = provider.public_digest(names[0]) != first
            preserved = provider.public_digest(names[1]) == other
            if not all((absent, changed, preserved)):
                raise SafetyError('Native key isolation test failed')
        finally:
            for name in created:
                digest = provider.public_digest(name)
                if digest:
                    provider.delete_selected(name, digest, test=True)
        return {'status': SelfTest.PASSED, 'package_context': bool(expected_package),
                'deleted_key_absent': absent, 'recreated_public_key_changed': changed,
                'other_test_key_preserved': preserved, 'test_keys_cleaned': True}
