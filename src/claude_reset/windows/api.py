"""Windows DLLs and the prototype of every function the program calls on them, each declared once, here.

`Library(name)` loads a DLL the way ctypes.WinDLL does, one loaded copy per caller, and hands out its functions
with the prototype declared below. A function that is not declared cannot be read: a new call starts by declaring
its prototype here. Last-error values are kept for ctypes.get_last_error().

Functions whose prototypes use a module's own structures are declared in that module's PROTOTYPES, which it passes
to Library: fwpuclnt in wfp_session, CryptProtectData in system, the catalog functions of crypt32 in catalog,
wintrust in authenticode. Every function is declared in exactly one table (tests/test_windows_api.py).
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
from types import MappingProxyType

__all__ = ['PROTOTYPES', 'Library', 'ProcessInfo', 'Startup']


class Startup(C.Structure):
    """STARTUPINFOW."""
    _fields_ = [('cb', W.DWORD), ('reserved', W.LPWSTR), ('desktop', W.LPWSTR), ('title', W.LPWSTR),
                *[(name, W.DWORD) for name in ('x','y','xsize','ysize','xchars','ychars','fill','flags')],
                ('show', W.WORD), ('reserved_size', W.WORD), ('reserved_ptr', C.c_void_p),
                ('stdin', W.HANDLE), ('stdout', W.HANDLE), ('stderr', W.HANDLE)]


class ProcessInfo(C.Structure):
    """PROCESS_INFORMATION."""
    _fields_ = [('process', W.HANDLE), ('thread', W.HANDLE), ('pid', W.DWORD), ('tid', W.DWORD)]


PVOID, PDWORD, TIMES = C.c_void_p, C.POINTER(W.DWORD), [C.POINTER(C.c_uint64)] * 4

# DLL -> function -> (result type, argument types).
PROTOTYPES = MappingProxyType({
    'kernel32': MappingProxyType({
        'AssignProcessToJobObject': (W.BOOL, [W.HANDLE, W.HANDLE]),
        'CloseHandle': (W.BOOL, [W.HANDLE]),
        'CreateFileW': (W.HANDLE, [W.LPCWSTR, W.DWORD, W.DWORD, PVOID, W.DWORD, W.DWORD, W.HANDLE]),
        'CreateJobObjectW': (W.HANDLE, [PVOID, W.LPCWSTR]),
        'CreateMutexW': (PVOID, [PVOID, C.c_int, C.c_wchar_p]),
        'CreateProcessW': (W.BOOL, [W.LPCWSTR, W.LPWSTR, PVOID, PVOID, W.BOOL, W.DWORD, PVOID, W.LPCWSTR,
                                    C.POINTER(Startup), C.POINTER(ProcessInfo)]),
        'GetCurrentPackageFamilyName': (C.c_long, [C.POINTER(C.c_uint32), C.c_wchar_p]),
        'GetDriveTypeW': (C.c_uint, [C.c_wchar_p]),
        'GetFileSizeEx': (W.BOOL, [W.HANDLE, C.POINTER(C.c_int64)]),
        'GetFinalPathNameByHandleW': (W.DWORD, [W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD]),
        'GetPackageFamilyName': (C.c_long, [W.HANDLE, C.POINTER(W.UINT), W.LPWSTR]),
        'GetProcessTimes': (W.BOOL, [W.HANDLE, *TIMES]),
        'LocalFree': (PVOID, [PVOID]),
        'OpenProcess': (W.HANDLE, [W.DWORD, W.BOOL, W.DWORD]),
        'QueryDosDeviceW': (W.DWORD, [W.LPCWSTR, W.LPWSTR, W.DWORD]),
        'QueryFullProcessImageNameW': (W.BOOL, [W.HANDLE, W.DWORD, W.LPWSTR, PDWORD]),
        'ReadFile': (W.BOOL, [W.HANDLE, PVOID, W.DWORD, PDWORD, PVOID]),
        'ReleaseMutex': (W.BOOL, [W.HANDLE]),
        'ResumeThread': (W.DWORD, [W.HANDLE]),
        'SetFilePointerEx': (W.BOOL, [W.HANDLE, C.c_int64, C.POINTER(C.c_int64), W.DWORD]),
        'SetInformationJobObject': (W.BOOL, [W.HANDLE, C.c_int, PVOID, W.DWORD]),
        'TerminateProcess': (W.BOOL, [W.HANDLE, W.UINT]),
        'WaitForSingleObject': (W.DWORD, [W.HANDLE, W.DWORD]),
    }),
    'advapi32': MappingProxyType({
        'CloseServiceHandle': (W.BOOL, [W.HANDLE]),
        'ConvertSidToStringSidW': (W.BOOL, [PVOID, C.POINTER(W.LPWSTR)]),
        'ConvertStringSecurityDescriptorToSecurityDescriptorW': (W.BOOL,
                                                                 [W.LPCWSTR, W.DWORD, C.POINTER(PVOID), PDWORD]),
        'FreeSid': (PVOID, [PVOID]),
        'GetAce': (W.BOOL, [PVOID, W.DWORD, C.POINTER(PVOID)]),
        'GetLengthSid': (W.DWORD, [PVOID]),
        'GetSecurityDescriptorControl': (W.BOOL, [PVOID, C.POINTER(C.c_uint16), PDWORD]),
        'GetSecurityDescriptorDacl': (W.BOOL, [PVOID, C.POINTER(W.BOOL), C.POINTER(PVOID), C.POINTER(W.BOOL)]),
        'GetSecurityDescriptorOwner': (W.BOOL, [PVOID, C.POINTER(PVOID), C.POINTER(W.BOOL)]),
        'GetTokenInformation': (W.BOOL, [W.HANDLE, C.c_int, PVOID, W.DWORD, PDWORD]),
        'IsValidSid': (W.BOOL, [PVOID]),
        'LookupAccountNameW': (W.BOOL, [W.LPCWSTR, W.LPCWSTR, PVOID, PDWORD, W.LPWSTR, PDWORD, PDWORD]),
        'OpenProcessToken': (W.BOOL, [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]),
        'OpenSCManagerW': (W.HANDLE, [W.LPCWSTR, W.LPCWSTR, W.DWORD]),
        'OpenServiceW': (W.HANDLE, [W.HANDLE, W.LPCWSTR, W.DWORD]),
        'QueryServiceConfig2W': (W.BOOL, [W.HANDLE, W.DWORD, PVOID, W.DWORD, PDWORD]),
        'QueryServiceConfigW': (W.BOOL, [W.HANDLE, PVOID, W.DWORD, PDWORD]),
        'QueryServiceObjectSecurity': (W.BOOL, [W.HANDLE, W.DWORD, PVOID, W.DWORD, PDWORD]),
        'QueryServiceStatusEx': (W.BOOL, [W.HANDLE, C.c_int, PVOID, W.DWORD, PDWORD]),
        'RegCloseKey': (W.LONG, [W.HANDLE]),
        'RegOpenKeyExW': (W.LONG, [W.HANDLE, W.LPCWSTR, W.DWORD, W.DWORD, C.POINTER(W.HANDLE)]),
        'StartServiceW': (W.BOOL, [W.HANDLE, W.DWORD, PVOID]),
    }),
    'iphlpapi': MappingProxyType({
        'GetExtendedTcpTable': (W.DWORD, [PVOID, PDWORD, W.BOOL, W.ULONG, C.c_int, W.ULONG]),
    }),
    'ncrypt': MappingProxyType({
        'NCryptCreatePersistedKey': (C.c_long, [PVOID, C.POINTER(PVOID), C.c_wchar_p, C.c_wchar_p, C.c_uint32,
                                                C.c_uint32]),
        'NCryptDeleteKey': (C.c_long, [PVOID, C.c_uint32]),
        'NCryptEnumKeys': (C.c_long, [PVOID, C.c_wchar_p, C.POINTER(PVOID), C.POINTER(PVOID), C.c_uint32]),
        'NCryptExportKey': (C.c_long, [PVOID, PVOID, C.c_wchar_p, PVOID, PVOID, C.c_uint32, C.POINTER(C.c_uint32),
                                       C.c_uint32]),
        'NCryptFinalizeKey': (C.c_long, [PVOID, C.c_uint32]),
        'NCryptFreeBuffer': (C.c_long, [PVOID]),
        'NCryptFreeObject': (C.c_long, [PVOID]),
        'NCryptOpenKey': (C.c_long, [PVOID, C.POINTER(PVOID), C.c_wchar_p, C.c_uint32, C.c_uint32]),
        'NCryptOpenStorageProvider': (C.c_long, [C.POINTER(PVOID), C.c_wchar_p, C.c_uint32]),
    }),
    'ole32': MappingProxyType({
        'CoTaskMemFree': (None, [PVOID]),
    }),
    'shell32': MappingProxyType({
        'CommandLineToArgvW': (C.POINTER(W.LPWSTR), [W.LPCWSTR, C.POINTER(C.c_int)]),
        'SHGetFolderPathW': (C.c_long, [W.HWND, C.c_int, W.HANDLE, W.DWORD, W.LPWSTR]),
        'SHGetKnownFolderPath': (C.c_long, [PVOID, C.c_uint32, PVOID, C.POINTER(PVOID)]),
        'ShellExecuteW': (PVOID, [PVOID, C.c_wchar_p, C.c_wchar_p, C.c_wchar_p, C.c_wchar_p, C.c_int]),
    }),
    'userenv': MappingProxyType({
        'DeriveAppContainerSidFromAppContainerName': (C.c_long, [W.LPCWSTR, C.POINTER(PVOID)]),
    }),
})


class Library:
    """One loaded copy of a DLL; each function read from it carries its declared prototype."""

    def __init__(self, name: str, prototypes: MappingProxyType = PROTOTYPES) -> None:
        self.name = name
        self.prototypes = prototypes[name]
        self.dll = C.WinDLL(name, use_last_error=True)

    def __getattr__(self, function: str):
        if function not in self.prototypes:
            raise AttributeError(f'{self.name}.{function} has no declared prototype (windows/api.py)')
        bound = getattr(self.dll, function)
        bound.restype, bound.argtypes = self.prototypes[function]
        setattr(self, function, bound)   # later reads skip this lookup
        return bound
