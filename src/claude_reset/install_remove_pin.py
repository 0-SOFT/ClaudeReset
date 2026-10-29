"""Installer-only mutation handle; separate from read-only runtime file pins."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
from pathlib import Path
from .gateway_profile import local_path
from .safeio import SafetyError,guarded,local_volume
from .install_receipts import identity


class RemovalPin:
    def __init__(self,path):
        self.handle=None;self.path=Path(local_path(str(path)))
        guarded(local_volume(self.path),self.path.parent)
        self.api=C.WinDLL('kernel32',use_last_error=True)
        for name,args,result in [
            ('CreateFileW',[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE],W.HANDLE),
            ('GetFinalPathNameByHandleW',[W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD],W.DWORD),
            ('GetFileSizeEx',[W.HANDLE,C.POINTER(C.c_int64)],W.BOOL),
            ('ReadFile',[W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p],W.BOOL),
            ('CloseHandle',[W.HANDLE],W.BOOL),
        ]:
            fn=getattr(self.api,name);fn.argtypes,fn.restype=args,result
        try:
            # READ|DELETE, share READ only, OPEN_EXISTING|OPEN_REPARSE_POINT.
            # No DELETE_ON_CLOSE: an exception during verification preserves it.
            self.handle=self.api.CreateFileW(str(self.path),0x80010000,1,None,3,0x00200000,None)
            if self.handle in (None,C.c_void_p(-1).value):
                self.handle=None;raise SafetyError('Cannot hold staged file for recovery')
            identity(self.api,self.handle)
            final=C.create_unicode_buffer(32768)
            count=self.api.GetFinalPathNameByHandleW(self.handle,final,len(final),0)
            if not 0<count<len(final) or final.value.casefold()!=('\\\\?\\'+str(self.path)).casefold():
                raise SafetyError('Recovery path changed')
            size=C.c_int64()
            if not self.api.GetFileSizeEx(self.handle,C.byref(size)) or not 0<=size.value<=268435456:
                raise SafetyError('Recovery file exceeds the payload limit')
            digest=hashlib.sha256();total=0;buffer=C.create_string_buffer(65536)
            while True:
                read=W.DWORD()
                if not self.api.ReadFile(self.handle,buffer,len(buffer),C.byref(read),None):
                    raise SafetyError('Cannot read recovery file')
                if not read.value:break
                total+=read.value
                if total>size.value:raise SafetyError('Recovery file size changed')
                digest.update(buffer.raw[:read.value])
            if total!=size.value:raise SafetyError('Incomplete recovery read')
            self.sha256=digest.hexdigest()
        except BaseException:self.close();raise

    def close(self):
        if self.handle:self.api.CloseHandle(self.handle);self.handle=None
