"""Installed service controller. This generation never opens Claude clients."""
from contextlib import ExitStack
import ctypes as C
from ctypes import wintypes as W
import json
import os
import sys
import time
import uuid
from . import backend_boundary, backend_spec, exit_reachability, gateway_profile, service_store
from .backend_lifecycle import Generation
from .connections import measure
from .gateway_service import Gateway
from .safeio import SafetyError, atomic_bytes
from .service_identity import Process
from .strict_wfp import Engine
from .tcp_inventory import listeners
from .windows_job import OwnedJob
from .windows_pin import PinnedFile


class Platform:
    def __init__(self):
        self.stack = ExitStack(); self.lock = None; self.gateway = None
        self.root = service_store.program_files()/'ClaudeReset'
        self.paths = backend_boundary.layout(self.root)

    def prepare(self):
        if not getattr(sys, 'frozen', False) or os.path.normcase(sys.executable) != os.path.normcase(str(self.paths['runtime'])):
            raise SafetyError('Only the installed frozen runtime can start a backend generation')
        self.controller = self.stack.enter_context(Process(os.getpid(), image=self.paths['runtime'], service='ClaudeResetBackend'))
        directories = [self.root, *[self.root/name for name in ('Engine','Gateway','Runtime','Backend','RuntimeTemp')]]
        files = [self.paths[name] for name in ('engine','engine_config','gateway','runtime','backend','spec')]
        service_store.verify_paths([*directories,*files], directories)
        api = C.WinDLL('kernel32', use_last_error=True)
        api.CreateFileW.argtypes = [W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
        api.CreateFileW.restype = W.HANDLE
        api.CloseHandle.argtypes = [W.HANDLE]; api.CloseHandle.restype = W.BOOL
        self.lock_api = api
        self.lock = api.CreateFileW(str(self.root/'Backend/controller.lock'), 0xC0000000, 0, None, 4, 0x00200000, None)
        if self.lock in (None, C.c_void_p(-1).value):
            self.lock = None
            raise SafetyError('Another controller owns the backend generation')
        # The directory was protected before creating the exclusive lock. Check
        # an existing lock too; no ordinary principal may precreate it.
        service_store.verify_paths([self.root/'Backend/controller.lock'], [])
        spec_pin = self.stack.enter_context(PinnedFile(self.paths['spec'], limit=16384))
        self.spec = backend_spec.decode(spec_pin.data)
        if not exit_reachability.may_block(exit_reachability.probe_spec(self.spec)):
            raise SafetyError('Selected exit is not reachable; client admission stays closed')
        config_pin = self.stack.enter_context(PinnedFile(self.paths['engine_config'],
            expected_sha256=self.spec['engine_config_sha256'], limit=65536))
        self.protocol = backend_spec.bind_config(self.spec, config_pin.data)
        for name in ('engine','runtime','gateway'):
            self.stack.enter_context(PinnedFile(self.paths[name], expected_sha256=self.spec[name+'_sha256']))
        self.opened = backend_boundary.verify_installed(self.root, self.spec)
        self.gateway = Gateway(self.paths['gateway'])
        self.generation = uuid.uuid4().hex

    def suspended_engine(self):
        return OwnedJob(self.paths['engine'], ['run','-c',str(self.paths['engine_config'])], temp=self.paths['temp'])

    def acquire_lease(self):
        lease = Engine(dynamic=True)
        try:
            if any(lease.exists_verified(rule) for rule in self.opened):
                raise SafetyError('A previous service permit already occupies this endpoint slot')
            lease.install(self.opened)
            return lease
        except BaseException:
            lease.close(); raise

    def verify_boundary(self, lease):
        backend_boundary.verify_installed(self.root, self.spec, active_lease=True)
        if not all(lease.exists_verified(rule) for rule in self.opened):
            raise SafetyError('Runtime-owned service permissions disappeared')

    def start_gateway(self, child):
        deadline = time.monotonic() + 10
        while True:
            if not child.running(): raise SafetyError('Engine exited before binding its listener')
            rows = listeners([self.spec['backend_port']])
            if rows:
                if rows != [(self.spec['backend_port'],'127.0.0.1',child.pid)]:
                    raise SafetyError('Backend listener belongs to another process or address')
                break
            if time.monotonic() >= deadline: raise SafetyError('Backend listener readiness timed out')
            time.sleep(.05)
        profile = {'schema': 2, 'protocol': self.protocol,
            'backend_port': self.spec['backend_port'], 'listen_port': self.spec['gateway_port'],
            'engine_pid': child.pid, 'engine_start_utc_ticks': child.start_utc_ticks,
            'engine_path': str(self.paths['engine']), 'engine_sha256': self.spec['engine_sha256'],
            'engine_config_path': str(self.paths['engine_config']), 'engine_config_sha256': self.spec['engine_config_sha256'],
            'generation': self.generation, 'controller_pid': os.getpid(),
            'controller_start_utc_ticks': self.controller.start_utc_ticks,
            'controller_path': str(self.paths['runtime']), 'controller_sha256': self.spec['runtime_sha256']}
        atomic_bytes(self.paths['gateway_config'], gateway_profile.encode(profile), self.root)
        service_store.verify_paths([self.paths['gateway_config']], [])
        self.stack.enter_context(PinnedFile(self.paths['gateway_config'], limit=16384))
        return self.gateway.start()

    def verify_generation(self, child, gateway, lease):
        if not child.running() or not self.controller.running():
            raise SafetyError('Owned backend generation exited')
        gateway.verify()
        self.verify_boundary(lease)
        wanted = {(self.spec['backend_port'], '127.0.0.1', child.pid),
                  (self.spec['gateway_port'], '127.0.0.1', gateway.process.pid)}
        rows = listeners([self.spec['backend_port'],self.spec['gateway_port']])
        if len(rows) != 2 or set(rows) != wanted:
            raise SafetyError('Backend listener ownership differs')

    def probe(self):
        # The gateway front door is always HTTP CONNECT. Its profile protocol
        # selects only the gateway-to-engine handshake.
        result = measure('http://127.0.0.1:'+str(self.spec['gateway_port']))
        return result.get('status') == 'measured' and result.get('exit_ip') in self.spec['expected_exit_ips']

    def report(self, generation):
        atomic_bytes(self.root/'Backend/runtime-status.json', json.dumps(generation.status()).encode('ascii'), self.root)

    def close(self):
        try:
            if self.gateway: self.gateway.close()
        finally:
            try: self.stack.close()
            finally:
                if self.lock: self.lock_api.CloseHandle(self.lock); self.lock = None


def main():
    if sys.argv[1:] != ['--service']: return 2
    platform = Platform(); generation = Generation(platform)
    try:
        generation.start(); platform.report(generation)
        while True:
            time.sleep(2)
            generation.poll()
    except Exception:
        # Details may contain local paths; only a closed, redacted state is
        # written to the protected store. The service wrapper observes exit.
        try: generation.close()
        finally:
            if generation.prepared and getattr(platform, 'spec', None): platform.report(generation)
        return 1
