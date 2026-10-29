"""Loopback-only Snow worker. DPAPI at rest, config via stdin, no network reconfiguration."""
from pathlib import Path
import ctypes, hashlib, ipaddress, json, msvcrt, os, socket, subprocess, sys, time, uuid
from ctypes import wintypes
BASE=Path(__file__).resolve().parent
sys.path.insert(0,r'__CLAUDE_RESET_SRC__')  # replaced at install time
from claude_reset.windows import DPAPI

def atomic(path,value):
    temp=path.with_suffix('.tmp')
    temp.write_text(json.dumps(value,indent=2),encoding='utf-8')
    os.replace(temp,path)

class BASIC(ctypes.Structure):
    _fields_=[('PerProcessUserTimeLimit',ctypes.c_longlong),('PerJobUserTimeLimit',ctypes.c_longlong),
              ('LimitFlags',wintypes.DWORD),('MinimumWorkingSetSize',ctypes.c_size_t),('MaximumWorkingSetSize',ctypes.c_size_t),
              ('ActiveProcessLimit',wintypes.DWORD),('Affinity',ctypes.c_size_t),('PriorityClass',wintypes.DWORD),('SchedulingClass',wintypes.DWORD)]
class IO(ctypes.Structure):
    _fields_=[(x,ctypes.c_ulonglong) for x in ['ReadOperationCount','WriteOperationCount','OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount']]
class EXTENDED(ctypes.Structure):
    _fields_=[('BasicLimitInformation',BASIC),('IoInfo',IO),('ProcessMemoryLimit',ctypes.c_size_t),('JobMemoryLimit',ctypes.c_size_t),('PeakProcessMemoryUsed',ctypes.c_size_t),('PeakJobMemoryUsed',ctypes.c_size_t)]

def stop_requested(path,instance):
    try:
        return json.loads(path.read_text('utf-8-sig'))=={'instance':instance}
    except (FileNotFoundError,UnicodeDecodeError,json.JSONDecodeError):
        # A partial write must not crash a functioning proxy; old PowerShell
        # also writes a UTF-8 BOM by default.
        return False

def main():
    lock=open(BASE/'worker.lock','a+b')
    lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:return 0
    instance=uuid.uuid4().hex
    status={'schema':1,'instance':instance,'worker_pid':os.getpid(),'state':'starting','router_changed':False}
    engine=None;job=None
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR];kernel.CreateJobObjectW.restype=wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    try:
        meta=json.loads((BASE/'profile.json').read_text('utf-8'))
        path=Path(meta['engine_path'])
        assert path.resolve().is_relative_to((BASE/'engine').resolve())
        assert hashlib.sha256(path.read_bytes()).hexdigest()==meta['engine_sha256']
        plain=DPAPI().decrypt((BASE/'snow-config.dpapi').read_bytes())
        assert hashlib.sha256(plain).hexdigest()==meta['config_sha256']
        cfg=json.loads(plain)
        assert len(cfg['outbounds'])==1 and cfg['outbounds'][0]['type']=='vless'
        # Servers this PC must never use (optional, local): forbidden-servers.json next to the worker, a JSON list.
        deny=BASE/'forbidden-servers.json'
        assert cfg['outbounds'][0]['server'] not in (json.loads(deny.read_text('utf-8')) if deny.is_file() else [])
        assert ipaddress.ip_address(cfg['outbounds'][0]['server']).is_global
        assert cfg['route']=={'final':'snow-only'}
        assert cfg['inbounds']==[{'type':'http','tag':'claude-loopback','listen':'127.0.0.1','listen_port':25080}]
        assert cfg['experimental']['clash_api']['external_controller']=='127.0.0.1:25081'
        assert cfg['experimental']['clash_api']['secret']
        assert cfg['log']=={'disabled':True}
        for port in (25080,25081):
            with socket.socket() as test:test.bind(('127.0.0.1',port))
        job=kernel.CreateJobObjectW(None,None)
        assert job
        limits=EXTENDED();limits.BasicLimitInformation.LimitFlags=0x2000
        assert kernel.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits))
        engine=subprocess.Popen([str(path),'run','-c','stdin'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000)
        assert kernel.AssignProcessToJobObject(job,wintypes.HANDLE(int(engine._handle)))
        engine.stdin.write(plain);engine.stdin.close();del plain,cfg
        for _ in range(60):
            assert engine.poll() is None
            try:
                with socket.create_connection(('127.0.0.1',25080),.2):break
            except OSError:time.sleep(.1)
        else:raise TimeoutError('listener')
        status.update(state='running',engine_pid=engine.pid,proxy_url=meta['proxy_url'],kill_on_worker_exit=True)
        atomic(BASE/'worker-status.json',status)
        requested_stop=False
        while engine.poll() is None:
            if stop_requested(BASE/'stop-request.json',instance):
                requested_stop=True
                break
            time.sleep(.5)
        if not requested_stop:
            raise RuntimeError('engine_exited_unexpectedly')
        status['state']='stopped'
    except Exception as exc:
        status.update(state='failed',error_type=type(exc).__name__)
    finally:
        if job:kernel.CloseHandle(job)
        if engine and engine.poll() is None:
            try:engine.wait(timeout=3)
            except subprocess.TimeoutExpired:engine.terminate();engine.wait(timeout=3)
        status['engine_closed']=engine is None or engine.poll() is not None
        atomic(BASE/'worker-status.json',status)
        lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()
    return 1 if status['state']=='failed' else 0

def supervise():
    # Task Scheduler retries did not fire for a demand-started task on this PC.
    # Recover engine failures locally; never relax WFP or change network routes.
    # A normal instance-specific stop and duplicate-lock exit remain final.
    for attempt in range(4):
        code=main()
        if code==0:return 0
        if attempt<3:time.sleep(2**attempt)
    return 1

if __name__=='__main__':sys.exit(supervise())
