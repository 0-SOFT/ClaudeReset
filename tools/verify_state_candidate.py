"""Synthetic DPAPI memory recovery from source and frozen candidate. No user archive access."""
import base64
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.core import Paths,recover_memory
from claude_reset.windows import DPAPI


def main(candidate=None):
    base=ROOT/'work/release-execution-2026-10-26'
    fixture=base/('state-fixture-'+uuid.uuid4().hex); fixture.mkdir()
    run=uuid.uuid4().hex; folder=fixture/'runs'/run;folder.mkdir(parents=True)
    memory=b'Synthetic memory\r\nUTF-8: \xd0\xbf\xd0\xb0\xd0\xbc\xd1\x8f\xd1\x82\xd1\x8c\n'
    payload={'schema':1,'files':[{'path':'CLAUDE.md','data':base64.b64encode(memory).decode(),'sha256':hashlib.sha256(memory).hexdigest()}]}
    encrypted=DPAPI().encrypt(json.dumps(payload).encode());(folder/'memory.dpapi').write_bytes(encrypted)
    paths=Paths(fixture/'home',fixture/'roaming',fixture/'local',fixture)
    source=recover_memory(paths,run)
    assert (source/'CLAUDE.md').read_bytes()==memory
    exe=candidate.resolve() if candidate else base/'candidate/dist/ClaudeResetCandidate.exe'
    p=subprocess.run([str(exe),'--state-root',str(fixture),'--recover',run],capture_output=True,timeout=40,creationflags=0x08000000)
    assert p.returncode==0, p.stderr.decode(errors='replace')
    exports=list((fixture/'recovered-memory').iterdir())
    assert len(exports)==2 and all((e/'CLAUDE.md').read_bytes()==memory for e in exports)
    assert (folder/'memory.dpapi').read_bytes()==encrypted
    reports=[]
    for argv in ([sys.executable,str(ROOT/'src/launcher.py')],[str(exe)]):
        result=subprocess.run([*argv,'--state-inspect'],capture_output=True,timeout=40,creationflags=0x08000000)
        assert result.returncode==0,result.stderr
        reports.append(json.loads(result.stdout))
    assert reports[0]==reports[1], 'Source/frozen state discovery differs'
    bad=subprocess.run([str(exe),'--state-root','relative','--recover',run],capture_output=True,timeout=40,creationflags=0x08000000)
    assert bad.returncode!=0
    report={'schema':1,'utc':datetime.now(timezone.utc).isoformat(),'passed':True,'source_and_frozen_dpapi_recovery':True,
            'memory_byte_identical':True,'same_state_discovery':True,'relative_path_rejected':True,
            'user_archives_read':False,'user_archives_moved':False,'client_network_opened':False,
            'candidate_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'fixture':str(fixture),
            'limits':['Actual independently launched MSIX process not exercised; this is source/frozen execution under the current session.']}
    (fixture/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--candidate',type=Path)
    main(parser.parse_args().candidate)
