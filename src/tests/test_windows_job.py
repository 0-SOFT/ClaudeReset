import json
import os
from pathlib import Path
import subprocess
import time
import pytest
from claude_reset.windows_job import OwnedJob
from claude_reset.safeio import SafetyError


@pytest.fixture
def fixture(tmp_path):
    source = tmp_path / 'JobFixture.cs'
    source.write_text('''using System;using System.IO;using System.Threading;
class JobFixture {static void Main(string[] args){
File.WriteAllText(args[0],Environment.GetEnvironmentVariable("CLAUDERESET_POISON")??"clean");
Thread.Sleep(60000);}}''')
    executable = tmp_path / 'ClaudeResetJobFixture.exe'
    compiler = Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    result = subprocess.run([str(compiler),'/nologo','/out:'+str(executable),str(source)],capture_output=True,timeout=30,creationflags=0x08000000)
    assert result.returncode == 0, result.stdout
    return executable


def test_child_cannot_execute_before_job_assignment_and_environment_is_clean(tmp_path,fixture,monkeypatch):
    marker = tmp_path/'started.txt';monkeypatch.setenv('CLAUDERESET_POISON','inherited-secret')
    job = OwnedJob(fixture,[str(marker)],temp=tmp_path)
    try:
        assert job.running() and job.start_utc_ticks>0 and not marker.exists()
        job.resume()
        deadline=time.monotonic()+5
        while not marker.exists() and time.monotonic()<deadline: time.sleep(.01)
        assert marker.read_text()=='clean'
        with pytest.raises(SafetyError): job.resume()
    finally: job.close()
    assert job.exit_confirmed and not job.running()
    job.close()


def test_closing_before_resume_never_executes_child(tmp_path,fixture):
    marker=tmp_path/'never-started.txt'
    with OwnedJob(fixture,[str(marker)],temp=tmp_path) as job:
        assert job.running()
    assert job.exit_confirmed and not marker.exists()
