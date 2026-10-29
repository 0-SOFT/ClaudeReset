"""Compile and exercise actual native transport with local peers, no elevation."""
import json
import os
from pathlib import Path
import subprocess
import pytest


@pytest.mark.skipif(os.name != 'nt', reason='Native Windows gateway')
def test_native_gateway_protocols_with_local_receivers(tmp_path):
    compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    if not compiler.is_file():pytest.skip('Framework C# compiler unavailable')
    source=Path(__file__).resolve().parents[1]/'native/ClaudeResetGateway.cs'
    harness=Path(__file__).parent/'native/GatewayFunctionalTests.cs'
    exe=tmp_path/'GatewayFunctionalTests.exe'
    build=subprocess.run([str(compiler),'/nologo','/target:exe','/main:GatewayFunctionalTests',
        '/r:System.ServiceProcess.dll','/r:System.Web.Extensions.dll','/out:'+str(exe),str(source),str(harness)],
        capture_output=True,timeout=30,creationflags=0x08000000)
    assert build.returncode==0,build.stdout.decode(errors='replace')+build.stderr.decode(errors='replace')
    run=subprocess.run([str(exe),str(os.getpid())],capture_output=True,timeout=60,creationflags=0x08000000)
    assert run.returncode==0,run.stdout.decode(errors='replace')+run.stderr.decode(errors='replace')
    report=json.loads(run.stdout)
    assert report['passed'] and len(report['checks'])==20
    assert report['external_requests']==0 and not report['service_installed']
