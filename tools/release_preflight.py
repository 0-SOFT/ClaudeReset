"""Read-only release prerequisites and protected Codex process inventory."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.windows import ps_json
from claude_reset import state_location


def main():
    result={'schema':1,'utc':datetime.now(timezone.utc).isoformat(),'read_only':True,'uac_requested':False}
    result['windows']=ps_json(r'''
    $all=@(Get-CimInstance Win32_Process);
    $keep=[Collections.Generic.HashSet[uint32]]::new();
    foreach($p in $all){if($p.Name -match '(?i)codex'){[void]$keep.Add([uint32]$p.ProcessId)}}
    do {$changed=$false; foreach($p in $all){if($keep.Contains([uint32]$p.ParentProcessId)){if($keep.Add([uint32]$p.ProcessId)){$changed=$true}}}} while($changed);
    [void]$keep.Add([uint32]$PID);
    do {$changed=$false; foreach($p in $all){if($keep.Contains([uint32]$p.ProcessId) -and $p.ParentProcessId -gt 0){if($keep.Add([uint32]$p.ParentProcessId)){$changed=$true}}}} while($changed);
    $protected=@($all | Where-Object {$keep.Contains([uint32]$_.ProcessId)} | ForEach-Object {@{pid=$_.ProcessId;parent_pid=$_.ParentProcessId;name=$_.Name;image=$_.ExecutablePath;created=if($_.CreationDate){$_.CreationDate.ToString('O')}else{$null}}});
    $tools=@{};foreach($name in @('cl.exe','MSBuild.exe','signtool.exe','Inf2Cat.exe')){$tool=Get-Command $name -ErrorAction SilentlyContinue;$tools[$name]=[bool]$tool};
    $certs=@();foreach($store in @('Cert:/CurrentUser/My','Cert:/LocalMachine/My')){$certs+=@(Get-ChildItem $store | Where-Object {$_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and $_.NotBefore -lt (Get-Date) -and ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3')})};
    @{os_build=[Environment]::OSVersion.Version.ToString(); elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); protected_processes=$protected; protected_services=@(Get-CimInstance Win32_Service | Where-Object {$_.Name -match 'Codex'} | Select-Object Name,State,ProcessId,PathName); tools_in_path=$tools; valid_local_code_signing_keys=$certs.Count} | ConvertTo-Json -Depth 6 -Compress
    ''')
    result['disk_free_bytes']=shutil.disk_usage(ROOT).free
    local=state_location.physical_local_appdata()
    result['state']=state_location.inspect(Path.home(),local,Path(os.environ['LOCALAPPDATA']))
    broker=ROOT/'work/admin-broker/v0.1.0/ClaudeResetAdminClient.exe'
    for operation in ('status','services','hcs'):
        p=subprocess.run([str(broker),'--client',operation],capture_output=True,timeout=35,creationflags=0x08000000)
        result['admin_'+operation]=json.loads(p.stdout) if p.returncode==0 else {'verified':False,'returncode':p.returncode}
    result['external_conditions']={
        'driver_signing':{'available':False,'required':'Trusted Windows-compatible signed final driver package; no security-policy downgrade.'},
        'second_windows_host':{'available':False,'required':'Independent authorized Windows 11 x64 environment; no endpoint supplied.'},
        'production_installation':{'available':False,'required':'Reviewed installer and broker version with exact installation operations, followed by owner-approved UAC.'},
    }
    result['protected_files']=[str(ROOT/'work'),str(Path.home()/'.codex'),str(local/'Packages/OpenAI.Codex_2p2nqsd0c76g0')]
    destination=ROOT/'work/release-execution-2026-10-26';destination.mkdir(exist_ok=True)
    (destination/'preflight.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'evidence':str(destination/'preflight.json'),'protected_processes':len(result['windows']['protected_processes']),
                      'admin_ready':result['admin_status'].get('ok',False),'local_signing_keys':result['windows']['valid_local_code_signing_keys'],
                      'state_selection_required':result['state']['selection_required']}))


if __name__=='__main__':main()
