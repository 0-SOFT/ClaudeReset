using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

static class AdminBrokerTests {
    static int checks;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static void Reject(Action action,string message){bool rejected=false;try{action();}catch(Exception){rejected=true;}Check(rejected,message);}
    static string sid=WindowsIdentity.GetCurrent().User.Value;
    static int session=Process.GetCurrentProcess().SessionId;
    static void Protocol() {
        string token=Guid.NewGuid().ToString("N"),id=Guid.NewGuid().ToString("N");
        foreach(string op in AdminPolicy.Operations)Check(AdminPolicy.Parse(token+"|"+id+"|"+op,token)[2]==op,"allow exact operation");
        foreach(string op in new[]{"exec","powershell","cmd","start-service","install-driver","open-network","register-fixture --path x","status\r","STATUS","status|extra","../stop",""})Reject(()=>AdminPolicy.Parse(token+"|"+id+"|"+op,token),"reject arbitrary operation");
        foreach(string text in new[]{null,"",new string('a',111),Guid.NewGuid().ToString("N")+"|"+id+"|status",token+"|bad|status",token+"|"+id+"|status\0",token+"|"+id+"|stаtus"})Reject(()=>AdminPolicy.Parse(text,token),"reject malformed frame");
        Check(AdminPolicy.Hash(AdminFiles.Gateway())==AdminBuild.GatewayHash,"embedded payload hash");
        DirectorySecurity acl=AdminFiles.Security(sid);Check(acl.AreAccessRulesProtected,"protected ACL");Check(acl.GetOwner(typeof(SecurityIdentifier)).Value=="S-1-5-32-544","administrator owner");
        AdminFiles.Validate(acl,true);Check(true,"valid directory ACL");AdminFiles.Validate(AdminFiles.FileSecurity(),false);Check(true,"initial file ACL");
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) if(rule.IdentityReference.Value==sid)Check((rule.FileSystemRights&(FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership))==0,"reader cannot mutate privileged files");
        foreach(FileSystemRights rights in new[]{FileSystemRights.WriteData,FileSystemRights.AppendData,FileSystemRights.Delete,FileSystemRights.DeleteSubdirectoriesAndFiles,FileSystemRights.ChangePermissions,FileSystemRights.TakeOwnership}) {
            DirectorySecurity bad=AdminFiles.Security(sid);bad.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),rights,AccessControlType.Allow));Reject(()=>AdminFiles.Validate(bad,true),"dangerous ACL grant");
        }
        DirectorySecurity wrongOwner=AdminFiles.Security(sid);wrongOwner.SetOwner(new SecurityIdentifier(sid));Reject(()=>AdminFiles.Validate(wrongOwner,true),"ordinary owner has implicit WRITE_DAC");
        DirectorySecurity inherited=AdminFiles.Security(sid);inherited.SetAccessRuleProtection(false,true);Reject(()=>AdminFiles.Validate(inherited,true),"inherited directory ACL refused");
        string directory=Path.Combine(Path.GetTempPath(),"cr-admin-acl-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
        try{Reject(()=>AdminFiles.Check(directory,true),"ordinary user directory refused");}finally{Directory.Delete(directory);}
        Reject(()=>ClaudeResetAdminBroker.Dispatch("exec"),"dispatcher unknown action");
        Check(!AdminPolicy.Administrator(),"harness runs without elevation");
        Reject(()=>ClaudeResetAdminBroker.Serve(),"production server refuses unelevated process");
    }
    static void PipeRoundtrip() {
        string name="ClaudeReset.Admin.Test."+Guid.NewGuid().ToString("N");
        using(NamedPipeServerStream server=AdminTransport.Create(name,sid)) {
            Reject(()=>{using(var duplicate=AdminTransport.Create(name,sid)){}},"first pipe instance protected");
            Task worker=Task.Run(()=>{
                server.WaitForConnection();Check(AdminTransport.Authenticate(server,sid,session)==Process.GetCurrentProcess().Id,"OS peer PID and SID");
                Reject(()=>AdminTransport.Authenticate(server,"S-1-5-18",session),"wrong SID");
                Reject(()=>AdminTransport.Authenticate(server,sid,session+1),"wrong Windows session");
                Check(AdminTransport.Read(server,4000,110)=="status","real pipe read");AdminTransport.Write(server,"{\"ok\":true}",4000);
            });
            using(NamedPipeClientStream client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification)) {
                client.Connect(4000);uint pid;Check(AdminTransport.GetNamedPipeServerProcessId(client.SafePipeHandle,out pid)&&pid==Process.GetCurrentProcess().Id,"server PID");
                AdminTransport.Write(client,"status",4000);Check(AdminTransport.Read(client,4000,1024)=="{\"ok\":true}","real response");worker.GetAwaiter().GetResult();
            }
        }
    }
    static void PipeBadInput(bool stall) {
        string name="ClaudeReset.Admin.Test."+Guid.NewGuid().ToString("N");
        using(NamedPipeServerStream server=AdminTransport.Create(name,sid)) {
            Task worker=Task.Run(()=>{server.WaitForConnection();Reject(()=>AdminTransport.Read(server,300,110),stall?"slow peer deadline":"oversized peer request");});
            using(NamedPipeClientStream client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification)) {
                client.Connect(4000);if(!stall)AdminTransport.Write(client,new string('x',112),4000);worker.GetAwaiter().GetResult();
            }
        }
    }
    static int DisconnectServer(string name,string mode,int size) {
        using(var server=AdminTransport.Create(name,sid)) {
            Console.WriteLine("ready");Console.Out.Flush();server.WaitForConnection();
            if(AdminTransport.Read(server,4000,110)!="status")throw new InvalidDataException();
            byte[] bytes=Encoding.UTF8.GetBytes(new string('x',size)+(mode=="truncated"?"":mode=="multiple"?"\nextra\n":"\n"));
            if(mode=="invalid-utf8")bytes=new byte[]{0xff,10};
            if(mode=="stall")Thread.Sleep(500);
            else {var write=server.BeginWrite(bytes,0,bytes.Length,null,null);server.EndWrite(write);}
            server.Disconnect();
        }
        return 0;
    }
    static void DisconnectRoundtrip(string mode,int size) {
        string name="ClaudeReset.Admin.Test."+Guid.NewGuid().ToString("N");
        var start=new ProcessStartInfo(AdminPolicy.Image,"--disconnect-server "+name+" "+mode+" "+size) {
            UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var child=Process.Start(start)) {
            try {
                Task<string> ready=child.StandardOutput.ReadLineAsync();
                if(!ready.Wait(4000) || ready.Result!="ready")throw new Exception("Child server not ready");
                using(var client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification)) {
                    client.Connect(4000);
                    if(mode=="legacy") {
                        // A pending one-byte read survives disconnect; all unread
                        // bytes are discarded, reproducing the original defect.
                        byte[] first=new byte[1];var pending=client.BeginRead(first,0,1,null,null);
                        AdminTransport.Write(client,"status",4000);
                        Check(client.EndRead(pending)==1,"legacy reader gets only the first byte");
                        if(!child.WaitForExit(4000))throw new Exception("Child server deadline");
                        Reject(()=>AdminTransport.Read(client,1000,1048576),"legacy byte reader loses response after disconnect");
                    } else if(mode=="good") {
                        Check(AdminTransport.Exchange(client,"status",4000,1048576)==new string('x',size),"cross-process immediate disconnect, bytes="+size);
                    } else {
                        Reject(()=>AdminTransport.Exchange(client,"status",mode=="stall"?150:4000,1048576),"reject "+mode);
                    }
                }
                if(!child.WaitForExit(4000))throw new Exception("Child server deadline");
                Check(child.ExitCode==0,"child server completed: "+child.StandardError.ReadToEnd());
            } finally {if(!child.HasExited){child.Kill();child.WaitForExit(4000);}}
        }
    }
    static int Main(string[] args){try{
        if(args.Length==4 && args[0]=="--disconnect-server")return DisconnectServer(args[1],args[2],int.Parse(args[3]));
        Protocol();PipeRoundtrip();PipeBadInput(false);PipeBadInput(true);
        DisconnectRoundtrip("legacy",4096);
        foreach(int size in new[]{0,1,512,4095,4096,4097,65536,1048576})DisconnectRoundtrip("good",size);
        foreach(string mode in new[]{"truncated","multiple","invalid-utf8","stall"})DisconnectRoundtrip(mode,512);
        Console.WriteLine(AdminPolicy.Json(new{passed=true,checks=checks,real_local_pipe_test=true,separate_process_disconnect_test=true,legacy_loss_reproduced=true,admin_mutations_executed=false,production_broker_started=false,uac_requested=false}));return 0;
    }catch(Exception e){Console.Error.WriteLine(e);return 1;}}
}
