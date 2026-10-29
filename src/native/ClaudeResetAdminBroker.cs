// A finite, local maintenance broker. No shell/eval/script/upload endpoint.
// Production isolation and signed-driver installation are deliberately unavailable.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using TimeoutException = System.TimeoutException;

static class AdminPolicy {
    internal static readonly string[] Operations = {"status", "services", "hcs", "wfp", "stage-fixture", "register-fixture", "remove-fixture", "stop"};
    internal const string Fixture = "ClaudeResetGatewayFixture";
    internal static bool IsId(string value) { return value != null && Regex.IsMatch(value, @"\A[0-9a-f]{32}\z"); }
    internal static string[] Parse(string text, string session) {
        if (text == null || text.Length > 110 || text.Any(c => c < 33 || c > 126)) throw new InvalidDataException("Invalid frame");
        string[] p = text.Split('|');
        if (p.Length != 3 || p[0] != session || !IsId(p[0]) || !IsId(p[1]) || !Operations.Contains(p[2])) throw new InvalidDataException("Rejected request");
        return p;
    }
    internal static bool Administrator() { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
    internal static string Hash(byte[] bytes) { using (SHA256 h=SHA256.Create()) return BitConverter.ToString(h.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }
    internal static string Image { get { return Assembly.GetExecutingAssembly().Location; } }
    internal static string ImageHash { get { return Hash(File.ReadAllBytes(Image)); } }
    internal static string Root { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClaudeResetAdmin"); } }
    internal static string FixtureRoot { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Fixture); } }
    internal static string Json(object o) { return new JavaScriptSerializer { MaxJsonLength=1048576 }.Serialize(o); }
    internal static Dictionary<string,object> Object(string json) { return new JavaScriptSerializer { MaxJsonLength=1048576 }.Deserialize<Dictionary<string,object>>(json); }
    internal static string Error(Exception e) { return e is Win32Exception ? "win32_"+((Win32Exception)e).NativeErrorCode : e.GetType().Name; }
}

static class AdminFiles {
    internal static readonly SecurityIdentifier SystemSid = new SecurityIdentifier("S-1-5-18");
    internal static readonly SecurityIdentifier AdminSid = new SecurityIdentifier("S-1-5-32-544");
    internal static DirectorySecurity Security(string reader) {
        DirectorySecurity acl=new DirectorySecurity(); acl.SetOwner(AdminSid); acl.SetAccessRuleProtection(true,false);
        foreach(SecurityIdentifier sid in new[]{SystemSid,AdminSid}) acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(reader),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        return acl;
    }
    internal static void NoReparse(string path) {
        string current=Path.GetFullPath(path);
        while(current!=null) {
            if((File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0) throw new InvalidDataException("Reparse point");
            current=Path.GetDirectoryName(current);
        }
    }
    internal static void Check(string path, bool directory) {
        NoReparse(path);
        FileSystemSecurity acl=directory ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
        Validate(acl,directory);
    }
    internal static void Validate(FileSystemSecurity acl,bool directory) {
        string owner=acl.GetOwner(typeof(SecurityIdentifier)).Value;
        if(owner!=SystemSid.Value && owner!=AdminSid.Value) throw new UnauthorizedAccessException("Untrusted owner");
        if(directory && !acl.AreAccessRulesProtected) throw new UnauthorizedAccessException("Inherited directory ACL");
        const int write=2|4|16|64|256|65536|262144|524288|0x10000000|0x40000000;
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
            string sid=rule.IdentityReference.Value;
            if(rule.AccessControlType==AccessControlType.Allow && ((int)rule.FileSystemRights&write)!=0 && sid!=SystemSid.Value && sid!=AdminSid.Value) throw new UnauthorizedAccessException("Untrusted writer");
        }
    }
    internal static void DirectoryOwned(string path) {
        string parent=Path.GetDirectoryName(path); NoReparse(parent);
        if(!Directory.Exists(path)) Directory.CreateDirectory(path,Security(AdminBuild.OwnerSid));
        Check(path,true);
    }
    internal static void NewFile(string path, byte[] data) {
        Check(Path.GetDirectoryName(path),true);
        FileSecurity acl=FileSecurity();
        using(FileStream f=new FileStream(path,FileMode.CreateNew,FileSystemRights.Write,FileShare.Read,4096,FileOptions.None,acl)) { f.Write(data,0,data.Length); f.Flush(true); }
        Check(path,false);
    }
    internal static FileSecurity FileSecurity() {
        FileSecurity acl=new FileSecurity();acl.SetOwner(AdminSid);acl.SetAccessRuleProtection(true,false);
        foreach(SecurityIdentifier sid in new[]{SystemSid,AdminSid})acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(AdminBuild.OwnerSid),FileSystemRights.ReadAndExecute,AccessControlType.Allow));
        return acl;
    }
    internal static void AtomicJson(string path, object data) {
        Check(Path.GetDirectoryName(path),true); string tmp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        NewFile(tmp,new UTF8Encoding(false).GetBytes(AdminPolicy.Json(data)));
        if(File.Exists(path)) { Check(path,false); File.Replace(tmp,path,null); } else File.Move(tmp,path);
    }
    internal static byte[] Gateway() {
        using(Stream s=Assembly.GetExecutingAssembly().GetManifestResourceStream("GatewayFixture")) {
            if(s==null || s.Length>2097152) throw new InvalidDataException("Embedded payload missing");
            using(MemoryStream m=new MemoryStream()) {s.CopyTo(m); byte[] bytes=m.ToArray(); if(AdminPolicy.Hash(bytes)!=AdminBuild.GatewayHash) throw new InvalidDataException("Embedded payload changed");return bytes;}
        }
    }
    internal static void Stage() {
        DirectoryOwned(AdminPolicy.FixtureRoot);
        string exe=Path.Combine(AdminPolicy.FixtureRoot,"ClaudeResetGateway.exe");
        // A pre-existing configuration could activate a stale backend if somebody
        // starts the service outside this broker. Never stage over such a tree.
        if(Directory.GetFiles(AdminPolicy.FixtureRoot).Any(p=>Path.GetFileName(p)!="ClaudeResetGateway.exe" && Path.GetFileName(p)!="broker-payload.json")) throw new InvalidDataException("Unexpected fixture files");
        if(Directory.GetDirectories(AdminPolicy.FixtureRoot).Length!=0) throw new InvalidDataException("Unexpected fixture directory");
        if(File.Exists(exe)) { Check(exe,false); if(AdminPolicy.Hash(File.ReadAllBytes(exe))!=AdminBuild.GatewayHash) throw new InvalidDataException("Existing payload differs"); }
        else NewFile(exe,Gateway());
        AtomicJson(Path.Combine(AdminPolicy.FixtureRoot,"broker-payload.json"),new {schema=1,sha256=AdminBuild.GatewayHash,service=AdminPolicy.Fixture,network_authorized=false});
    }
    internal static string VerifyFixture() {
        Check(AdminPolicy.FixtureRoot,true); string exe=Path.Combine(AdminPolicy.FixtureRoot,"ClaudeResetGateway.exe"); Check(exe,false);
        if(AdminPolicy.Hash(File.ReadAllBytes(exe))!=AdminBuild.GatewayHash) throw new InvalidDataException("Fixture changed");
        string receipt=Path.Combine(AdminPolicy.FixtureRoot,"broker-payload.json"); Check(receipt,false);
        var r=AdminPolicy.Object(File.ReadAllText(receipt));
        if((string)r["sha256"]!=AdminBuild.GatewayHash || (string)r["service"]!=AdminPolicy.Fixture) throw new InvalidDataException("Unowned fixture");
        return exe;
    }
}

static class AdminTransport {
    [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { internal int length; internal IntPtr descriptor; internal int inherit; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafePipeHandle CreateNamedPipe(string name,uint access,uint mode,uint instances,uint output,uint input,uint timeout,ref SECURITY_ATTRIBUTES security);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    internal static NamedPipeServerStream Create(string name,string owner) {
        PipeSecurity security=new PipeSecurity();security.SetAccessRuleProtection(true,false);security.SetOwner(WindowsIdentity.GetCurrent().User);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-2"),PipeAccessRights.FullControl,AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(owner),PipeAccessRights.ReadWrite,AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(AdminFiles.SystemSid,PipeAccessRights.FullControl,AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(AdminFiles.AdminSid,PipeAccessRights.FullControl,AccessControlType.Allow));
        byte[] sd=security.GetSecurityDescriptorBinaryForm();GCHandle pin=GCHandle.Alloc(sd,GCHandleType.Pinned);
        try {
            SECURITY_ATTRIBUTES sa=new SECURITY_ATTRIBUTES{length=Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),descriptor=pin.AddrOfPinnedObject(),inherit=0};
            // First instance, overlapped I/O, duplex, and kernel rejection of remote clients.
            SafePipeHandle handle=CreateNamedPipe(@"\\.\pipe\"+name,0x40080003,8,1,4096,256,0,ref sa);
            if(handle.IsInvalid) { int code=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(code); }
            return new NamedPipeServerStream(PipeDirection.InOut,true,false,handle);
        } finally {pin.Free();}
    }
    internal static int Authenticate(NamedPipeServerStream pipe,string owner,int session) {
        uint pid;if(!GetNamedPipeClientProcessId(pipe.SafePipeHandle,out pid)) throw new Win32Exception(Marshal.GetLastWin32Error());
        string sid=null;pipe.RunAsClient(delegate {using(WindowsIdentity id=WindowsIdentity.GetCurrent(true)){if(id!=null)sid=id.User.Value;}});
        using(Process p=Process.GetProcessById((int)pid)) if(sid!=owner || p.SessionId!=session) throw new UnauthorizedAccessException("Different user/session");
        return (int)pid;
    }
    internal static string Read(PipeStream pipe,int timeout,int limit) {
        Stopwatch timer=Stopwatch.StartNew();MemoryStream bytes=new MemoryStream();byte[] b=new byte[1];
        while(bytes.Length<=limit) {
            IAsyncResult pending=pipe.BeginRead(b,0,1,null,null);
            WaitHandle wait=pending.AsyncWaitHandle;
            int left=timeout-(int)timer.ElapsedMilliseconds;
            // On timeout, the pipe owner disposes the pipe to cancel I/O. Its
            // callback still needs the event; let that pending result retain it.
            if(left<=0 || !wait.WaitOne(left)) throw new TimeoutException("Frame deadline");
            int count;try{count=pipe.EndRead(pending);}finally{wait.Dispose();}
            if(count!=1) throw new EndOfStreamException();
            if(b[0]==10) return new UTF8Encoding(false,true).GetString(bytes.ToArray());
            bytes.WriteByte(b[0]);
        }
        throw new InvalidDataException("Oversized frame");
    }
    internal static void Write(PipeStream pipe,string message,int timeout) {
        byte[] bytes=new UTF8Encoding(false).GetBytes(message+"\n");IAsyncResult pending=pipe.BeginWrite(bytes,0,bytes.Length,null,null);
        WaitHandle wait=pending.AsyncWaitHandle;
        if(!wait.WaitOne(timeout)) throw new TimeoutException();
        try{pipe.EndWrite(pending);}finally{wait.Dispose();}
    }
    internal static string Exchange(PipeStream pipe,string request,int timeout,int limit) {
        // The v0.1.0 server disconnects immediately after its single response write.
        // DisconnectNamedPipe discards unread data. Post ONE read large enough for
        // the entire bounded response BEFORE sending the request, so the kernel
        // transfers that write directly to this buffer. Never retry a mutation if
        // its response is incomplete: completion may already have occurred.
        byte[] bytes=new byte[checked(limit+1)];Stopwatch timer=Stopwatch.StartNew();
        IAsyncResult pending=pipe.BeginRead(bytes,0,bytes.Length,null,null);
        WaitHandle wait=pending.AsyncWaitHandle;
        Write(pipe,request,3000);
        int left=timeout-(int)timer.ElapsedMilliseconds;
        if(left<=0 || !wait.WaitOne(left))throw new TimeoutException("Response deadline");
        int count;try{count=pipe.EndRead(pending);}finally{wait.Dispose();}
        if(count==0)throw new EndOfStreamException();
        if(bytes[count-1]!=10 || Array.IndexOf(bytes,(byte)10,0,count)!=count-1)throw new InvalidDataException("Incomplete or multiple response frames");
        return new UTF8Encoding(false,true).GetString(bytes,0,count-1);
    }
}

static class AdminServices {
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr scm,string name,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateService(IntPtr scm,string name,string display,uint access,uint type,uint start,uint error,string path,string group,IntPtr tag,string dependencies,string account,string password);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool ChangeServiceConfig2(IntPtr service,uint level,ref uint value);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool DeleteService(IntPtr service);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
    internal static object Inventory() {
        List<object> rows=new List<object>();
        foreach(string name in new[]{"SbieSvc","SbieDrv",AdminPolicy.Fixture,"ClaudeResetGateway","CoworkVMService","CodexSandboxService.OpenAI.Codex"}) {
            using(RegistryKey key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+name,false)) {
                if(key==null){rows.Add(new{name=name,installed=false});continue;}
                string state="unavailable";try{using(ServiceController service=new ServiceController(name)){state=service.Status.ToString();}}catch(InvalidOperationException){}
                rows.Add(new{name=name,installed=true,state=state,image=Convert.ToString(key.GetValue("ImagePath")),start=key.GetValue("Start")});
            }
        }
        return new{read_only=true,services=rows};
    }
    internal static object RegisterFixture() {
        AdminFiles.Stage();string exe=AdminFiles.VerifyFixture();
        IntPtr scm=OpenSCManager(null,null,3);if(scm==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr service=IntPtr.Zero;
        try {
            service=CreateService(scm,AdminPolicy.Fixture,"ClaudeReset gateway fixture (not started)",0x10002,0x10,3,1,"\""+exe+"\" --service",null,IntPtr.Zero,null,"LocalSystem",null);
            if(service==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint sid=1;if(!ChangeServiceConfig2(service,5,ref sid)) {int code=Marshal.GetLastWin32Error();DeleteService(service);throw new Win32Exception(code);}
            return new{registered=true,service=AdminPolicy.Fixture,started=false,network_authorized=false};
        } finally {if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(scm);}
    }
    internal static object RemoveFixture() {
        string exe=AdminFiles.VerifyFixture();
        using(RegistryKey key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+AdminPolicy.Fixture,false)) {
            if(key==null) return new{removed=false,already_absent=true};
            if(Convert.ToString(key.GetValue("ImagePath"))!="\""+exe+"\" --service" || Convert.ToString(key.GetValue("ObjectName"))!="LocalSystem" || Convert.ToInt32(key.GetValue("Type"))!=0x10 || Convert.ToInt32(key.GetValue("Start"))!=3) throw new InvalidDataException("Existing service is not this fixture");
        }
        using(ServiceController controller=new ServiceController(AdminPolicy.Fixture)) if(controller.Status!=ServiceControllerStatus.Stopped)throw new InvalidOperationException("Fixture must already be stopped");
        IntPtr scm=OpenSCManager(null,null,1);if(scm==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());IntPtr service=IntPtr.Zero;
        try {service=OpenService(scm,AdminPolicy.Fixture,0x10000);if(service==IntPtr.Zero || !DeleteService(service))throw new Win32Exception(Marshal.GetLastWin32Error());return new{removed=true,files_retained=true};}
        finally {if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(scm);}
    }
}

static class AdminDiagnostics {
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine,IntPtr template,out IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine,IntPtr handle,uint count,out IntPtr entries,out uint returned);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine,IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr data);
    static void Ok(uint code) {if(code!=0)throw new Win32Exception(unchecked((int)code));}
    static Guid GuidAt(IntPtr p,int offset){return (Guid)Marshal.PtrToStructure(IntPtr.Add(p,offset),typeof(Guid));}
    internal static object Wfp() {
        if(IntPtr.Size!=8)throw new PlatformNotSupportedException();
        IntPtr engine=IntPtr.Zero,handle=IntPtr.Zero;bool transaction=false;List<object> rows=new List<object>();int scanned=0;
        try {
            Ok(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));Ok(FwpmTransactionBegin0(engine,1));transaction=true;
            Ok(FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out handle));
            while(true){IntPtr entries=IntPtr.Zero;uint count;
                try {Ok(FwpmFilterEnum0(engine,handle,256,out entries,out count));if(count==0)break;scanned+=(int)count;if(scanned>131072)throw new InvalidDataException("Enumeration bound");
                    for(int i=0;i<count;i++) {
                        IntPtr p=Marshal.ReadIntPtr(entries,i*IntPtr.Size);int size=Marshal.ReadInt32(p,48);if(size<11 || size>4096)continue;
                        IntPtr data=Marshal.ReadIntPtr(p,56);if(data==IntPtr.Zero)continue;byte[] bytes=new byte[size];Marshal.Copy(data,bytes,0,size);
                        if(Encoding.ASCII.GetString(bytes,0,11)!="ClaudeReset")continue;
                        int conditions=Marshal.ReadInt32(p,112);if(conditions<0 || conditions>128)throw new InvalidDataException();
                        IntPtr cp=Marshal.ReadIntPtr(p,120);List<object> fields=new List<object>();
                        for(int j=0;j<conditions;j++){IntPtr c=IntPtr.Add(cp,j*40);int type=Marshal.ReadInt32(c,24);fields.Add(new{field=GuidAt(c,0),match=Marshal.ReadInt32(c,16),type=type,scalar=type>=1&&type<=3?(long?)Marshal.ReadInt32(c,32):null});}
                        rows.Add(new{key=GuidAt(p,0),layer=GuidAt(p,64),sublayer=GuidAt(p,80),flags=Marshal.ReadInt32(p,32),action=Marshal.ReadInt32(p,128),id=Marshal.ReadInt64(p,176),marker_sha256=AdminPolicy.Hash(bytes),conditions=fields});
                        if(rows.Count>1024)throw new InvalidDataException("Owned filter bound");
                    }
                }finally{if(entries!=IntPtr.Zero)FwpmFreeMemory0(ref entries);}
            }
            return new{read_only=true,filters_changed=false,observed_count=rows.Count,filters=rows,coverage_verified=false};
        } finally {if(handle!=IntPtr.Zero)FwpmFilterDestroyEnumHandle0(engine,handle);if(transaction)FwpmTransactionAbort0(engine);if(engine!=IntPtr.Zero)FwpmEngineClose0(engine);}
    }
    internal static object Hcs() {
        string system=Environment.GetFolderPath(Environment.SpecialFolder.System),exe=Path.Combine(system,"hcsdiag.exe");AdminFiles.NoReparse(exe);
        ProcessStartInfo start=new ProcessStartInfo(exe,"list -raw"){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=system,RedirectStandardOutput=true,RedirectStandardError=true};
        start.EnvironmentVariables.Clear();start.EnvironmentVariables["SystemRoot"]=Path.GetDirectoryName(system);start.EnvironmentVariables["WINDIR"]=Path.GetDirectoryName(system);start.EnvironmentVariables["PATH"]=system;
        using(Process p=Process.Start(start)) {
            var stdout=p.StandardOutput.ReadToEndAsync();var stderr=p.StandardError.ReadToEndAsync();
            if(!p.WaitForExit(15000)){p.Kill();throw new TimeoutException("HCS inventory");}
            if(p.ExitCode!=0)return new{read_only=true,inventory_verified=false,exit_code=p.ExitCode};
            string text=stdout.Result;if(text.Length>1048576)throw new InvalidDataException("HCS response bound");
            object parsed=new JavaScriptSerializer().DeserializeObject(text);object[] systems=parsed as object[];if(systems==null)throw new InvalidDataException("Unknown HCS schema");
            List<object> rows=new List<object>();
            foreach(object o in systems){var d=o as Dictionary<string,object>;if(d==null)throw new InvalidDataException();string owner=d.ContainsKey("Owner")?Convert.ToString(d["Owner"]):"";
                if(owner.IndexOf("cowork",StringComparison.OrdinalIgnoreCase)<0 && owner.IndexOf("claude",StringComparison.OrdinalIgnoreCase)<0)continue;
                rows.Add(new{id=d.ContainsKey("Id")?d["Id"]:null,owner=owner,state=d.ContainsKey("State")?d["State"]:null});}
            return new{read_only=true,inventory_verified=true,guests=rows,guest_network_verified=false};
        }
    }
}

static class ClaudeResetAdminBroker {
    static volatile bool stopping;
    internal static object Dispatch(string operation) {
        switch(operation){
            case "status":return new{version="0.1.1",elevated=AdminPolicy.Administrator(),pid=Process.GetCurrentProcess().Id,operations=AdminPolicy.Operations,production_clients_permitted=false,driver_install_supported=false,arbitrary_commands_supported=false};
            case "services":return AdminServices.Inventory();
            case "hcs":return AdminDiagnostics.Hcs();
            case "wfp":return AdminDiagnostics.Wfp();
            case "stage-fixture":AdminFiles.Stage();return new{staged=true,sha256=AdminBuild.GatewayHash,executed=false};
            case "register-fixture":return AdminServices.RegisterFixture();
            case "remove-fixture":return AdminServices.RemoveFixture();
            case "stop":stopping=true;return new{stopping=true};
            default:throw new InvalidDataException("Unsupported operation");
        }
    }
    internal static int Serve() {
        if(!AdminPolicy.Administrator() || IntPtr.Size!=8 || Process.GetCurrentProcess().SessionId!=AdminBuild.SessionId)throw new UnauthorizedAccessException("Elevated x64 session required");
        string hash=AdminPolicy.ImageHash,expected=Path.Combine(AdminPolicy.Root,hash,"ClaudeResetAdminBroker.exe");
        if(!String.Equals(AdminPolicy.Image,expected,StringComparison.OrdinalIgnoreCase))throw new UnauthorizedAccessException("Protected installation required");
        AdminFiles.Check(AdminPolicy.Root,true);AdminFiles.Check(Path.GetDirectoryName(expected),true);AdminFiles.Check(expected,false);
        if(Directory.GetFiles(Path.GetDirectoryName(expected)).Any(p=>p!=expected) || Directory.GetDirectories(Path.GetDirectoryName(expected)).Length!=0)throw new InvalidDataException("Unexpected executable sidecar");
        // Lock the loaded image against replacement throughout the maintenance session.
        using(FileStream imagePin=new FileStream(expected,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            string mutexName=@"Global\ClaudeReset.AdminBroker."+AdminBuild.OwnerSid;
            MutexSecurity ms=new MutexSecurity();ms.AddAccessRule(new MutexAccessRule(AdminFiles.AdminSid,MutexRights.FullControl,AccessControlType.Allow));ms.AddAccessRule(new MutexAccessRule(AdminFiles.SystemSid,MutexRights.FullControl,AccessControlType.Allow));
            bool created;using(Mutex mutex=new Mutex(false,mutexName,out created,ms)) {
                bool owned;try{owned=mutex.WaitOne(0);}catch(AbandonedMutexException){owned=true;}if(!owned)throw new InvalidOperationException("Broker already running");
                try {
                    string session=Guid.NewGuid().ToString("N"),pipeName="ClaudeReset.Admin."+session;
                    string sessions=Path.Combine(AdminPolicy.Root,"sessions");AdminFiles.DirectoryOwned(sessions);string folder=Path.Combine(sessions,session);AdminFiles.DirectoryOwned(folder);
                    string journal=Path.Combine(folder,"journal.jsonl");AdminFiles.NewFile(journal,new byte[0]);
                    string active=Path.Combine(AdminPolicy.Root,"active.json");DateTime until=DateTime.UtcNow.AddHours(24);Stopwatch lifetime=Stopwatch.StartNew();
                    HashSet<string> seen=new HashSet<string>();
                    using(FileStream logFile=new FileStream(journal,FileMode.Append,FileAccess.Write,FileShare.Read)) using(StreamWriter log=new StreamWriter(logFile,new UTF8Encoding(false))) {
                        Action<object> record=delegate(object r){log.WriteLine(AdminPolicy.Json(r));log.Flush();logFile.Flush(true);};
                        record(new{event_type="started",utc=DateTime.UtcNow.ToString("O"),hash=hash,operations=AdminPolicy.Operations});
                        using(NamedPipeServerStream pipe=AdminTransport.Create(pipeName,AdminBuild.OwnerSid)) {
                            AdminFiles.AtomicJson(active,new{schema=1,state="ready",session=session,pipe=pipeName,pid=Process.GetCurrentProcess().Id,start_ticks=Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks,sha256=hash,owner_sid=AdminBuild.OwnerSid,windows_session=AdminBuild.SessionId,expires_utc=until.ToString("O"),image=expected});
                            while(!stopping && lifetime.Elapsed.TotalHours<24 && seen.Count<10000) {
                                IAsyncResult wait=pipe.BeginWaitForConnection(null,null);
                                using(WaitHandle ready=wait.AsyncWaitHandle){while(!ready.WaitOne(500)){if(lifetime.Elapsed.TotalHours>=24){stopping=true;break;}}if(stopping)break;pipe.EndWaitForConnection(wait);}
                                string request=null,operation=null;int peer=0;
                                try {
                                    peer=AdminTransport.Authenticate(pipe,AdminBuild.OwnerSid,AdminBuild.SessionId);
                                    string[] frame=AdminPolicy.Parse(AdminTransport.Read(pipe,4000,110),session);request=frame[1];operation=frame[2];
                                    if(!seen.Add(request))throw new InvalidDataException("Replay");
                                    record(new{event_type="request",utc=DateTime.UtcNow.ToString("O"),request=request,operation=operation,client_pid=peer});
                                    object result=Dispatch(operation);record(new{event_type="completed",utc=DateTime.UtcNow.ToString("O"),request=request,operation=operation});
                                    AdminTransport.Write(pipe,AdminPolicy.Json(new{ok=true,request=request,result=result}),4000);
                                } catch(Exception e) {
                                    string error=AdminPolicy.Error(e);record(new{event_type="rejected_or_failed",utc=DateTime.UtcNow.ToString("O"),request=request,operation=operation,client_pid=peer,error=error});
                                    try{AdminTransport.Write(pipe,AdminPolicy.Json(new{ok=false,request=request,error=error}),1000);}catch(Exception){}
                                    // A timed-out async I/O cannot safely be reused. Stop rather than leave an unbounded privileged worker.
                                    if(e is TimeoutException)stopping=true;
                                } finally {if(pipe.IsConnected)pipe.Disconnect();}
                            }
                        }
                        record(new{event_type="stopped",utc=DateTime.UtcNow.ToString("O")});AdminFiles.AtomicJson(active,new{schema=1,state="stopped",session=session,sha256=hash});
                    }
                    return 0;
                } finally {mutex.ReleaseMutex();}
            }
        }
    }
    internal static int Client(string operation,string expectedServerHash) {
        if(!AdminPolicy.Operations.Contains(operation))throw new InvalidDataException("Unsupported operation");
        AdminFiles.Check(AdminPolicy.Root,true);string active=Path.Combine(AdminPolicy.Root,"active.json");AdminFiles.Check(active,false);
        var data=AdminPolicy.Object(File.ReadAllText(active));if((string)data["state"]!="ready")throw new InvalidOperationException("Broker not running");
        string session=(string)data["session"],hash=(string)data["sha256"],name=(string)data["pipe"];
        if(!AdminPolicy.IsId(session) || name!="ClaudeReset.Admin."+session || hash!=expectedServerHash || (string)data["owner_sid"]!=WindowsIdentity.GetCurrent().User.Value || Convert.ToInt32(data["windows_session"])!=Process.GetCurrentProcess().SessionId)throw new UnauthorizedAccessException("Session identity differs");
        string image=Path.Combine(AdminPolicy.Root,hash,"ClaudeResetAdminBroker.exe");AdminFiles.Check(Path.GetDirectoryName(image),true);AdminFiles.Check(image,false);
        if((string)data["image"]!=image || AdminPolicy.Hash(File.ReadAllBytes(image))!=hash)throw new UnauthorizedAccessException("Server image differs");
        using(NamedPipeClientStream pipe=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification)) {
            pipe.Connect(3000);uint pid;if(!AdminTransport.GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid) || pid!=Convert.ToUInt32(data["pid"]))throw new UnauthorizedAccessException("Server PID differs");
            using(Process process=Process.GetProcessById((int)pid)) {
                if(process.StartTime.ToUniversalTime().Ticks!=Convert.ToInt64(data["start_ticks"]))throw new UnauthorizedAccessException("Server generation differs");
                string id=Guid.NewGuid().ToString("N");
                string response=AdminTransport.Exchange(pipe,session+"|"+id+"|"+operation,25000,1048576);var value=AdminPolicy.Object(response);if((string)value["request"]!=id)throw new InvalidDataException("Response mismatch");Console.WriteLine(response);return (bool)value["ok"]?0:1;
            }
        }
    }
    static int Main(string[] args) {
        try {
            if(args.Length==1 && args[0]=="--serve")return Serve();
            if(args.Length==2 && args[0]=="--client")return Client(args[1],AdminPolicy.ImageHash);
            Console.Error.WriteLine("Use the reviewed launcher, or --client <operation>.");return 2;
        } catch(Exception e) {Console.Error.WriteLine(AdminPolicy.Json(new{ok=false,error=AdminPolicy.Error(e)}));return 1;}
    }
}
