// Fixed service bootstrap: no arbitrary command, script or caller-supplied path.
// The runtime verifies the preinstalled boundary before starting the engine.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Web.Script.Serialization;

sealed class ClaudeResetBackend : ServiceBase {
    const string Name="ClaudeResetBackend";
    readonly object sync=new object();
    readonly List<FileStream> pins=new List<FileStream>();
    IntPtr job=IntPtr.Zero,process=IntPtr.Zero;
    Timer health;
    bool stopping;
    bool exitConfirmed=true;
    static readonly string Root=AppDomain.CurrentDomain.BaseDirectory;

    [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
        public long processTime,jobTime;public uint flags;public UIntPtr minimum,maximum;
        public uint active;public UIntPtr affinity;public uint priority,scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters {public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes;}
    [StructLayout(LayoutKind.Sequential)] struct Limits {public BasicLimits basic;public IoCounters io;public UIntPtr processMemory,jobMemory,peakProcess,peakJob;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {
        public uint cb;public string reserved,desktop,title;public uint x,y,xsize,ysize,xchars,ychars,fill,flags;
        public ushort show,reservedSize;public IntPtr reservedPtr,stdin,stdout,stderr;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {public IntPtr process,thread;public uint pid,tid;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr attributes,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref Limits limits,uint size);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);

    static void Main(string[] args) {
        if(args.Length!=1 || args[0]!="--service")Environment.Exit(2);
        ServiceBase.Run(new ClaudeResetBackend{ServiceName=Name,CanStop=true,CanShutdown=true,AutoLog=false});
    }

    static Dictionary<string,object> Bootstrap(string text) {
        var value=ClaudeResetGateway.DecodeConfig(text);
        if(value.Count!=2 || !value.ContainsKey("schema") || !(value["schema"] is int) || (int)value["schema"]!=1
            || !value.ContainsKey("runtime_sha256") || !(value["runtime_sha256"] is string)
            || !System.Text.RegularExpressions.Regex.IsMatch((string)value["runtime_sha256"],@"\A[a-f0-9]{64}\z"))
            throw new InvalidDataException("Unsupported backend bootstrap configuration");
        return value;
    }

    static string CleanEnvironment(string temp) {
        string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return "OPENSSL_CONF=\0PATH="+Path.Combine(windows,"System32")+";"+windows+"\0SystemDrive="+Path.GetPathRoot(windows).TrimEnd('\\')+
            "\0SystemRoot="+windows+"\0TEMP="+temp+"\0TMP="+temp+"\0WINDIR="+windows+"\0\0";
    }

    void Report(string state) {
        try{File.WriteAllText(Path.Combine(Root,"backend-service-status.json"),new JavaScriptSerializer().Serialize(new{
            state=state,utc=DateTime.UtcNow.ToString("O"),full_tunnel_verified=false,client_admission=false}));}
        catch(IOException){}catch(UnauthorizedAccessException){}
    }

    protected override void OnStart(string[] args) {
        IntPtr environment=IntPtr.Zero;ProcessInfo child=new ProcessInfo();
        try {
            if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(Limits))!=144 || Marshal.SizeOf(typeof(Startup))!=104)throw new InvalidDataException("Unsupported process layout");
            using(var self=Process.GetCurrentProcess()){
                ClaudeResetGateway.RequireEngineService(self);
                string expected=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeReset","Backend","ClaudeResetBackend.exe");
                if(!String.Equals(self.MainModule.FileName,expected,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Unexpected service image");
                ClaudeResetGateway.TrustedPath(expected);
            }
            string installation=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeReset");
            var config=new FileStream(ClaudeResetGateway.TrustedPath(Path.Combine(Root,"backend-bootstrap.json")),FileMode.Open,FileAccess.Read,FileShare.Read);
            pins.Add(config);if(config.Length>1024)throw new InvalidDataException();
            string text;using(var reader=new StreamReader(config,Encoding.UTF8,true,1024,true))text=reader.ReadToEnd();
            var bootstrap=Bootstrap(text);
            string runtime=Path.Combine(installation,"Runtime","ClaudeResetRuntime.exe");
            pins.Add(ClaudeResetGateway.PinTrusted(runtime,(string)bootstrap["runtime_sha256"]));
            string temp=ClaudeResetGateway.TrustedPath(Path.Combine(installation,"RuntimeTemp"));
            job=CreateJobObjectW(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new InvalidOperationException("Job creation failed");
            var limits=new Limits();limits.basic.flags=0x2000; // mandatory inheritance, kill-on-close
            if(!SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(limits)))throw new InvalidOperationException("Job limits failed");
            var startup=new Startup{cb=(uint)Marshal.SizeOf(typeof(Startup))};
            environment=Marshal.StringToHGlobalUni(CleanEnvironment(temp));
            if(!CreateProcessW(runtime,new StringBuilder("\""+runtime+"\" --service"),IntPtr.Zero,IntPtr.Zero,false,4|0x400|0x08000000,
                environment,Path.GetDirectoryName(runtime),ref startup,out child))throw new InvalidOperationException("Runtime creation failed");
            process=child.process;
            exitConfirmed=false;
            if(!AssignProcessToJobObject(job,process) || ResumeThread(child.thread)!=1)throw new InvalidOperationException("Suspended runtime assignment failed");
            CloseHandle(child.thread);child.thread=IntPtr.Zero;
            health=new Timer(delegate(object unused){bool ended;lock(sync){if(stopping)return;ended=WaitForSingleObject(process,0)!=258;}if(ended)Stop();},null,250,250);
            Report("runtime_started_no_client_admission");
        } catch {CloseOwned();Report("blocked_start_failure");throw;}
        finally {if(child.thread!=IntPtr.Zero)CloseHandle(child.thread);if(environment!=IntPtr.Zero)Marshal.FreeHGlobal(environment);}
    }

    void CloseOwned() {
        lock(sync){
            if(stopping)return;stopping=true;
            if(health!=null)health.Dispose();
            bool released=true;if(job!=IntPtr.Zero){released=CloseHandle(job);job=IntPtr.Zero;}
            if(process!=IntPtr.Zero){
                if(WaitForSingleObject(process,1000)!=0)TerminateProcess(process,1);
                uint exited=WaitForSingleObject(process,5000);CloseHandle(process);process=IntPtr.Zero;
                exitConfirmed=released && exited==0;
            }
            foreach(var pin in pins)pin.Dispose();pins.Clear();
        }
    }
    protected override void OnStop(){CloseOwned();Report(exitConfirmed?"closed":"owned_runtime_exit_unconfirmed");}
    protected override void OnShutdown(){CloseOwned();Report(exitConfirmed?"closed_shutdown":"owned_runtime_exit_unconfirmed");}
}
