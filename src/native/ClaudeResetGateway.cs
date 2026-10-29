// The service image and configuration must be installed in an administrator-owned
// directory. WFP reserves its listening port for this image AND service SID.
// This transport never authorizes application isolation or selects another route.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using TimeoutException = System.TimeoutException;

sealed class ClaudeResetGateway : ServiceBase {
#if FIXTURE
    const string Name = "ClaudeResetGatewayFixture";
    const string BackendName = "ClaudeResetBackendFixture";
#else
    const string Name = "ClaudeResetGateway";
    const string BackendName = "ClaudeResetBackend";
#endif
    static readonly string Root = AppDomain.CurrentDomain.BaseDirectory;
    readonly object sync = new object();
    readonly HashSet<TcpClient> sockets = new HashSet<TcpClient>();
    readonly Semaphore slots = new Semaphore(64,64);
    readonly List<FileStream> pins = new List<FileStream>();
    volatile bool stopping;
    TcpListener listener;
    Process engine;
    Process controller;
    Thread acceptThread;
    Timer health;
    string protocol;
    int backendPort;

    [DllImport("iphlpapi.dll",SetLastError=true)]
    static extern uint GetExtendedTcpTable(IntPtr table,ref int size,bool order,int family,int tableClass,uint reserved);
    [DllImport("advapi32.dll",SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    internal static void RequireEngineService(Process process) {
        IntPtr token;
        if(!OpenProcessToken(process.Handle,8,out token))throw new InvalidDataException("Engine token unavailable");
        try {
            using(var identity=new WindowsIdentity(token)) {
                if(identity.User.Value!="S-1-5-18")throw new InvalidDataException("Engine must use the protected backend service token");
                string sid=((SecurityIdentifier)new NTAccount("NT SERVICE",BackendName).Translate(typeof(SecurityIdentifier))).Value;
                if(!identity.Groups.Any(g=>g.Value==sid))throw new InvalidDataException("Engine backend service identity mismatch");
            }
        } finally {CloseHandle(token);}
    }

    static void ClaimGeneration(string directory,string generation) {
        if(generation==null || !Regex.IsMatch(generation,@"\A[a-f0-9]{32}\z"))throw new InvalidDataException("Invalid gateway generation");
        // Parent is checked by TrustedPath before this call. Never remove or
        // reuse a claim: a restart needs a newly verified controller generation.
        using(var claim=new FileStream(Path.Combine(directory,"generation-"+generation+".claim"),FileMode.CreateNew,FileAccess.Write,FileShare.None))claim.Flush(true);
    }

    bool ContextAlive() {return !stopping && engine!=null && controller!=null && !engine.HasExited && !controller.HasExited;}

    static void Main(string[] args) {
        if(args.Length!=1 || args[0]!="--service") Environment.Exit(2);
        ServiceBase.Run(new ClaudeResetGateway{ServiceName=Name,CanStop=true,AutoLog=false});
    }

    static string Hash(Stream stream) {
        stream.Position=0;using(SHA256 hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
    }

    static string LocalPath(string path) {
        // Reject UNC/device/relative paths before any filesystem lookup. Opening
        // a config on SMB would itself contact a host outside the pinned tunnel.
        if(path==null || !Regex.IsMatch(path,@"\A[A-Za-z]:\\") || path.IndexOfAny(new[]{'\r','\n','\0','/'})>=0
            || path.IndexOf(':',2)>=0 || path.Length>32760)throw new InvalidDataException("Local absolute file path required");
        string full=Path.GetFullPath(path);
        if(!String.Equals(full,path,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Non-canonical local path");
        foreach(string part in path.Substring(3).Split('\\')) {
            if(part.Length==0 || part.EndsWith(".") || part.EndsWith(" ") ||
                Regex.IsMatch(part,@"\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|\z)",RegexOptions.IgnoreCase))
                throw new InvalidDataException("Unsafe local path alias");
        }
        DriveType kind=new DriveInfo(Path.GetPathRoot(full)).DriveType;
        if(kind!=DriveType.Fixed && kind!=DriveType.Removable && kind!=DriveType.Ram)throw new InvalidDataException("Remote or unknown volume");
        return full;
    }

    static void ValidateAcl(FileSystemSecurity security,bool directory) {
        string owner=security.GetOwner(typeof(SecurityIdentifier)).Value;
        if((owner!="S-1-5-18" && owner!="S-1-5-32-544") || (directory && !security.AreAccessRulesProtected))
            throw new InvalidDataException("Unprotected runtime owner or directory ACL");
        const long writes=2|4|16|64|256|65536|262144|524288|0x10000000|0x40000000;
        var writers=new HashSet<string>();
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
            if(rule.AccessControlType!=AccessControlType.Allow || ((long)rule.FileSystemRights&writes)==0)continue;
            // Inherit-only entries do not apply to this object; each descendant
            // is separately checked and directories must disable inheritance.
            if((rule.PropagationFlags&PropagationFlags.InheritOnly)!=0)continue;
            string sid=rule.IdentityReference.Value;
            if(sid!="S-1-5-18" && sid!="S-1-5-32-544")throw new InvalidDataException("Untrusted runtime writer");
            writers.Add(sid);
        }
        if(!writers.Contains("S-1-5-18") || !writers.Contains("S-1-5-32-544"))throw new InvalidDataException("Incomplete runtime ACL");
    }

    internal static string TrustedPath(string path) {
        path=LocalPath(path);
        string programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
#if FIXTURE
        string installation=Path.Combine(programFiles,"ClaudeResetGatewayFixture");
#else
        string installation=Path.Combine(programFiles,"ClaudeReset");
#endif
        if(!path.StartsWith(installation+"\\",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Outside protected runtime installation");
        for(string p=path;;p=Path.GetDirectoryName(p)) {
            FileAttributes attributes=File.GetAttributes(p);
            if((attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Runtime reparse point");
            bool directory=(attributes&FileAttributes.Directory)!=0;
            ValidateAcl(directory?(FileSystemSecurity)Directory.GetAccessControl(p):File.GetAccessControl(p),directory);
            if(String.Equals(p,installation,StringComparison.OrdinalIgnoreCase))break;
        }
        return path;
    }

    internal static Dictionary<string,object> DecodeConfig(string text) {
        if(text==null || text.Length>16384)throw new InvalidDataException("Configuration size limit");
        // The schema is deliberately flat. Parse keys before deserialization so
        // the framework cannot silently replace duplicate (even escaped) keys.
        var serializer=new JavaScriptSerializer();var values=new Dictionary<string,object>();
        var token=new Regex(@"\G[ \t\r\n]*(""(?:[^""\\\x00-\x1f]|\\[""\\/bfnrt]|\\u[0-9a-fA-F]{4})*""|-?(?:0|[1-9][0-9]*))[ \t\r\n]*",RegexOptions.None,TimeSpan.FromSeconds(1));
        int position=0;Action whitespace=()=>{while(position<text.Length && " \t\r\n".IndexOf(text[position])>=0)position++;};
        whitespace();if(position>=text.Length || text[position++]!='{')throw new InvalidDataException();
        whitespace();if(position<text.Length && text[position]=='}'){position++;whitespace();if(position!=text.Length)throw new InvalidDataException();return values;}
        while(true) {
            Match key=token.Match(text,position);
            if(!key.Success || key.Groups[1].Value[0]!='"')throw new InvalidDataException();
            string name=serializer.Deserialize<string>(key.Groups[1].Value);position=key.Index+key.Length;
            if(position>=text.Length || text[position++]!=':' || values.ContainsKey(name))throw new InvalidDataException("Duplicate or malformed configuration key");
            Match value=token.Match(text,position);
            if(!value.Success)throw new InvalidDataException();position=value.Index+value.Length;
            values.Add(name,serializer.DeserializeObject(value.Groups[1].Value));
            if(position>=text.Length)throw new InvalidDataException();
            char delimiter=text[position++];if(delimiter=='}')break;if(delimiter!=',')throw new InvalidDataException();
        }
        whitespace();if(position!=text.Length)throw new InvalidDataException();return values;
    }

    internal static FileStream PinTrusted(string path,string expectedHash) {
        path=TrustedPath(path);
        if(expectedHash==null || !Regex.IsMatch(expectedHash,@"\A[0-9a-f]{64}\z"))throw new InvalidDataException();
        for(string p=Path.GetFullPath(path);p!=null;p=Path.GetDirectoryName(p)) {
            if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Reparse point in pinned path");
            if(Path.GetPathRoot(p)==p)break;
        }
        FileStream stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(Hash(stream)!=expectedHash){stream.Dispose();throw new InvalidDataException("Pinned content changed");}
        return stream;
    }

    FileStream Pin(string path,string expectedHash) {FileStream stream=PinTrusted(path,expectedHash);pins.Add(stream);return stream;}

    void Report(string state) {
        // No destination names, payload, credentials or public IPs in the report.
        try { File.WriteAllText(Path.Combine(Root,"gateway-status.json"),new JavaScriptSerializer().Serialize(new {
            state=state,pid=Process.GetCurrentProcess().Id,utc=DateTime.UtcNow.ToString("O"),full_tunnel_verified=false
        })); } catch(IOException) {} catch(UnauthorizedAccessException) {}
    }

    static long Number(Dictionary<string,object> c,string key,long low,long high) {
        object value;if(!c.TryGetValue(key,out value) || (!(value is int) && !(value is long)))throw new InvalidDataException("Integer required");
        long number=Convert.ToInt64(value);
        if(number<low || number>high)throw new InvalidDataException("Integer outside allowed range");return number;
    }

    protected override void OnStart(string[] args) {
        try {
            WindowsIdentity identity=WindowsIdentity.GetCurrent();
            string sid=((SecurityIdentifier)new NTAccount("NT SERVICE",Name).Translate(typeof(SecurityIdentifier))).Value;
            if(identity.User.Value!="S-1-5-18" || !identity.Groups.Any(g=>g.Value==sid))throw new InvalidOperationException("Not the dedicated service token");
            TrustedPath(Process.GetCurrentProcess().MainModule.FileName);
            FileStream config=new FileStream(TrustedPath(Path.Combine(Root,"gateway.json")),FileMode.Open,FileAccess.Read,FileShare.Read);
            pins.Add(config);if(config.Length>16384)throw new InvalidDataException();
            string text;using(StreamReader reader=new StreamReader(config,Encoding.UTF8,true,1024,true))text=reader.ReadToEnd();
            var c=DecodeConfig(text);
            string[] keys={"schema","protocol","backend_port","listen_port","engine_pid","engine_start_utc_ticks","engine_path","engine_sha256","engine_config_path","engine_config_sha256",
                "generation","controller_pid","controller_start_utc_ticks","controller_path","controller_sha256"};
            if(c==null || c.Count!=keys.Length || keys.Any(k=>!c.ContainsKey(k)) || Number(c,"schema",2,2)!=2)throw new InvalidDataException();
            protocol=(string)c["protocol"];if(protocol!="http" && protocol!="socks5")throw new InvalidDataException();
            backendPort=(int)Number(c,"backend_port",1024,49151);int port=(int)Number(c,"listen_port",1024,49151);
            if(port==backendPort)throw new InvalidDataException();
            engine=Process.GetProcessById((int)Number(c,"engine_pid",1,Int32.MaxValue));
            // Hold the original process object before checking generation. A PID
            // may be reused; future checks must never open a replacement process.
            IntPtr heldEngineHandle=engine.Handle;
            if(heldEngineHandle==IntPtr.Zero)throw new InvalidDataException("Engine handle unavailable");
            if(engine.HasExited || engine.StartTime.ToUniversalTime().Ticks!=Number(c,"engine_start_utc_ticks",1,DateTime.MaxValue.Ticks))throw new InvalidDataException("Engine generation changed");
            RequireEngineService(engine);
            if(!String.Equals(engine.MainModule.FileName,(string)c["engine_path"],StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Engine image changed");
            Pin((string)c["engine_path"],(string)c["engine_sha256"]);
            Pin((string)c["engine_config_path"],(string)c["engine_config_sha256"]);
            controller=Process.GetProcessById((int)Number(c,"controller_pid",1,Int32.MaxValue));
            IntPtr heldControllerHandle=controller.Handle;
            if(heldControllerHandle==IntPtr.Zero || controller.Id==engine.Id || controller.HasExited
                || controller.StartTime.ToUniversalTime().Ticks!=Number(c,"controller_start_utc_ticks",1,DateTime.MaxValue.Ticks))throw new InvalidDataException("Controller generation changed");
            RequireEngineService(controller);
            if(!String.Equals(controller.MainModule.FileName,(string)c["controller_path"],StringComparison.OrdinalIgnoreCase)
                || Path.GetFileName((string)c["controller_path"])!="ClaudeResetRuntime.exe")throw new InvalidDataException("Controller image changed");
            Pin((string)c["controller_path"],(string)c["controller_sha256"]);
            ClaimGeneration(Root,(string)c["generation"]);
            if(!ContextAlive())throw new InvalidDataException("Backend session ended during preparation");
            listener=new TcpListener(IPAddress.Loopback,port);listener.Server.ExclusiveAddressUse=true;listener.Start(32);
            acceptThread=new Thread(Accept);acceptThread.IsBackground=true;acceptThread.Start();
            health=new Timer(delegate(object unused){try{if(!ContextAlive())Stop();}catch(InvalidOperationException){Stop();}},null,250,250);
            Report("listening_pinned_engine");
        } catch {CloseAll();Report("blocked_start_failure");throw;}
    }

    bool Track(TcpClient socket) {
        lock(sync){if(stopping){socket.Close();return false;}sockets.Add(socket);return true;}
    }
    void Release(TcpClient socket) {
        if(socket==null)return;lock(sync){sockets.Remove(socket);}socket.Close();
    }
    void CloseAll() {
        stopping=true;if(health!=null)health.Dispose();if(listener!=null)listener.Stop();
        lock(sync){foreach(TcpClient socket in sockets)socket.Close();sockets.Clear();}
        foreach(FileStream pin in pins)pin.Dispose();pins.Clear();
        if(engine!=null)engine.Dispose();
        if(controller!=null)controller.Dispose();
    }
    protected override void OnStop(){CloseAll();Report("closed");}

    void Accept() {
        while(!stopping) {
            TcpClient client;
            try{client=listener.AcceptTcpClient();}catch(SocketException){if(stopping)return;Stop();return;}catch(ObjectDisposedException){return;}
            if(!slots.WaitOne(0)){client.Close();continue;}
            if(!Track(client)){slots.Release();return;}
            Task.Run(()=>Handle(client));
        }
    }

    static byte[] Exact(NetworkStream stream,int length,Stopwatch timer) {
        byte[] b=new byte[length];int offset=0;
        while(offset<length){int remaining=8000-(int)timer.ElapsedMilliseconds;if(remaining<=0)throw new TimeoutException();stream.ReadTimeout=remaining;
            int n=stream.Read(b,offset,length-offset);if(n==0)throw new EndOfStreamException();offset+=n;}
        return b;
    }
    static string Header(NetworkStream stream,Stopwatch timer) {
        var bytes=new List<byte>();
        while(bytes.Count<8192){bytes.Add(Exact(stream,1,timer)[0]);int n=bytes.Count;
            if(n>=4 && bytes[n-4]==13 && bytes[n-3]==10 && bytes[n-2]==13 && bytes[n-1]==10){
                if(bytes.Any(x=>x>126 || (x<32 && x!=13 && x!=10)))throw new InvalidDataException();
                return Encoding.ASCII.GetString(bytes.ToArray());}}
        throw new InvalidDataException("Header too large");
    }
    static void Destination(string authority,out string host,out int port) {
        Match m=Regex.Match(authority,@"^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+):([0-9]{1,5})$");
        if(!m.Success || authority.Length>260)throw new InvalidDataException();
        host=m.Groups[1].Value;port=Int32.Parse(m.Groups[2].Value,CultureInfo.InvariantCulture);
        if(port<1 || port>65535)throw new InvalidDataException();
        if(host.StartsWith("[")){IPAddress ip;if(!IPAddress.TryParse(host.Substring(1,host.Length-2),out ip) || ip.AddressFamily!=AddressFamily.InterNetworkV6)throw new InvalidDataException();host=ip.ToString();}
        else if(host.Length>253 || host.Split('.').Any(s=>!Regex.IsMatch(s,@"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")))throw new InvalidDataException();
    }

    bool PeerIsEngine(TcpClient upstream) {
        int local=((IPEndPoint)upstream.Client.LocalEndPoint).Port;
        Stopwatch timer=Stopwatch.StartNew();
        do {
            if(!ContextAlive())return false;
            int size=0;uint code=GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0);
            if(code!=122 || size<4 || size>16777216)return false;
            IntPtr table=Marshal.AllocHGlobal(size);
            try {
                if(GetExtendedTcpTable(table,ref size,false,2,5,0)!=0)return false;
                int count=Marshal.ReadInt32(table);if(count<0 || count>(size-4)/24)return false;
                for(int i=0;i<count;i++){
                    IntPtr row=IntPtr.Add(table,4+i*24);int lp=Marshal.ReadInt32(row,8),rp=Marshal.ReadInt32(row,16);
                    lp=((lp&255)<<8)|((lp>>8)&255);rp=((rp&255)<<8)|((rp>>8)&255);
                    if(Marshal.ReadInt32(row)==5 && lp==backendPort && rp==local && Marshal.ReadInt32(row,4)==0x0100007f && Marshal.ReadInt32(row,12)==0x0100007f)
                        return Marshal.ReadInt32(row,20)==engine.Id && ContextAlive();
                }
            } finally {Marshal.FreeHGlobal(table);}
            Thread.Sleep(10);
        } while(timer.ElapsedMilliseconds<1000);
        return false;
    }

    void Handshake(NetworkStream stream,string host,int port) {
        Stopwatch timer=Stopwatch.StartNew();stream.WriteTimeout=5000;
        if(protocol=="http") {
            string authority=(host.Contains(":")?"["+host+"]":host)+":"+port.ToString(CultureInfo.InvariantCulture);
            byte[] request=Encoding.ASCII.GetBytes("CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n");stream.Write(request,0,request.Length);
            string[] first=Header(stream,timer).Split(new[]{"\r\n"},StringSplitOptions.None)[0].Split(' ');
            if(first.Length<2 || (first[0]!="HTTP/1.0" && first[0]!="HTTP/1.1") || first[1]!="200")throw new IOException("CONNECT refused");
        } else {
            stream.Write(new byte[]{5,1,0},0,3);byte[] reply=Exact(stream,2,timer);if(reply[0]!=5 || reply[1]!=0)throw new IOException("SOCKS authentication refused");
            var request=new List<byte>(new byte[]{5,1,0});IPAddress ip;
            if(IPAddress.TryParse(host,out ip)){request.Add((byte)(ip.AddressFamily==AddressFamily.InterNetwork?1:4));request.AddRange(ip.GetAddressBytes());}
            else{byte[] name=Encoding.ASCII.GetBytes(host);request.Add(3);request.Add((byte)name.Length);request.AddRange(name);}
            request.Add((byte)(port>>8));request.Add((byte)port);byte[] bytes=request.ToArray();stream.Write(bytes,0,bytes.Length);
            reply=Exact(stream,4,timer);if(reply[0]!=5 || reply[1]!=0 || reply[2]!=0)throw new IOException("SOCKS CONNECT refused");
            int length=reply[3]==1?4:reply[3]==4?16:reply[3]==3?Exact(stream,1,timer)[0]:0;
            if(length==0)throw new IOException("SOCKS response invalid");Exact(stream,length+2,timer);
        }
    }

    void Handle(TcpClient client) {
        TcpClient upstream=null;
        try {
            NetworkStream incoming=client.GetStream();string[] lines=Header(incoming,Stopwatch.StartNew()).Split(new[]{"\r\n"},StringSplitOptions.None);
            string[] first=lines[0].Split(' ');
            if(first.Length!=3 || first[0]!="CONNECT" || (first[2]!="HTTP/1.1" && first[2]!="HTTP/1.0"))throw new InvalidDataException();
            foreach(string line in lines.Skip(1).Where(s=>s.Length>0)) {
                int colon=line.IndexOf(':');if(colon<=0 || Char.IsWhiteSpace(line[0]))throw new InvalidDataException();
                string key=line.Substring(0,colon).ToLowerInvariant();
                if(key=="content-length" || key=="transfer-encoding" || key=="proxy-authorization")throw new InvalidDataException();
            }
            string host;int port;Destination(first[1],out host,out port);
            if(!ContextAlive())return;
            upstream=new TcpClient(AddressFamily.InterNetwork);if(!Track(upstream))return;
            IAsyncResult connect=upstream.BeginConnect(IPAddress.Loopback,backendPort,null,null);
            using(WaitHandle wait=connect.AsyncWaitHandle){if(!wait.WaitOne(5000))throw new TimeoutException();upstream.EndConnect(connect);}
            if(!PeerIsEngine(upstream))throw new IOException("Backend socket owner not verified");
            NetworkStream outgoing=upstream.GetStream();Handshake(outgoing,host,port);
            if(!ContextAlive())return;
            byte[] ok=Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");incoming.Write(ok,0,ok.Length);
            incoming.ReadTimeout=outgoing.ReadTimeout=Timeout.Infinite;incoming.WriteTimeout=outgoing.WriteTimeout=30000;
            Task a=Task.Run(()=>Copy(incoming,outgoing));Task b=Task.Run(()=>Copy(outgoing,incoming));Task.WaitAny(a,b);
        } catch(InvalidDataException) {} catch(IOException) {} catch(SocketException) {} catch(TimeoutException) {} catch(ObjectDisposedException) {} catch(InvalidOperationException) {}
        finally {Release(client);Release(upstream);slots.Release();}
    }
    void Copy(Stream from,Stream to) {
        try{byte[] b=new byte[32768];while(ContextAlive()){int n=from.Read(b,0,b.Length);if(n==0 || !ContextAlive())return;to.Write(b,0,n);}}
        catch(IOException) {} catch(ObjectDisposedException) {} catch(InvalidOperationException) {}
    }
}
