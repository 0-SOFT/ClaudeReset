// Invokes the actual service implementation without installing or starting SCM.
// All peers are disposable loopback sockets. No application traffic or DNS.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

class GatewayFunctionalTests {
    const BindingFlags Private=BindingFlags.NonPublic|BindingFlags.Instance|BindingFlags.Static;
    static readonly Type T=typeof(ClaudeResetGateway);
    static object Call(object instance,string method,params object[] args) {
        try{return T.GetMethod(method,Private).Invoke(instance,args);}
        catch(TargetInvocationException e){throw e.InnerException;}
    }
    static void Set(object instance,string field,object value){T.GetField(field,Private).SetValue(instance,value);}
    static void Check(bool result){if(!result)throw new Exception("Functional assertion failed");}
    static byte[] Read(NetworkStream s,int n) {
        s.ReadTimeout=4000;var b=new byte[n];int offset=0;
        while(offset<n){int got=s.Read(b,offset,n-offset);if(got==0)throw new EndOfStreamException();offset+=got;}
        return b;
    }
    static string Header(NetworkStream s) {
        var b=new List<byte>();while(b.Count<8192){b.Add(Read(s,1)[0]);int n=b.Count;
            if(n>3 && b[n-4]==13 && b[n-3]==10 && b[n-2]==13 && b[n-1]==10)return Encoding.ASCII.GetString(b.ToArray());}
        throw new Exception("Test peer header too large");
    }
    static void Write(NetworkStream s,string text){byte[] b=Encoding.ASCII.GetBytes(text);s.Write(b,0,b.Length);}
    static void Destination(string input,bool valid,string expected=null,int port=0) {
        object[] args={input,null,0};bool accepted;
        try{Call(null,"Destination",args);accepted=true;}catch(InvalidDataException){accepted=false;}
        Check(accepted==valid);if(valid){Check((string)args[1]==expected);Check((int)args[2]==port);}
    }
    static void Tunnel(string protocol,string authority,string version,bool accept) {
        using(var gateway=new ClaudeResetGateway())using(var engine=Process.GetCurrentProcess()){
            IntPtr held=engine.Handle;Set(gateway,"engine",engine);Set(gateway,"controller",engine);Set(gateway,"protocol",protocol);
            var backend=new TcpListener(IPAddress.Loopback,0);backend.Start();int bp=((IPEndPoint)backend.LocalEndpoint).Port;
            Set(gateway,"backendPort",bp);
            var front=new TcpListener(IPAddress.Loopback,0);front.Start();
            Task peer=Task.Run(()=>{
                using(TcpClient c=backend.AcceptTcpClient()){
                    NetworkStream s=c.GetStream();
                    if(protocol=="http"){
                        Check(Header(s)=="CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n");
                        Write(s,accept?"HTTP/1.0 200 OK\r\n\r\n":"HTTP/1.1 502 Refused\r\n\r\n");
                    } else {
                        Check(BitConverter.ToString(Read(s,3))=="05-01-00");s.Write(new byte[]{5,0},0,2);
                        byte[] h=Read(s,4);Check(h[0]==5 && h[1]==1 && h[2]==0);
                        int length=h[3]==1?4:h[3]==4?16:h[3]==3?Read(s,1)[0]:0;Check(length>0);
                        byte[] host=Read(s,length);byte[] port=Read(s,2);Check(port[0]==1 && port[1]==187);
                        if(authority=="fixture.invalid:443"){Check(h[3]==3);Check(Encoding.ASCII.GetString(host)=="fixture.invalid");}
                        else if(authority=="192.0.2.1:443"){Check(h[3]==1);Check(new IPAddress(host).ToString()=="192.0.2.1");}
                        else{Check(h[3]==4);Check(new IPAddress(host).ToString()=="2001:db8::1");}
                        s.Write(new byte[]{5,(byte)(accept?0:5),0,1,127,0,0,1,0,1},0,10);
                    }
                    if(accept){byte[] marker=Read(s,4);Check(Encoding.ASCII.GetString(marker)=="PING");Write(s,"PONG");}
                }
            });
            using(var client=new TcpClient()){
                client.Connect(IPAddress.Loopback,((IPEndPoint)front.LocalEndpoint).Port);
                TcpClient accepted=front.AcceptTcpClient();
                ((Semaphore)T.GetField("slots",Private).GetValue(gateway)).WaitOne();
                Task relay=Task.Run(()=>Call(gateway,"Handle",accepted));
                NetworkStream s=client.GetStream();Write(s,"CONNECT "+authority+" "+version+"\r\nHost: ignored.invalid\r\n\r\n");
                if(accept){Check(Header(s).StartsWith("HTTP/1.1 200 "));Write(s,"PING");Check(Encoding.ASCII.GetString(Read(s,4))=="PONG");}
                else{Check(s.ReadByte()==-1);}
                client.Close();Check(relay.Wait(6000));Check(peer.Wait(6000));
            }
            front.Stop();backend.Stop();
        }
    }
    static void RejectedFrontend(string request) {
        using(var gateway=new ClaudeResetGateway())using(var engine=Process.GetCurrentProcess()){
            IntPtr held=engine.Handle;Set(gateway,"engine",engine);Set(gateway,"controller",engine);Set(gateway,"protocol","http");
            var backend=new TcpListener(IPAddress.Loopback,0);backend.Start();Set(gateway,"backendPort",((IPEndPoint)backend.LocalEndpoint).Port);
            var front=new TcpListener(IPAddress.Loopback,0);front.Start();
            using(var client=new TcpClient()){
                client.Connect(IPAddress.Loopback,((IPEndPoint)front.LocalEndpoint).Port);TcpClient accepted=front.AcceptTcpClient();
                ((Semaphore)T.GetField("slots",Private).GetValue(gateway)).WaitOne();
                Task relay=Task.Run(()=>Call(gateway,"Handle",accepted));NetworkStream s=client.GetStream();s.ReadTimeout=4000;
                Write(s,request);Check(s.ReadByte()==-1);Check(relay.Wait(5000));Check(!backend.Pending());
            }
            front.Stop();backend.Stop();
        }
    }
    static void WrongOwner(int expectedPid) {
        using(var gateway=new ClaudeResetGateway())using(var engine=Process.GetProcessById(expectedPid)){
            IntPtr held=engine.Handle;Set(gateway,"engine",engine);Set(gateway,"controller",engine);Set(gateway,"protocol","http");
            var backend=new TcpListener(IPAddress.Loopback,0);backend.Start();Set(gateway,"backendPort",((IPEndPoint)backend.LocalEndpoint).Port);
            var front=new TcpListener(IPAddress.Loopback,0);front.Start();
            Task peer=Task.Run(()=>{using(TcpClient c=backend.AcceptTcpClient()){NetworkStream s=c.GetStream();s.ReadTimeout=4000;Check(s.ReadByte()==-1);}});
            using(var client=new TcpClient()){
                client.Connect(IPAddress.Loopback,((IPEndPoint)front.LocalEndpoint).Port);TcpClient accepted=front.AcceptTcpClient();
                ((Semaphore)T.GetField("slots",Private).GetValue(gateway)).WaitOne();Task relay=Task.Run(()=>Call(gateway,"Handle",accepted));
                NetworkStream s=client.GetStream();s.ReadTimeout=4000;Write(s,"CONNECT never-disclose.invalid:443 HTTP/1.1\r\n\r\n");
                Check(s.ReadByte()==-1);Check(relay.Wait(5000));Check(peer.Wait(5000));
            }
            front.Stop();backend.Stop();
        }
    }
    static void StopActiveTunnel() {
        using(var gateway=new ClaudeResetGateway())using(var engine=Process.GetCurrentProcess()){
            IntPtr held=engine.Handle;Set(gateway,"engine",engine);Set(gateway,"controller",engine);Set(gateway,"protocol","http");
            var backend=new TcpListener(IPAddress.Loopback,0);backend.Start();Set(gateway,"backendPort",((IPEndPoint)backend.LocalEndpoint).Port);
            var front=new TcpListener(IPAddress.Loopback,0);front.Start();
            Task peer=Task.Run(()=>{using(TcpClient c=backend.AcceptTcpClient()){
                NetworkStream s=c.GetStream();Header(s);Write(s,"HTTP/1.1 200 OK\r\n\r\n");s.ReadTimeout=4000;
                Check(s.ReadByte()==-1);
            }});
            using(var client=new TcpClient()){
                client.Connect(IPAddress.Loopback,((IPEndPoint)front.LocalEndpoint).Port);TcpClient accepted=front.AcceptTcpClient();
                ((Semaphore)T.GetField("slots",Private).GetValue(gateway)).WaitOne();Call(gateway,"Track",accepted);
                Task relay=Task.Run(()=>Call(gateway,"Handle",accepted));NetworkStream s=client.GetStream();
                Write(s,"CONNECT fixture.invalid:443 HTTP/1.1\r\n\r\n");Check(Header(s).StartsWith("HTTP/1.1 200 "));
                Call(gateway,"CloseAll");s.ReadTimeout=4000;Check(s.ReadByte()==-1);Check(relay.Wait(5000));Check(peer.Wait(5000));
                Check(!backend.Pending());
            }
            front.Stop();backend.Stop();
        }
    }
    static int Main(string[] args) {
        if(args.Length==1 && args[0]=="--exit")return 0;
        var passed=new List<string>();
        try {
            Destination("fixture.invalid:443",true,"fixture.invalid",443);
            Destination("[2001:db8::1]:443",true,"2001:db8::1",443);
            foreach(string bad in new[]{"localhost:0","x:65536","x:0000001","x:443\r\nX:1","a..b:443","-a:443","user@host:443","[x::1]:443","http://x:443","x:443 "})Destination(bad,false);
            passed.Add("authority_validation");
            foreach(string bad in new[]{@"\\server\share\file",@"\\?\C:\file",@"\file",@"C:file",@"C:\file:stream",@"C:\a\..\b","C:/file","C:\\file\n",@"C:\file.",@"C:\file ",@"C:\CON.txt",@"C:\NUL",@"C:\COM1\file"}){
                bool rejected=false;try{Call(null,"LocalPath",bad);}catch(InvalidDataException){rejected=true;}Check(rejected);
            }
            Check((string)Call(null,"LocalPath",Process.GetCurrentProcess().MainModule.FileName)==Process.GetCurrentProcess().MainModule.FileName);
            passed.Add("config_paths_never_use_unc_or_device_namespace");
            foreach(string bad in new[]{"{\"a\":1,\"a\":2}","{\"a\":1,\"\\u0061\":2}","{\"x\":{}}","{\"x\":true}","{\"x\":1,}","{\"x\":01}","{\"x\":1.0}","{}garbage","{\"x\":1\f}"}) {
                bool rejected=false;try{Call(null,"DecodeConfig",bad);}catch(InvalidDataException){rejected=true;}Check(rejected);
            }
            var decoded=(Dictionary<string,object>)Call(null,"DecodeConfig"," {\"a\":1, \"path\":\"C:\\\\Runtime\\\\file\"} \r\n");
            Check((int)decoded["a"]==1 && (string)decoded["path"]==@"C:\Runtime\file");
            passed.Add("native_config_rejects_duplicates_and_nested_values");
            foreach(string sddl in new[]{"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)","O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"}) {
                var acl=new DirectorySecurity();acl.SetSecurityDescriptorSddlForm(sddl);Call(null,"ValidateAcl",acl,true);
            }
            foreach(string sddl in new[]{"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)","O:BUG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)","O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)","O:SYG:SYD:P(A;;FA;;;SY)"}) {
                var acl=new DirectorySecurity();acl.SetSecurityDescriptorSddlForm(sddl);bool rejected=false;
                try{Call(null,"ValidateAcl",acl,true);}catch(InvalidDataException){rejected=true;}Check(rejected);
            }
            passed.Add("native_runtime_acl_requires_protected_trusted_writers");
            bool outside=false;try{Call(null,"TrustedPath",Process.GetCurrentProcess().MainModule.FileName);}catch(InvalidDataException){outside=true;}Check(outside);
            passed.Add("native_runtime_refuses_unprotected_install_location");
            using(var ordinary=Process.GetCurrentProcess()) {
                bool rejected=false;try{Call(null,"RequireEngineService",ordinary);}catch(InvalidDataException){rejected=true;}Check(rejected);
            }
            passed.Add("ordinary_engine_process_cannot_impersonate_backend_service");
            string claims=Path.Combine(Path.GetTempPath(),"ClaudeReset-claims-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(claims);
            string generation=Guid.NewGuid().ToString("N");
            try {
                Call(null,"ClaimGeneration",claims,generation);bool rejected=false;
                try{Call(null,"ClaimGeneration",claims,generation);}catch(IOException){rejected=true;}Check(rejected);
                rejected=false;try{Call(null,"ClaimGeneration",claims,"../invalid");}catch(InvalidDataException){rejected=true;}Check(rejected);
            } finally {File.Delete(Path.Combine(claims,"generation-"+generation+".claim"));Directory.Delete(claims);}
            passed.Add("gateway_generation_is_single_use");
            using(var gateway=new ClaudeResetGateway())using(var engine=Process.GetCurrentProcess())
            using(var ended=Process.Start(new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,"--exit"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden})) {
                IntPtr held=ended.Handle;Check(ended.WaitForExit(5000));Set(gateway,"engine",engine);
                Check(!(bool)Call(gateway,"ContextAlive"));Set(gateway,"controller",ended);Check(!(bool)Call(gateway,"ContextAlive"));
                Set(gateway,"controller",engine);Check((bool)Call(gateway,"ContextAlive"));
                Set(gateway,"engine",ended);Check(!(bool)Call(gateway,"ContextAlive"));
                Set(gateway,"engine",engine);Set(gateway,"stopping",true);Check(!(bool)Call(gateway,"ContextAlive"));
            }
            passed.Add("missing_dead_engine_or_controller_and_stopping_refuse_transport");
            foreach(object bad in new object[]{true,1.0,"1",null,0,65536}){
                bool rejected=false;try{Call(null,"Number",new Dictionary<string,object>{{"port",bad}},"port",1L,65535L);}catch(InvalidDataException){rejected=true;}Check(rejected);
            }
            Check((long)Call(null,"Number",new Dictionary<string,object>{{"port",443}},"port",1L,65535L)==443);passed.Add("strict_config_integer_types");
            foreach(string protocol in new[]{"http","socks5"})foreach(string host in new[]{"fixture.invalid:443","192.0.2.1:443","[2001:db8::1]:443"}) {
                Tunnel(protocol,host,"HTTP/1.1",true);passed.Add(protocol+"_opaque_echo_"+host);
            }
            Tunnel("http","fixture.invalid:443","HTTP/1.0",true);passed.Add("http10_frontend");
            Tunnel("http","fixture.invalid:443","HTTP/1.1",false);Tunnel("socks5","fixture.invalid:443","HTTP/1.1",false);passed.Add("backend_refusal_closes");
            foreach(string bad in new[]{"GET http://fixture.invalid HTTP/1.1\r\n\r\n","CONNECT x:443 HTTP/2\r\n\r\n","CONNECT x:443 HTTP/1.1\r\nContent-Length: 1\r\n\r\n","CONNECT x:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n","CONNECT x:443 HTTP/1.1\r\nProxy-Authorization: test\r\n\r\n","CONNECT x:443 HTTP/1.1\r\n bad: folded\r\n\r\n"})RejectedFrontend(bad);
            passed.Add("malformed_frontend_never_connects_backend");
            WrongOwner(Int32.Parse(args[0]));passed.Add("wrong_backend_owner_receives_zero_bytes");
            StopActiveTunnel();passed.Add("stop_closes_existing_flow_both_directions");
            Console.WriteLine(new JavaScriptSerializer().Serialize(new{passed=true,checks=passed,external_requests=0,service_installed=false}));return 0;
        } catch(Exception e){Console.WriteLine(new JavaScriptSerializer().Serialize(new{passed=false,checks=passed,error=e.GetType().Name,detail=e.ToString()}));return 1;}
    }
}
