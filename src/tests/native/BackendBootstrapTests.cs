using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;

class BackendBootstrapTests {
    static readonly Type T=typeof(ClaudeResetBackend);
    static object Call(string method,params object[] args) {
        try{return T.GetMethod(method,BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,args);}
        catch(TargetInvocationException e){throw e.InnerException;}
    }
    static void Check(bool value){if(!value)throw new Exception("Bootstrap assertion failed");}
    static int Main() {
        int checks=0;
        try {
            var good=(Dictionary<string,object>)Call("Bootstrap","{\"schema\":1,\"runtime_sha256\":\""+new string('a',64)+"\"}");
            Check((int)good["schema"]==1);checks++;
            foreach(string bad in new[]{"{}","{\"schema\":true}","{\"schema\":1,\"runtime_sha256\":\"bad\"}",
                "{\"schema\":1,\"schema\":1}","{\"schema\":1,\"runtime_sha256\":\""+new string('a',64)+"\",\"command\":\"arbitrary\"}"}) {
                bool rejected=false;try{Call("Bootstrap",bad);}catch(InvalidDataException){rejected=true;}Check(rejected);checks++;
            }
            string env=(string)Call("CleanEnvironment",@"C:\FixtureTemp");
            Check(env.EndsWith("\0\0") && !env.Contains("HTTP_PROXY") && !env.Contains("PYTHONPATH"));checks++;
            Check(env.StartsWith("OPENSSL_CONF=\0PATH=") && !env.Contains("OPENSSL_MODULES") && !env.Contains("OPENSSL_ENGINES"));checks++;
            Check(Marshal.SizeOf(T.GetNestedType("Limits",BindingFlags.NonPublic))==144);checks++;
            Check(Marshal.SizeOf(T.GetNestedType("Startup",BindingFlags.NonPublic))==104);checks++;
            Console.WriteLine(new JavaScriptSerializer().Serialize(new{passed=true,checks=checks,service_started=false}));return 0;
        }catch(Exception e){Console.WriteLine(new JavaScriptSerializer().Serialize(new{passed=false,checks=checks,error=e.GetType().Name,detail=e.ToString()}));return 1;}
    }
}
