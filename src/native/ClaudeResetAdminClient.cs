// Unprivileged client, pinned at build time to one reviewed server binary.
// No --serve entry point, elevation, or caller-supplied server hash.
using System;

static class ClaudeResetAdminClient {
    static int Main(string[] args) {
        try {
            if(args.Length==2 && args[0]=="--client")return ClaudeResetAdminBroker.Client(args[1],AdminClientBuild.ServerHash);
            Console.Error.WriteLine("Use --client <operation>.");return 2;
        } catch(Exception e) {
            Console.Error.WriteLine(AdminPolicy.Json(new{ok=false,error=AdminPolicy.Error(e)}));return 1;
        }
    }
}
