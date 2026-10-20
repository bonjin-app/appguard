// Host-only probe, compiled with Unity's actual compiler/reference set.
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using AppGuard;
class RiskManagedProbe {
    [DllImport("AppGuardUnityHost",EntryPoint="AppGuardUnityInvoke")] static extern IntPtr Invoke(byte[] op,byte[] payload);
    [DllImport("AppGuardUnityHost",EntryPoint="AppGuardUnityFree")] static extern void Free(IntPtr pointer);
    sealed class Wire : INativeTransport {
        internal int Frees, Worker;
        public string Invoke(string operation,string payload) {
            Worker=Thread.CurrentThread.ManagedThreadId;
            var pointer=RiskManagedProbe.Invoke(Encoding.UTF8.GetBytes(operation+"\0"),Encoding.UTF8.GetBytes(payload+"\0"));
            return NativeResponse.Consume(pointer,p=>{Frees++;Free(p);},4096);
        }
    }
    static void Require(bool condition) {if(!condition)throw new Exception("host C ABI managed probe failed");}
    public static void Main() {
        int caller=Thread.CurrentThread.ManagedThreadId;var wire=new Wire();var client=new Client(wire);
        var report=client.ScanLocalRiskAsync().GetAwaiter().GetResult();
        Require(report.Platform=="ios" && report.Checks.Count==5 && wire.Frees==1 && wire.Worker!=caller);
        Require(report.Checks[3].State=="not_configured" && report.Checks[4].State=="not_configured");
        Require(report.RiskSignals.Count==1 && report.RiskSignals[0]=="local_checks_unavailable");
        try {client.ScanLocalRiskAsync(new LocalRiskOptions(androidSignerSha256:new[]{new string('a',64)})).GetAwaiter().GetResult();throw new Exception("missing unsupported error");}
        catch(AppGuardException error) {Require(error.Code=="APPGUARD_UNSUPPORTED" && error.InnerException==null);}
        Require(wire.Frees==2);
        Console.WriteLine("PASS: actual managed async -> host C ABI -> native scan -> strict report/error decode, 2 owned buffers freed on worker");
    }
}
