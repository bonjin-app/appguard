using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
namespace AppGuard.Tests {
public class LocalRiskTests {
    static JObject Corpus => JObject.Parse(File.ReadAllText(Path.Combine(UnityEditor.PackageManager.PackageInfo.FindForAssembly(typeof(Client).Assembly).resolvedPath,"Tests/Editor/local-risk-bridge.json")));
    static string Good => new JObject { ["ok"]=true,["result"]=Corpus["reports"][0]["report"].DeepClone() }.ToString(Newtonsoft.Json.Formatting.None);
    sealed class Wire : INativeTransport {
        public string Response=Good, Payload, Operation; public int ThreadId, Calls; public Exception Error;
        public string Invoke(string op,string payload) { Calls++; ThreadId=Thread.CurrentThread.ManagedThreadId;Operation=op;Payload=payload;if(Error!=null)throw Error;return Response; }
    }
    static AppGuardException Failure(Task<LocalRiskReport> task) { try { task.GetAwaiter().GetResult();Assert.Fail("expected failure");return null; } catch(AppGuardException e) {Assert.That(e.InnerException,Is.Null);Assert.That(e.Message,Is.EqualTo(e.Code));return e;} }
    static IEnumerable<TestCaseData> ReportCases() {
        foreach(var c in Corpus["reports"])yield return new TestCaseData(c).SetName("SharedReport_"+(string)c["id"]);
    }
    [TestCaseSource(nameof(ReportCases))] public void SharedReportCase(JToken c) {
        var w=new Wire {Response=new JObject {["ok"]=true,["result"]=c["report"].DeepClone()}.ToString()};
        if((bool)c["valid"]) {var r=new Client(w).ScanLocalRiskAsync().GetAwaiter().GetResult();Assert.That(r.Schema,Is.EqualTo("appguard-local-risk-v0"));}
        else Assert.That(Failure(new Client(w).ScanLocalRiskAsync()).Code,Is.EqualTo("APPGUARD_OPERATION_FAILED"));
    }
    [Test] public void ExactUtf8EnvelopeBoundary() {
        var w=new Wire {Response=Good.PadRight(4096)};new Client(w).ScanLocalRiskAsync().GetAwaiter().GetResult();
        w.Response+=" ";Assert.That(Failure(new Client(w).ScanLocalRiskAsync()).Code,Is.EqualTo("APPGUARD_OPERATION_FAILED"));
        w.Response=Good+new string('é',(4096-System.Text.Encoding.UTF8.GetByteCount(Good))/2+1);
        Assert.That(Failure(new Client(w).ScanLocalRiskAsync()).Code,Is.EqualTo("APPGUARD_OPERATION_FAILED"));
    }
    [Test] public void DefaultPayloadIsEmptyAndNativeRunsOnOwnedWorker() {
        var w=new Wire();int caller=Thread.CurrentThread.ManagedThreadId;
        new Client(w).ScanLocalRiskAsync().GetAwaiter().GetResult();
        Assert.That(w.Operation,Is.EqualTo("scanLocalRisk"));Assert.That(w.Payload,Is.EqualTo("{}"));Assert.That(w.ThreadId,Is.Not.EqualTo(caller));
    }
    [Test] public void OptionsSnapshotCollectionsAndReturnedReportAreImmutable() {
        var pins=new List<string>{new string('a',64)};var resources=new Dictionary<string,string>{{"data/a.json",new string('b',64)}};
        var options=new LocalRiskOptions("io.app",pins,resources);pins[0]="private";resources.Clear();
        var w=new Wire();var pending=new Client(w).ScanLocalRiskAsync(options);pins.Clear();resources["PRIVATE"]=null;var report=pending.GetAwaiter().GetResult();
        Assert.That((string)JObject.Parse(w.Payload)["androidSignerSha256"][0],Is.EqualTo(new string('a',64)));
        Assert.That(JObject.Parse(w.Payload)["protectedResources"].Count(),Is.EqualTo(1));
        Assert.Throws<NotSupportedException>(()=>((IList<string>)options.AndroidSignerSha256)[0]="private");
        Assert.Throws<NotSupportedException>(()=>((IDictionary<string,string>)options.ProtectedResources).Clear());
        Assert.Throws<NotSupportedException>(()=>((IList<LocalRiskCheck>)report.Checks).Clear());
        Assert.Throws<NotSupportedException>(()=>((IList<string>)report.RiskSignals).Add("root"));
    }
    [TestCase("")][TestCase("é")][TestCase("_bad")][TestCase("a/b")][TestCase("a\n")]
    public void InvalidIdsNeverDispatch(string id) { Assert.That(Assert.Throws<AppGuardException>(()=>new LocalRiskOptions(id)).Code,Is.EqualTo("APPGUARD_INVALID_INPUT")); }
    [Test] public void BoundsPinsAndPathsAreValidated() {
        Assert.Throws<AppGuardException>(()=>new LocalRiskOptions(new string('a',256)));
        Assert.Throws<AppGuardException>(()=>new LocalRiskOptions(androidSignerSha256:new[]{new string('A',64)}));
        Assert.Throws<AppGuardException>(()=>new LocalRiskOptions(androidSignerSha256:new[]{new string('a',64),new string('a',64)}));
        Assert.Throws<AppGuardException>(()=>new LocalRiskOptions(androidSignerSha256:Enumerable.Range(0,9).Select(x=>x.ToString("x64"))));
        foreach(string path in new[]{"/a","a/../b","a//b","a\\b","a/.","é",new string('a',129)}) Assert.Throws<AppGuardException>(()=>new LocalRiskOptions(protectedResources:new Dictionary<string,string>{{path,new string('a',64)}}));
        Assert.Throws<AppGuardException>(()=>new LocalRiskOptions(protectedResources:Enumerable.Range(0,9).ToDictionary(x=>"a"+x,x=>new string('a',64))));
        // Accepted upper bounds and explicitly empty collections retain their fields.
        var w=new Wire();new Client(w).ScanLocalRiskAsync(new LocalRiskOptions(new string('a',255),new string[0],new Dictionary<string,string>())).GetAwaiter().GetResult();
        Assert.That(JObject.Parse(w.Payload).Count,Is.EqualTo(3));
    }
    [TestCase("APPGUARD_UNSUPPORTED")][TestCase("APPGUARD_NATIVE_UNAVAILABLE")][TestCase("APPGUARD_INVALID_INPUT")][TestCase("PRIVATE")]
    public void NativeErrorsAreFixed(string code) {
        var w=new Wire {Response="{\"ok\":false,\"error\":{\"code\":\""+code+"\",\"message\":\"PRIVATE\"}}"};
        Assert.That(Failure(new Client(w).ScanLocalRiskAsync()).Code,Is.EqualTo(code=="PRIVATE"?"APPGUARD_OPERATION_FAILED":code));
    }
    [Test] public void MalformedEnvelopesAndOversizeAreRedacted() {
        foreach(var text in new[]{"PRIVATE",Good+" {}",Good.Replace("\"ok\":true","\"ok\":true,\"ok\":true"),new string('é',2049),"{\"ok\":true,\"result\":{}}"})
            Assert.That(Failure(new Client(new Wire {Response=text}).ScanLocalRiskAsync()).Code,Is.EqualTo("APPGUARD_OPERATION_FAILED"));
        foreach(var error in new Exception[]{new DllNotFoundException("PRIVATE"),new EntryPointNotFoundException("PRIVATE"),new Exception("PRIVATE")})
            Assert.That(Failure(new Client(new Wire {Error=error}).ScanLocalRiskAsync()).Code,Is.EqualTo(error is DllNotFoundException||error is EntryPointNotFoundException?"APPGUARD_NATIVE_UNAVAILABLE":"APPGUARD_OPERATION_FAILED"));
    }
    [Test] public void AttachInvokeDetachAllUseOwnedThreadAndDetachAfterFailure() {
        int caller=Thread.CurrentThread.ManagedThreadId;var events=new List<string>();int attach=0,invoke=0,detach=0;
        var worker=new ScanWorker(()=>{attach=Thread.CurrentThread.ManagedThreadId;events.Add("attach");},()=>{detach=Thread.CurrentThread.ManagedThreadId;events.Add("detach");});
        var task=worker.Start<LocalRiskReport>(()=>{invoke=Thread.CurrentThread.ManagedThreadId;events.Add("invoke");throw new Exception("PRIVATE");});
        Assert.That(Failure(task).Code,Is.EqualTo("APPGUARD_OPERATION_FAILED"));Assert.That(events,Is.EqualTo(new[]{"attach","invoke","detach"}));Assert.That(attach,Is.EqualTo(invoke));Assert.That(detach,Is.EqualTo(invoke));Assert.That(invoke,Is.Not.EqualTo(caller));
    }
    [Test] public void FailedAttachmentDoesNotInvokeOrDetach() {
        var worker=new ScanWorker(()=>{throw new AppGuardException("APPGUARD_NATIVE_UNAVAILABLE");},()=>Assert.Fail("detach without successful attach"));
        Assert.That(Failure(worker.Start<LocalRiskReport>(()=>{Assert.Fail("invoke without attach");return null;})).Code,Is.EqualTo("APPGUARD_NATIVE_UNAVAILABLE"));
    }
    [Test] public void BoundedScanResponseAlwaysFreesOwnedBuffer() {
        int frees=0;var p=Marshal.AllocCoTaskMem(4097);for(int i=0;i<4097;i++)Marshal.WriteByte(p,i,65);
        Assert.Throws<AppGuardException>(()=>NativeResponse.Consume(p,x=>{frees++;Marshal.FreeCoTaskMem(x);},4096));Assert.That(frees,Is.EqualTo(1));
        p=Marshal.AllocCoTaskMem(2);Marshal.WriteByte(p,0,255);Marshal.WriteByte(p,1,0);
        Assert.Throws<AppGuardException>(()=>NativeResponse.Consume(p,x=>{frees++;Marshal.FreeCoTaskMem(x);},4096));Assert.That(frees,Is.EqualTo(2));
    }
    [Test] public void EditorRejectsExplicitly() {Assert.That(Failure(new Client().ScanLocalRiskAsync()).Code,Is.EqualTo("APPGUARD_UNSUPPORTED"));}
}}
