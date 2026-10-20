using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AppGuard {
/// <summary>Immutable, bounded release expectations. Omitted checks are not configured.</summary>
public sealed class LocalRiskOptions {
    public string ExpectedAppId { get; }
    public IReadOnlyList<string> AndroidSignerSha256 { get; }
    public IReadOnlyDictionary<string,string> ProtectedResources { get; }
    static bool Matches(string value,string pattern,int limit) => value!=null && value.Length<=limit && Regex.IsMatch(value,pattern,RegexOptions.CultureInvariant);
    static bool Hash(string value) => Matches(value,"\\A[a-f0-9]{64}\\z",64);
    static bool Path(string value) => value!=null && value.Length<=256 && value.Split('/').All(p=>Matches(p,"\\A[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}\\z",128));
    public LocalRiskOptions(string expectedAppId=null,IEnumerable<string> androidSignerSha256=null,IDictionary<string,string> protectedResources=null) {
        try {
            if(expectedAppId!=null && !Matches(expectedAppId,"\\A[A-Za-z0-9][A-Za-z0-9._-]{0,254}\\z",255)) throw new FormatException();
            ExpectedAppId=expectedAppId;
            if(androidSignerSha256!=null) {
                var pins=new List<string>();var unique=new HashSet<string>(StringComparer.Ordinal);
                foreach(var pin in androidSignerSha256) {if(pins.Count==8 || !Hash(pin) || !unique.Add(pin))throw new FormatException();pins.Add(pin);}
                AndroidSignerSha256=pins.AsReadOnly();
            }
            if(protectedResources!=null) {
                var resources=new Dictionary<string,string>(StringComparer.Ordinal);
                foreach(var pair in protectedResources) {if(resources.Count==8 || !Path(pair.Key) || !Hash(pair.Value))throw new FormatException();resources.Add(pair.Key,pair.Value);}
                ProtectedResources=new ReadOnlyDictionary<string,string>(resources);
            }
            Encode();
        } catch {throw new AppGuardException("APPGUARD_INVALID_INPUT");}
    }
    internal string Encode() {
        var json=new JObject();
        if(ExpectedAppId!=null)json["expectedAppId"]=ExpectedAppId;
        if(AndroidSignerSha256!=null)json["androidSignerSha256"]=new JArray(AndroidSignerSha256);
        if(ProtectedResources!=null) {var map=new JObject();foreach(var pair in ProtectedResources)map[pair.Key]=pair.Value;json["protectedResources"]=map;}
        string result=json.ToString(Formatting.None);
        if(Encoding.UTF8.GetByteCount(result)>8192)throw new AppGuardException("APPGUARD_INVALID_INPUT");
        return result;
    }
}
public sealed class LocalRiskCheck {
    public string Code { get; }
    public string State { get; }
    internal LocalRiskCheck(string code,string state) {Code=code;State=state;}
}
/// <summary>Untrusted local hints, never a clean verdict or authenticated integrity proof.</summary>
public sealed class LocalRiskReport {
    public string Schema => "appguard-local-risk-v0";
    public string Platform { get; }
    public IReadOnlyList<LocalRiskCheck> Checks { get; }
    public IReadOnlyList<string> RiskSignals { get; }
    internal LocalRiskReport(string platform,List<LocalRiskCheck> checks,List<string> signals) {Platform=platform;Checks=checks.AsReadOnly();RiskSignals=signals.AsReadOnly();}
}
internal static class LocalRiskDecoder {
    internal const int MaxBytes=4096;
    static readonly string[] Android={"debugger_attached","debug_build","root_artifact","hook_artifact","app_identity_mismatch","app_signer_mismatch","bundle_resource_mismatch"};
    static readonly string[] Ios={"debugger_attached","root_artifact","hook_artifact","app_identity_mismatch","bundle_resource_mismatch"};
    static bool Keys(JObject obj,params string[] keys) => obj!=null && obj.Count==keys.Length && keys.All(k=>obj.Property(k)!=null);
    static string Text(JToken obj,string key) {if(obj?[key]?.Type!=JTokenType.String)throw new FormatException();return (string)obj[key];}
    internal static LocalRiskReport Decode(string response) {
        try {
            StrictRiskJson.Validate(response);
            JObject root;
            using(var reader=new JsonTextReader(new StringReader(response)) {DateParseHandling=DateParseHandling.None,MaxDepth=16}) {
                root=JObject.Load(reader,new JsonLoadSettings {DuplicatePropertyNameHandling=DuplicatePropertyNameHandling.Error});if(reader.Read())throw new FormatException();
            }
            if(root["ok"]?.Type!=JTokenType.Boolean)throw new FormatException();
            if(!(bool)root["ok"]) {
                if(!Keys(root,"ok","error") || !(root["error"] is JObject error))throw new FormatException();
                throw new AppGuardException(Client.SafeCode(Text(error,"code")));
            }
            if(!Keys(root,"ok","result") || !(root["result"] is JObject report) || !Keys(report,"schema","platform","checks","riskSignals"))throw new FormatException();
            if(Text(report,"schema")!="appguard-local-risk-v0")throw new FormatException();
            string platform=Text(report,"platform");string[] codes=platform=="android"?Android:platform=="ios"?Ios:null;
            if(codes==null || !(report["checks"] is JArray entries) || entries.Count!=codes.Length || !(report["riskSignals"] is JArray inputSignals))throw new FormatException();
            var checks=new List<LocalRiskCheck>();var categories=new HashSet<string>(StringComparer.Ordinal);
            for(int i=0;i<codes.Length;i++) {
                if(!(entries[i] is JObject entry) || !Keys(entry,"code","state") || Text(entry,"code")!=codes[i])throw new FormatException();
                string state=Text(entry,"state");
                if(state!="detected" && state!="not_observed" && state!="unavailable" && state!="not_configured")throw new FormatException();
                if(state=="not_configured" && i<(platform=="android"?4:3))throw new FormatException();
                if(state=="unavailable")categories.Add("local_checks_unavailable");
                if(state=="detected")categories.Add(codes[i]=="debugger_attached"||codes[i]=="debug_build"?"debugger":codes[i]=="root_artifact"?"root":codes[i]=="hook_artifact"?"hook":"tamper");
                checks.Add(new LocalRiskCheck(codes[i],state));
            }
            var signals=new[]{"debugger","root","hook","tamper","local_checks_unavailable"}.Where(categories.Contains).ToList();
            if(inputSignals.Count!=signals.Count)throw new FormatException();
            for(int i=0;i<signals.Count;i++)if(inputSignals[i].Type!=JTokenType.String || (string)inputSignals[i]!=signals[i])throw new FormatException();
            return new LocalRiskReport(platform,checks,signals);
        } catch(AppGuardException) {throw;} catch {throw new AppGuardException("APPGUARD_OPERATION_FAILED");}
    }
}
// A fresh managed Thread owns the complete JNI attachment lifetime. Never detach
// a caller/Unity main thread or a shared thread-pool thread.
internal sealed class ScanWorker {
    readonly Action attach,detach;
    internal ScanWorker(Action attach=null,Action detach=null) {this.attach=attach;this.detach=detach;}
    internal static ScanWorker Platform() {
#if UNITY_ANDROID && !UNITY_EDITOR
        return new ScanWorker(()=>{if(UnityEngine.AndroidJNI.AttachCurrentThread()!=0)throw new AppGuardException("APPGUARD_NATIVE_UNAVAILABLE");},()=>{UnityEngine.AndroidJNI.DetachCurrentThread();});
#else
        return new ScanWorker();
#endif
    }
    internal Task<T> Start<T>(Func<T> action) {
        var completion=new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        try {
            var thread=new Thread(()=>{
                T result=default(T);Exception failure=null;bool attached=false;
                try {attach?.Invoke();attached=true;result=action();}
                catch(Exception e) {failure=Redact(e);}
                finally {if(attached)try {detach?.Invoke();}catch(Exception e) {failure=Redact(e);}}
                if(failure!=null)completion.SetException(failure);else completion.SetResult(result);
            }) {IsBackground=true,Name="AppGuard local risk"};
            thread.Start();
        } catch(Exception e) {completion.SetException(Redact(e));}
        return completion.Task;
    }
    static AppGuardException Redact(Exception error) => new AppGuardException(error is AppGuardException known?Client.SafeCode(known.Code):error is DllNotFoundException||error is EntryPointNotFoundException?"APPGUARD_NATIVE_UNAVAILABLE":"APPGUARD_OPERATION_FAILED");
}
}
