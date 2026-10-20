using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Newtonsoft.Json.Linq;
[assembly: InternalsVisibleTo("AppGuard.Unity.Tests")]
namespace AppGuard {
public enum HardwareRequirement { Any, Hardware, StrongBox }
public sealed class AppGuardException : Exception { public string Code {get;} internal AppGuardException(string code):base(code){Code=code;} }
internal interface INativeTransport { string Invoke(string operation,string payload); }
public sealed class PrepareRequest { public string Alias,Origin,Method,Target,ContentType,Authorization,AppId,KeyId,Nonce; public byte[] Body; public long Created,Expires; public HardwareRequirement HardwareRequirement; }
public sealed class EnrollmentChallenge { public string AppId,Origin,Subject,KeyId,PublicKeySha256,Nonce; public long Expires; }
public sealed class EnrollmentRequest { public string Alias,ExpectedAppId,ExpectedOrigin,ExpectedSubject,ExpectedKeyId; public EnrollmentChallenge Challenge; public HardwareRequirement HardwareRequirement; }
public sealed class PublicKeyResult { public string PublicKeyPem {get;internal set;} public string Backing {get;internal set;} }
public sealed class Header { public string Name {get;internal set;} public string Value {get;internal set;} }
public sealed class PreparedRequest { public string Origin {get;internal set;} public string Method {get;internal set;} public string Target {get;internal set;} public string BodyBase64 {get;internal set;} public byte[] Body => Convert.FromBase64String(BodyBase64); public string KeyId {get;internal set;} public IReadOnlyList<Header> Headers {get;internal set;} }
public sealed class EnrollmentProofResult { public string ProofBase64 {get;internal set;} public string ClientDataHashBase64 {get;internal set;} public string GoogleRequestHash {get;internal set;} }
public sealed class Client {
    readonly INativeTransport wire;
    public Client() : this(new PlatformTransport()) {}
    internal Client(INativeTransport wire) { this.wire=wire ?? throw new AppGuardException("APPGUARD_NATIVE_UNAVAILABLE"); }
    /// <summary>Collect bounded untrusted local hints on an owned background thread.</summary>
    public System.Threading.Tasks.Task<LocalRiskReport> ScanLocalRiskAsync(LocalRiskOptions options=null) {
        // Immutable options are fully encoded on the caller before scheduling.
        string payload=(options ?? new LocalRiskOptions()).Encode();
        return ScanWorker.Platform().Start(()=>LocalRiskDecoder.Decode(wire is PlatformTransport platform ? platform.InvokeLocalRisk(payload) : wire.Invoke("scanLocalRisk",payload)));
    }
    static JObject Common(string alias, HardwareRequirement requirement) {
        if (string.IsNullOrEmpty(alias) || !Enum.IsDefined(typeof(HardwareRequirement),requirement)) throw new AppGuardException("APPGUARD_INVALID_INPUT");
        return new JObject { ["alias"]=alias, ["hardwareRequirement"]=requirement==HardwareRequirement.Any ? "any" : requirement==HardwareRequirement.Hardware ? "hardware" : "strongbox" };
    }
    JObject Invoke(string operation,JObject payload) {
        string encoded=payload.ToString(Newtonsoft.Json.Formatting.None);
        if(System.Text.Encoding.UTF8.GetByteCount(encoded)>1500000) throw new AppGuardException("APPGUARD_INVALID_INPUT");
        string response;
        try { response=wire.Invoke(operation,encoded); }
        catch(AppGuardException e) { throw new AppGuardException(SafeCode(e.Code)); }
        catch(DllNotFoundException) {throw new AppGuardException("APPGUARD_NATIVE_UNAVAILABLE");}
        catch(EntryPointNotFoundException) {throw new AppGuardException("APPGUARD_NATIVE_UNAVAILABLE");}
        catch { throw new AppGuardException("APPGUARD_OPERATION_FAILED"); }
        try {
            if(response==null || System.Text.Encoding.UTF8.GetByteCount(response)>NativeResponse.MaxBytes) throw new FormatException();
            JObject root;
            using(var reader=new Newtonsoft.Json.JsonTextReader(new System.IO.StringReader(response)) {DateParseHandling=Newtonsoft.Json.DateParseHandling.None}) {
                root=JObject.Load(reader, new JsonLoadSettings {DuplicatePropertyNameHandling=DuplicatePropertyNameHandling.Error});
                if(reader.Read()) throw new FormatException();
            }
            if(root["ok"]?.Type!=JTokenType.Boolean) throw new FormatException();
            if(!(bool)root["ok"]) throw new AppGuardException(SafeCode(root["error"]?["code"]?.Type==JTokenType.String ? (string)root["error"]["code"] : null));
            if(!(root["result"] is JObject result)) throw new FormatException();
            return result;
        } catch(AppGuardException) {throw;} catch {throw new AppGuardException("APPGUARD_OPERATION_FAILED");}
    }
    internal static string SafeCode(string code) {
        switch(code) {case "APPGUARD_INVALID_INPUT":case "APPGUARD_KEY_UNAVAILABLE":case "APPGUARD_UNSUPPORTED":case "APPGUARD_NATIVE_UNAVAILABLE": return code; default:return "APPGUARD_OPERATION_FAILED";}
    }
    static string Text(JObject result,string key) { if(result[key]?.Type!=JTokenType.String) throw new AppGuardException("APPGUARD_OPERATION_FAILED"); return (string)result[key]; }
    public PublicKeyResult PublicKey(string alias, HardwareRequirement requirement=HardwareRequirement.Any) {
        var result=Invoke("publicKey",Common(alias,requirement)); return new PublicKeyResult {PublicKeyPem=Text(result,"publicKeyPem"),Backing=Text(result,"backing")};
    }
    public PreparedRequest Prepare(PrepareRequest request) {
        if(request==null || request.Body==null || request.Body.Length>1048576) throw new AppGuardException("APPGUARD_INVALID_INPUT");
        var p=Common(request.Alias,request.HardwareRequirement);
        p["origin"]=request.Origin;p["method"]=request.Method;p["target"]=request.Target;p["bodyBase64"]=Convert.ToBase64String(request.Body);p["contentType"]=request.ContentType;p["authorization"]=request.Authorization;p["appId"]=request.AppId;p["keyId"]=request.KeyId;p["created"]=request.Created;p["expires"]=request.Expires;p["nonce"]=request.Nonce;
        var r=Invoke("prepare",p);
        try {
            string body=Text(r,"bodyBase64"); var bytes=Convert.FromBase64String(body);
            if(bytes.Length>1048576 || Convert.ToBase64String(bytes)!=body) throw new FormatException();
            if(!(r["headers"] is JArray pairs)) throw new FormatException();
            var headers=new List<Header>(); foreach(var pair in pairs) {if(!(pair is JArray a) || a.Count!=2 || a[0].Type!=JTokenType.String || a[1].Type!=JTokenType.String) throw new FormatException(); headers.Add(new Header {Name=(string)a[0],Value=(string)a[1]});}
            return new PreparedRequest {Origin=Text(r,"origin"),Method=Text(r,"method"),Target=Text(r,"target"),BodyBase64=body,KeyId=Text(r,"keyId"),Headers=headers.AsReadOnly()};
        } catch(AppGuardException) {throw;} catch {throw new AppGuardException("APPGUARD_OPERATION_FAILED");}
    }
    public EnrollmentProofResult EnrollmentProof(EnrollmentRequest request) {
        if(request?.Challenge==null) throw new AppGuardException("APPGUARD_INVALID_INPUT");
        var p=Common(request.Alias,request.HardwareRequirement); var c=request.Challenge;
        p["challenge"]=new JObject {["appId"]=c.AppId,["origin"]=c.Origin,["subject"]=c.Subject,["keyId"]=c.KeyId,["publicKeySha256"]=c.PublicKeySha256,["nonce"]=c.Nonce,["expires"]=c.Expires};
        p["expectedAppId"]=request.ExpectedAppId;p["expectedOrigin"]=request.ExpectedOrigin;p["expectedSubject"]=request.ExpectedSubject;p["expectedKeyId"]=request.ExpectedKeyId;
        var r=Invoke("enrollmentProof",p);return new EnrollmentProofResult {ProofBase64=Text(r,"proofBase64"),ClientDataHashBase64=Text(r,"clientDataHashBase64"),GoogleRequestHash=Text(r,"googleRequestHash")};
    }
}
}
