using System;
using System.Runtime.InteropServices;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace AppGuard.Tests {
public class ClientTests {
    sealed class Wire : INativeTransport {
        public string Operation, Payload;
        public string Response = "{\"ok\":true,\"result\":{\"publicKeyPem\":\"pem\",\"backing\":\"software\"}}";
        public string Invoke(string operation, string payload) { Operation = operation; Payload = payload; return Response; }
    }
    sealed class Missing : INativeTransport { public string Invoke(string operation,string payload) { throw new DllNotFoundException("secret native path"); } }
    [Test] public void MissingNativeLibraryIsExplicitAndRedacted() { Assert.That(Assert.Throws<AppGuardException>(()=>new Client(new Missing()).PublicKey("a")).Code,Is.EqualTo("APPGUARD_NATIVE_UNAVAILABLE")); }
    sealed class Broken : INativeTransport { public string Invoke(string operation, string payload) { throw new Exception("Bearer SECRET native-key"); } }
    [Test] public void PublicKeyUsesOnlyCommonFields() {
        var wire = new Wire(); var result = new Client(wire).PublicKey("install", HardwareRequirement.Hardware);
        Assert.That(result.PublicKeyPem, Is.EqualTo("pem"));
        Assert.That(wire.Operation, Is.EqualTo("publicKey"));
        Assert.That(JObject.Parse(wire.Payload).ToString(), Is.EqualTo(JObject.Parse("{alias:'install',hardwareRequirement:'hardware'}").ToString()));
    }
    [Test] public void PreparePreservesBinaryBodyEmptyQueryAndOrderedHeaders() {
        var wire = new Wire { Response = "{\"ok\":true,\"result\":{\"origin\":\"https://api.example\",\"method\":\"POST\",\"target\":\"/a?\",\"bodyBase64\":\"AP+A\",\"keyId\":\"key\",\"headers\":[[\"Authorization\",\"Bearer token\"],[\"Content-Digest\",\"hash\"]]}}" };
        var request = new PrepareRequest { Alias="a", Origin="https://api.example", Method="POST", Target="/a?", Body=new byte[]{0,255,128}, ContentType="application/octet-stream", Authorization="Bearer token", AppId="app", KeyId="key", Created=10, Expires=20, Nonce="nonce" };
        var result = new Client(wire).Prepare(request);
        var json = JObject.Parse(wire.Payload);
        Assert.That((string)json["bodyBase64"], Is.EqualTo("AP+A")); Assert.That((string)json["target"], Is.EqualTo("/a?"));
        Assert.That((long)json["created"], Is.EqualTo(10)); Assert.That(result.Body, Is.EqualTo(request.Body));
        Assert.That(result.Target, Is.EqualTo("/a?")); Assert.That(result.Headers[0].Name, Is.EqualTo("Authorization"));
        Assert.That(result.Headers[1].Value, Is.EqualTo("hash"));
    }
    [Test] public void EnrollmentMapsChallengeAndExpectedBinding() {
        var wire = new Wire {Response="{\"ok\":true,\"result\":{\"proofBase64\":\"cA==\",\"clientDataHashBase64\":\"aA==\",\"googleRequestHash\":\"g\"}}"};
        var result = new Client(wire).EnrollmentProof(new EnrollmentRequest { Alias="a", Challenge=new EnrollmentChallenge { AppId="app", Origin="https://api.example", Subject="s", KeyId="k", PublicKeySha256="hash", Nonce="nonce", Expires=20 }, ExpectedAppId="app", ExpectedOrigin="https://api.example", ExpectedSubject="s", ExpectedKeyId="k" });
        var json=JObject.Parse(wire.Payload); Assert.That(wire.Operation, Is.EqualTo("enrollmentProof"));
        Assert.That((string)json["challenge"]["publicKeySha256"], Is.EqualTo("hash")); Assert.That((string)json["expectedSubject"], Is.EqualTo("s")); Assert.That(result.ProofBase64, Is.EqualTo("cA=="));
    }
    [Test] public void IsoLookingIdentifiersAndHeaderValuesRemainExactStrings() {
        const string id="2026-10-20T00:00:00Z";
        var wire=new Wire {Response="{\"ok\":true,\"result\":{\"origin\":\"https://api.example\",\"method\":\"GET\",\"target\":\"/a?\",\"bodyBase64\":\"\",\"keyId\":\""+id+"\",\"headers\":[[\"AppGuard-App-Id\",\""+id+"\"]]}}"};
        var result=new Client(wire).Prepare(new PrepareRequest {Alias="a",Origin="https://api.example",Method="GET",Target="/a?",Body=new byte[0],ContentType="application/json",Authorization="Bearer token",AppId=id,KeyId=id,Created=10,Expires=20,Nonce="nonce"});
        Assert.That(result.KeyId,Is.EqualTo(id));Assert.That(result.Headers[0].Value,Is.EqualTo(id));
    }
    [Test] public void DuplicateResponsePropertiesRemainRejected() {
        var wire=new Wire {Response="{\"ok\":true,\"result\":{\"publicKeyPem\":\"first\",\"publicKeyPem\":\"second\",\"backing\":\"software\"}}"};
        Assert.That(Assert.Throws<AppGuardException>(()=>new Client(wire).PublicKey("a")).Code,Is.EqualTo("APPGUARD_OPERATION_FAILED"));
    }
    [TestCase("APPGUARD_INVALID_INPUT")][TestCase("APPGUARD_KEY_UNAVAILABLE")][TestCase("APPGUARD_UNSUPPORTED")][TestCase("APPGUARD_OPERATION_FAILED")]
    public void FixedNativeErrorsSurvive(string code) { var wire=new Wire {Response="{\"ok\":false,\"error\":{\"code\":\""+code+"\"}}"}; Assert.That(Assert.Throws<AppGuardException>(()=>new Client(wire).PublicKey("a")).Code, Is.EqualTo(code)); }
    [TestCase("{\"ok\":false,\"error\":{\"code\":\"Bearer SECRET\",\"message\":\"private\"}}")]
    [TestCase("private SECRET")][TestCase("{\"ok\":true,\"result\":{}}")][TestCase("{\"ok\":\"true\",\"result\":{}}")]
    public void InvalidNativeResponseIsRedacted(string response) { var wire=new Wire {Response=response}; var error=Assert.Throws<AppGuardException>(()=>new Client(wire).PublicKey("a")); Assert.That(error.Message, Is.EqualTo("APPGUARD_OPERATION_FAILED")); Assert.That(error.InnerException, Is.Null); }
    [Test] public void NativeExceptionsAreRedacted() { Assert.That(Assert.Throws<AppGuardException>(()=>new Client(new Broken()).PublicKey("a")).Message, Is.EqualTo("APPGUARD_OPERATION_FAILED")); }
    [Test] public void UnsupportedEditorIsExplicit() { Assert.That(Assert.Throws<AppGuardException>(()=>new Client().PublicKey("a")).Code, Is.EqualTo("APPGUARD_UNSUPPORTED")); }
    [Test] public void NullTransportIsRejected() { Assert.That(Assert.Throws<AppGuardException>(()=>new Client(null)).Code, Is.EqualTo("APPGUARD_NATIVE_UNAVAILABLE")); }
    [Test] public void OversizedBodyRejectedBeforeNativeAccess() { var wire=new Wire(); Assert.That(Assert.Throws<AppGuardException>(()=>new Client(wire).Prepare(new PrepareRequest {Body=new byte[1048577]})).Code, Is.EqualTo("APPGUARD_INVALID_INPUT")); Assert.That(wire.Operation, Is.Null); }
    [Test] public void ResponseBufferIsReleasedOnSuccessAndDecodeFailure() {
        var pointer=Marshal.AllocCoTaskMem(6); Marshal.Copy(new byte[]{104,101,108,108,111,0},0,pointer,6); int frees=0;
        Assert.That(NativeResponse.Consume(pointer, p=>{frees++; Marshal.FreeCoTaskMem(p);}),Is.EqualTo("hello")); Assert.That(frees,Is.EqualTo(1));
        pointer=Marshal.AllocCoTaskMem(NativeResponse.MaxBytes+1); for(int i=0;i<=NativeResponse.MaxBytes;i++) Marshal.WriteByte(pointer,i,65);
        Assert.Throws<AppGuardException>(()=>NativeResponse.Consume(pointer,p=>{frees++; Marshal.FreeCoTaskMem(p);})); Assert.That(frees,Is.EqualTo(2));
    }
    [Test] public void NullResponsePointerFailsWithoutFree() { Assert.Throws<AppGuardException>(()=>NativeResponse.Consume(IntPtr.Zero,p=>Assert.Fail("free null"))); }
}}
