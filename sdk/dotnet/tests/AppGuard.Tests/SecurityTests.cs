using System.Security.Cryptography;
using System.Text;
using AppGuard;
using Xunit;

namespace AppGuard.Tests;

public class SecurityTests
{
    internal sealed class Signed : IDisposable
    {
        internal readonly ECDsa Ec=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal SignatureParameters Parameters { get; }=new(100,220,"AAECAwQFBgcICQoLDA0ODw","key");
        internal RequestData Request { get; }
        internal KeyRecord Key => new("app","key","subject",Ec.ExportSubjectPublicKeyInfoPem());
        internal Signed(string target="/encoded%2fpath?b=2&a=1", byte[]? body=null)
        {
            body??=Encoding.UTF8.GetBytes("{\"raw\": true}\n");
            Request=new("POST",target,[new("Content-Type","application/json"),new("Content-Digest","sha-256=:"+Convert.ToBase64String(SHA256.HashData(body))+":"),new("Authorization","Bearer TEST_ONLY_TOKEN"),new("AppGuard-App-Id","app")],body);
        }
        internal byte[] Signature => Ec.SignData(Verifier.BuildSignatureBase(Request,Parameters,"https://api.example.test"),HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        internal VerificationContext Context(IReplayStore? store=null,KeyRecord? key=null,long now=100) => new("https://api.example.test","app","subject",key??Key,now,store??new InMemoryReplayStore());
        internal HeaderPair[] WireHeaders => [..Request.Headers,new("Signature-Input","appguard="+Parameters.Serialize()),new("Signature","appguard=:"+Convert.ToBase64String(Signature)+":" )];
        public void Dispose()=>Ec.Dispose();
    }
    internal sealed class CountingStore : IReplayStore
    {
        internal int Count;internal bool Fail;
        public ValueTask<bool> ClaimAsync(ReplayScope scope,long expires,long now,CancellationToken cancellationToken=default) { Interlocked.Increment(ref Count);if(Fail)throw new Exception("secret");return ValueTask.FromResult(true); }
    }
    [Fact] public async Task IndependentRawP256SignatureAndReplay()
    {
        using var s=new Signed();var store=new InMemoryReplayStore();
        Assert.Equal("VERIFIED",(await Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store))).Code);
        Assert.Equal("REPLAY_DETECTED",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store))));
    }
    [Theory] [InlineData(0)] [InlineData(63)] [InlineData(65)] [InlineData(70)]
    public async Task ExactRaw64Required(int length)
    {
        using var s=new Signed();var store=new CountingStore();
        Assert.Equal("INVALID_SIGNATURE",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,new byte[length],s.Context(store))));Assert.Equal(0,store.Count);
    }
    [Fact] public async Task DerSignatureRejected()
    {
        using var s=new Signed();var sig=s.Ec.SignData(Verifier.BuildSignatureBase(s.Request,s.Parameters,"https://api.example.test"),HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence);
        Assert.Equal("INVALID_SIGNATURE",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,sig,s.Context())));
    }
    [Fact] public async Task WrongCurvePrivateKeyTrailingPemAndExpiryRejectedBeforeClaim()
    {
        using var s=new Signed();using var wrong=ECDsa.Create(ECCurve.NamedCurves.nistP384);var store=new CountingStore();
        foreach(var pem in new[]{wrong.ExportSubjectPublicKeyInfoPem(),s.Ec.ExportECPrivateKeyPem(),s.Key.PublicKeyPem+"junk",s.Key.PublicKeyPem+s.Key.PublicKeyPem,"bad pem"})
            Assert.Equal("KEY_REJECTED",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store,new KeyRecord("app","key","subject",pem)))));
        var expired=new KeyRecord("app","key","subject",s.Key.PublicKeyPem,notAfter:100);
        Assert.Equal("KEY_REJECTED",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store,expired))));Assert.Equal(0,store.Count);
    }
    [Fact] public async Task SyntaxTimeKeyDigestAndSignaturePrecedeReplay()
    {
        using var s=new Signed();var store=new CountingStore();
        var modified=new RequestData("POST",s.Request.Target,s.Request.Headers,"modified"u8.ToArray());
        Assert.Equal("DIGEST_MISMATCH",await CorpusTests.Code(()=>Verifier.VerifyAsync(modified,s.Parameters,s.Signature,s.Context(store))));
        Assert.Equal("INVALID_SIGNATURE",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,new byte[64],s.Context(store))));
        Assert.Equal("INVALID_TIME",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store,now:220))));
        Assert.Equal(0,store.Count);
    }
    [Fact] public async Task ReplayStoreExceptionsAreRedactedAndFailClosed()
    {
        using var s=new Signed();var store=new CountingStore{Fail=true};
        var e=await Assert.ThrowsAsync<AppGuardException>(async()=>await Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store)));
        Assert.Equal("REPLAY_STORE_UNAVAILABLE",e.Code);Assert.Equal(e.Code,e.Message);Assert.Null(e.InnerException);
    }
    [Fact] public async Task AtomicReplayRaceAcceptsExactlyOnce()
    {
        var store=new InMemoryReplayStore();var scope=new ReplayScope("app","key","AAECAwQFBgcICQoLDA0ODw");
        var results=await Task.WhenAll(Enumerable.Range(0,100).Select(_=>Task.Run(async()=>await store.ClaimAsync(scope,220,100))));Assert.Equal(1,results.Count(x=>x));
    }
    [Fact] public async Task ReplayCapacityExpiryTtlScopeAndCancellation()
    {
        var store=new InMemoryReplayStore(1);var a=new ReplayScope("app","a","AAECAwQFBgcICQoLDA0ODw");var b=new ReplayScope("app","b","AAECAwQFBgcICQoLDA0ODw");
        Assert.True(await store.ClaimAsync(a,220,100));Assert.False(await store.ClaimAsync(a,220,100));
        Assert.Equal("REPLAY_STORE_UNAVAILABLE",(await Assert.ThrowsAsync<AppGuardException>(async()=>await store.ClaimAsync(b,220,100))).Code);
        Assert.True(await store.ClaimAsync(b,230,220));
        await Assert.ThrowsAsync<AppGuardException>(async()=>await store.ClaimAsync(a,400,220));
        await Assert.ThrowsAsync<OperationCanceledException>(async()=>await store.ClaimAsync(a,240,230,new CancellationToken(true)));
        Assert.True(await store.ClaimAsync(a,240,230));
        Assert.Throws<AppGuardException>(()=>new ReplayScope("bad value","key","AAECAwQFBgcICQoLDA0ODw"));
    }
    [Theory] [InlineData(-1)] [InlineData(1000000000000000)]
    public async Task InvalidIntegerDomainRejectsWithoutNonce(long now)
    {
        using var s=new Signed();var store=new CountingStore();
        Assert.Equal("INVALID_TIME",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store,now:now))));Assert.Equal(0,store.Count);
    }
    [Theory] [InlineData("//evil/a")] [InlineData("/a/../b")] [InlineData("/a/%2E%2e/b")] [InlineData("/a%5cb")] [InlineData("/a%00")] [InlineData("/a#fragment")] [InlineData("/bad%")]
    public void InvalidTargetsReject(string target)=>Assert.Throws<AppGuardException>(()=>new RequestData("GET",target,[],[]));
    [Fact] public void AllResourceLimitsAndCanonicalFramingReject()
    {
        using var s=new Signed();
        Assert.Throws<AppGuardException>(()=>new RequestData("POST","/",s.Request.Headers,new byte[1048577]));
        Assert.Throws<AppGuardException>(()=>new RequestData("POST","/"+new string('a',8192),s.Request.Headers,[]));
        Assert.Throws<AppGuardException>(()=>new RequestData("post","/",s.Request.Headers,[]));
        Assert.Throws<AppGuardException>(()=>new RequestData("GET","/",Enumerable.Repeat(new HeaderPair("x","a"),65),[]));
        Assert.Throws<AppGuardException>(()=>new RequestData("GET","/",[new("x",new string('a',16384))],[]));
        Assert.Throws<AppGuardException>(()=>Wire.ValidateFraming([..s.WireHeaders,new("Content-Length","1")],2));
        Assert.Throws<AppGuardException>(()=>new VerificationContext("https://api.example.test:443","app","subject",s.Key,100,new InMemoryReplayStore()));
        Assert.Throws<AppGuardException>(()=>new VerificationContext("https://API.example.test","app","subject",s.Key,100,new InMemoryReplayStore()));
    }
    [Fact] public void DefensiveCopiesProtectRequestAndEnvelope()
    {
        using var s=new Signed();var body=s.Request.Body.ToArray();var headers=s.Request.Headers.ToArray();var r=new RequestData("POST",s.Request.Target,headers,body);body[0]=0;headers[0]=new("Content-Type","evil");
        Assert.NotEqual((byte)0,r.Body.Span[0]);Assert.Equal("application/json",r.Headers[0].Value);
        var bytes=r.Body;System.Runtime.InteropServices.MemoryMarshal.TryGetArray(bytes,out var backing);backing.Array![backing.Offset]=0;Assert.NotEqual((byte)0,r.Body.Span[0]);
        var envelope=Wire.Parse(s.WireHeaders);var sig=envelope.Signature;System.Runtime.InteropServices.MemoryMarshal.TryGetArray(sig,out backing);backing.Array![backing.Offset]^=255;Assert.NotEqual(sig.Span[0],envelope.Signature.Span[0]);
    }
    [Fact] public void PolicyDefaultMissingAuthAndInvalidStatesAreFailClosed()
    {
        Assert.Equal("AUTHENTICATION_REQUIRED",PolicyEngine.Evaluate(new Policy(),new PolicyContext(),100).Code);
        Assert.Throws<PolicyException>(()=>new Policy("balanced",false));Assert.Throws<PolicyException>(()=>new PolicyContext(authentication:"client"));
        Assert.Throws<PolicyException>(()=>new PolicyContext(riskSignals:["root","root"]));Assert.Throws<PolicyException>(()=>new PolicyContext(riskSignals:Enumerable.Range(0,33).Select(i=>"r"+i)));
        Assert.Throws<PolicyException>(()=>new PolicyDecision("allow","AUTHENTICATION_REQUIRED","basic"));
    }
    [Fact] public async Task NullInputsWrongTypesAndInvalidTimestampsCannotReachReplay()
    {
        using var s=new Signed();var store=new CountingStore();
        Assert.Throws<AppGuardException>(()=>new RequestData("POST","/",null!,[]));
        Assert.Throws<AppGuardException>(()=>new RequestData("POST","/",[default],[]));
        Assert.Throws<AppGuardException>(()=>new RequestData("POST","/",s.Request.Headers,null!));
        Assert.Throws<AppGuardException>(()=>new KeyRecord("app","key","subject",null!));
        Assert.Throws<ArgumentNullException>(()=>new AppGuard.AspNetCore.AppGuardOptions("app","https://api.example.test",store,null!,(_,_,_,_)=>ValueTask.FromResult<KeyRecord?>(s.Key)));
        foreach(var value in new[]{-1L,1000000000000000L})
        {
            var p=new SignatureParameters(value,220,s.Parameters.Nonce,"key");
            Assert.Equal("INVALID_TIME",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,p,s.Signature,s.Context(store))));
        }
        Assert.Throws<PolicyException>(()=>new PolicyContext(attestationExpires:-1));Assert.Throws<PolicyException>(()=>PolicyEngine.Evaluate(new Policy(),new PolicyContext(),-1));
        Assert.Throws<AuditException>(()=>new AuditEvent(new PolicyDecision("allow","ALLOWED","basic"),"bad event","app",100));
        Assert.Equal(0,store.Count);
    }
    [Fact] public async Task AlternateValidEcdsaSignatureSharesNonceAndStorageKeyIsPortable()
    {
        using var s=new Signed();var signature=s.Signature;var alternate=signature.ToArray();
        var order=System.Numerics.BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",System.Globalization.NumberStyles.HexNumber);
        var scalar=new System.Numerics.BigInteger(signature.AsSpan(32),isUnsigned:true,isBigEndian:true);var high=(order-scalar).ToByteArray(isUnsigned:true,isBigEndian:true);alternate.AsSpan(32).Clear();high.CopyTo(alternate.AsSpan(64-high.Length));
        var store=new InMemoryReplayStore();Assert.Equal("VERIFIED",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,signature,s.Context(store))));
        Assert.Equal("REPLAY_DETECTED",await CorpusTests.Code(()=>Verifier.VerifyAsync(s.Request,s.Parameters,alternate,s.Context(store))));
        Assert.Equal("appguard:v0:replay:1a3a9e8f54a1f78b7dd93d4bb4bbd47ac0767b406779f6dfb309b40b6eb97ab2",new ReplayScope("app","key",s.Parameters.Nonce).StorageKey);
    }
    [Fact] public async Task AuditAllowlistAndSinkErrorRedaction()
    {
        var context=new PolicyContext("authenticated","verified","verified",101,["root"]);var decision=PolicyEngine.Evaluate(new Policy(),context,100);string? output=null;
        await new JsonAuditSink((json,_)=>{output=json;return ValueTask.CompletedTask;}).EmitAsync(decision,"opaque-event","app",100,context);
        using var doc=System.Text.Json.JsonDocument.Parse(output!);var names=doc.RootElement.EnumerateObject().Select(x=>x.Name).Order().ToArray();
        Assert.Equal(new[]{"schema_version","event_id","app_id","at","action","code","profile","risk_count","attestation_state"}.Order(),names);
        Assert.DoesNotContain("root",output!);Assert.DoesNotContain("subject",output!);
        var e=await Assert.ThrowsAsync<AuditUnavailableException>(async()=>await new JsonAuditSink((_,_)=>throw new Exception("SECRET provider data")).EmitAsync(decision,"opaque-event","app",100));
        Assert.Equal("AUDIT_UNAVAILABLE",e.Message);Assert.Null(e.InnerException);
    }
}
