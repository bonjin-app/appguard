using System.Text;
using System.Text.Json;
using AppGuard;
using Xunit;

namespace AppGuard.Tests;

public class CorpusTests
{
    public static IEnumerable<object[]> Requests() => Cases("requests");
    public static IEnumerable<object[]> Http() => Cases("http");
    public static IEnumerable<object[]> Policies() => Cases("policy").Concat(Cases("local-risk-policy"));
    static IEnumerable<object[]> Cases(string name) => JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "corpus", name + ".json"))).RootElement.EnumerateArray().Select(v => new object[] { v.GetProperty("id").GetString()!, v.Clone() }).ToArray();
    internal static string S(JsonElement o, string key) => o.GetProperty(key).GetString()!;
    internal static string S(JsonElement o, string key, string fallback) => o.TryGetProperty(key, out var v) ? v.GetString()! : fallback;
    internal static HeaderPair[] Headers(JsonElement h) => h.EnumerateArray().Select(p => new HeaderPair(p[0].GetString()!, p[1].GetString()!)).ToArray();
    internal static SignatureParameters Parameters(JsonElement p) => new(p.GetProperty("created").GetInt64(), p.GetProperty("expires").GetInt64(), S(p,"nonce"), S(p,"key_id"), S(p,"algorithm"), S(p,"tag"));
    internal static KeyRecord Key(JsonElement k) => new(S(k,"app_id"), S(k,"key_id"), S(k,"subject"), S(k,"public_key_pem"), k.GetProperty("revoked").GetBoolean(), S(k,"algorithm"));
    internal static RequestData Request(JsonElement r) => new(S(r,"method"), S(r,"target"), Headers(r.GetProperty("headers")), Convert.FromBase64String(S(r,"body_b64")));
    internal static async Task<string> Code(Func<ValueTask<VerificationResult>> action) { try { return (await action()).Code; } catch(AppGuardException e) { return e.Code; } }

    [Theory, MemberData(nameof(Requests))]
    public async Task RequestCorpus(string id, JsonElement v)
    {
        IReplayStore store = S(v,"replay_store") == "memory" ? new InMemoryReplayStore() : new UnavailableStore();
        var c = v.GetProperty("context");
        foreach(var expected in v.GetProperty("expected_codes").EnumerateArray())
        {
            var actual = await Code(() => Verifier.VerifyAsync(Request(v.GetProperty("request")), Parameters(v.GetProperty("parameters")), Convert.FromBase64String(S(v,"signature_b64")), new VerificationContext(S(c,"origin"), S(c,"app_id"), S(c,"subject"), Key(v.GetProperty("key")), c.GetProperty("now").GetInt64(), store)));
            Assert.True(expected.GetString() == actual, $"{id}: expected {expected.GetString()}, got {actual}");
        }
        if(v.TryGetProperty("expected_signature_base", out var b) && v.GetProperty("expected_codes")[0].GetString() == "VERIFIED")
            Assert.Equal(b.GetString(), Encoding.ASCII.GetString(Verifier.BuildSignatureBase(Request(v.GetProperty("request")), Parameters(v.GetProperty("parameters")), S(c,"origin"))));
    }

    [Theory, MemberData(nameof(Http))]
    public void HttpCorpus(string id, JsonElement v)
    {
        var actual = "PARSED";
        try
        {
            var e = Wire.Parse(Headers(v.GetProperty("headers")));
            if(v.TryGetProperty("expected", out var expected))
            {
                Assert.Equal(Parameters(expected.GetProperty("parameters")), e.Parameters);
                Assert.Equal(S(expected,"signature_b64"), Convert.ToBase64String(e.Signature.Span));
            }
        }
        catch(AppGuardException e) { actual = e.Code; }
        Assert.True(S(v,"expected_code") == actual, $"{id}: expected {S(v,"expected_code")}, got {actual}");
    }

    [Theory, MemberData(nameof(Policies))]
    public void PolicyCorpus(string id, JsonElement v)
    {
        var p=v.GetProperty("policy");var c=v.GetProperty("context"); var expected=v.GetProperty("expected");
        var policy=new Policy(S(p,"profile"), !p.TryGetProperty("require_signature",out var rs) || rs.GetBoolean(),p.TryGetProperty("suspicious_signals",out var hints)?hints.EnumerateArray().Select(x=>x.GetString()!).ToArray():null);
        var context=new PolicyContext(S(c,"authentication","missing"),S(c,"verification","missing"),S(c,"attestation","missing"),c.TryGetProperty("attestation_expires",out var ex) && ex.ValueKind!=JsonValueKind.Null ? ex.GetInt64():null,c.TryGetProperty("risk_signals",out var r)?r.EnumerateArray().Select(x=>x.GetString()!).ToArray():[],c.TryGetProperty("rate_limited",out var rl)&&rl.GetBoolean());
        var decision=PolicyEngine.Evaluate(policy,context,v.GetProperty("now").GetInt64());
        Assert.True(decision == new PolicyDecision(S(expected,"action"),S(expected,"code"),S(expected,"profile")), id);
    }
    internal sealed class UnavailableStore : IReplayStore { public ValueTask<bool> ClaimAsync(ReplayScope scope,long expires,long now,CancellationToken cancellationToken=default) => throw new IOException("SECRET backend details"); }
}
