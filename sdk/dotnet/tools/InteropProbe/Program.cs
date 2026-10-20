using System.Text.Json;
using AppGuard;

// Trusted TEST fixture transport only. Never expose this console runner as a server endpoint.
if(args.Length!=1){Console.Error.WriteLine("usage: InteropProbe fixture.json");return 2;}
var bytes=File.ReadAllBytes(args[0]);if(bytes.Length>2*1024*1024)throw new InvalidDataException("fixture too large");
using var doc=JsonDocument.Parse(bytes);
var vectors=doc.RootElement.ValueKind==JsonValueKind.Array?doc.RootElement.EnumerateArray().ToArray():[doc.RootElement];
if(vectors.Length is <1 or >100)throw new InvalidDataException("invalid fixture count");
foreach(var v in vectors)
{
    string S(JsonElement e,string n)=>e.GetProperty(n).GetString()!;
    var r=v.GetProperty("request");var p=v.GetProperty("parameters");var k=v.GetProperty("key");var c=v.GetProperty("context");
    var request=new RequestData(S(r,"method"),S(r,"target"),r.GetProperty("headers").EnumerateArray().Select(h=>new HeaderPair(h[0].GetString()!,h[1].GetString()!)),Convert.FromBase64String(S(r,"body_b64")));
    var parameters=new SignatureParameters(p.GetProperty("created").GetInt64(),p.GetProperty("expires").GetInt64(),S(p,"nonce"),S(p,"key_id"),S(p,"algorithm"),S(p,"tag"));
    var key=new KeyRecord(S(k,"app_id"),S(k,"key_id"),S(k,"subject"),S(k,"public_key_pem"),k.GetProperty("revoked").GetBoolean(),S(k,"algorithm"));
    var signature=Convert.FromBase64String(S(v,"signature_b64"));var envelope=Wire.Parse(request.Headers);Wire.ValidateFraming(request.Headers,request.Body.Length);
    if(envelope.Parameters!=parameters||!envelope.Signature.Span.SequenceEqual(signature))throw new InvalidDataException("wire fixture mismatch");
    VerificationContext Context(IReplayStore replay)=>new(S(c,"origin"),S(c,"app_id"),S(c,"subject"),key,c.GetProperty("now").GetInt64(),replay);
    async Task<string> Code(Func<RequestData> input,IReplayStore replay)
    {
        try{return(await Verifier.VerifyAsync(input(),parameters,signature,Context(replay))).Code;}catch(AppGuardException e){return e.Code;}
    }
    void Check(string expected,string actual){if(expected!=actual)throw new InvalidDataException("unexpected verification code");}
    var store=new InMemoryReplayStore();Check("VERIFIED",await Code(()=>request,store));Check("REPLAY_DETECTED",await Code(()=>request,store));
    Func<RequestData>[] variants=[
        ()=>new(request.Method,request.Target,request.Headers,[..request.Body.Span,(byte)'!']),
        ()=>new(request.Method,"/different-target",request.Headers,request.Body.ToArray()),
        ()=>new(request.Method,request.Target,request.Headers.Select(h=>h.Name.Equals("authorization",StringComparison.OrdinalIgnoreCase)?new HeaderPair(h.Name,"Bearer OTHER_TOKEN"):h),request.Body.ToArray())
    ];
    foreach(var variant in variants)
    {
        var mutationStore=new InMemoryReplayStore();if(await Code(variant,mutationStore)=="VERIFIED")throw new InvalidDataException("mutation accepted");Check("VERIFIED",await Code(()=>request,mutationStore));
    }
    Console.WriteLine("DOTNET_NATIVE_CLIENT_VERIFIED_REPLAY_AND_MUTATIONS_REJECTED");
}
Console.WriteLine($"vectors={vectors.Length} failures=0");return 0;
