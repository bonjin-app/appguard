using System.Collections.ObjectModel;
using System.Globalization;

namespace AppGuard;

/// <summary>A fixed, redacted protocol failure. Never includes the failed input or inner exception.</summary>
public sealed class AppGuardException : Exception
{
    static readonly HashSet<string> Codes=["INVALID_REQUEST","UNSUPPORTED_PROFILE","INVALID_TIME","KEY_REJECTED","DIGEST_MISMATCH","INVALID_SIGNATURE","REPLAY_DETECTED","REPLAY_STORE_UNAVAILABLE","AUTHENTICATION_REQUIRED","IDENTITY_UNAVAILABLE","KEY_RESOLVER_UNAVAILABLE","VERIFICATION_UNAVAILABLE"];
    public string Code { get; }
    public int StatusCode { get; }
    public AppGuardException(string code,int? statusCode=null):base(Codes.Contains(code)?code:"INVALID_REQUEST")
    {
        Code=Message;
        StatusCode=Code switch { "INVALID_REQUEST"=>statusCode==413?413:400,"AUTHENTICATION_REQUIRED"=>401,"IDENTITY_UNAVAILABLE" or "KEY_RESOLVER_UNAVAILABLE" or "VERIFICATION_UNAVAILABLE" or "REPLAY_STORE_UNAVAILABLE"=>503,_=>403 };
    }
}
public readonly record struct HeaderPair(string Name,string Value);

/// <summary>Copies bounded exact request evidence. Never construct target from a decoded URI.</summary>
public sealed class RequestData
{
    readonly byte[] _body;
    public string Method { get; }
    public string Target { get; }
    public IReadOnlyList<HeaderPair> Headers { get; }
    public ReadOnlyMemory<byte> Body => _body.ToArray();
    internal ReadOnlySpan<byte> BodySpan => _body;
    public RequestData(string method,string target,IEnumerable<HeaderPair> headers,byte[] body)
    {
        if(body is null || body.Length>Profile.MaxBodyBytes || headers is null)throw new AppGuardException("INVALID_REQUEST");
        Method=method;Target=target;
        var copy=new List<HeaderPair>();foreach(var h in headers){if(copy.Count==64)throw new AppGuardException("INVALID_REQUEST");copy.Add(h);}
        Headers=new ReadOnlyCollection<HeaderPair>(copy);_body=body.ToArray();
        Validation.Request(this);
    }
}

/// <summary>Structurally validated metadata; core verification applies timestamp domain and profile/time rules.</summary>
public sealed record SignatureParameters
{
    public long Created { get; }
    public long Expires { get; }
    public string Nonce { get; }
    public string KeyId { get; }
    public string Algorithm { get; }
    public string Tag { get; }
    public SignatureParameters(long created,long expires,string nonce,string keyId,string algorithm=Profile.Algorithm,string tag=Profile.Tag)
    {
        Validation.Identifier(keyId);Validation.Nonce(nonce);
        if(!Validation.IsIdentifier(algorithm,64)||!Validation.IsIdentifier(tag,64))throw new AppGuardException("INVALID_REQUEST");
        Created=created;Expires=expires;Nonce=nonce;KeyId=keyId;Algorithm=algorithm;Tag=tag;
    }
    public string Serialize()=>$"({Profile.Covered});created={Created.ToString(CultureInfo.InvariantCulture)};expires={Expires.ToString(CultureInfo.InvariantCulture)};nonce=\"{Nonce}\";keyid=\"{KeyId}\";alg=\"{Algorithm}\";tag=\"{Tag}\"";
}

/// <summary>Trusted enrollment lookup result; optional NotAfter is a trusted record expiry (exclusive).</summary>
public sealed record KeyRecord
{
    public string AppId{get;} public string KeyId{get;} public string Subject{get;} public string PublicKeyPem{get;} public bool Revoked{get;} public string Algorithm{get;} public long? NotAfter{get;}
    public KeyRecord(string appId,string keyId,string subject,string publicKeyPem,bool revoked=false,string algorithm=Profile.Algorithm,long? notAfter=null)
    {
        if(!Validation.IsIdentifier(appId)||!Validation.IsIdentifier(keyId)||!Validation.IsIdentifier(subject)||publicKeyPem is null || System.Text.Encoding.UTF8.GetByteCount(publicKeyPem)>4096 || publicKeyPem.Length==0 || !Validation.IsIdentifier(algorithm,64) || notAfter is not null&&!Validation.IsTime(notAfter.Value))throw new AppGuardException("KEY_REJECTED");
        AppId=appId;KeyId=keyId;Subject=subject;PublicKeyPem=publicKeyPem;Revoked=revoked;Algorithm=algorithm;NotAfter=notAfter;
    }
}
public sealed class VerificationContext
{
    public string Origin{get;}public string AppId{get;}public string Subject{get;}public KeyRecord? Key{get;}public long Now{get;}public IReplayStore Replay{get;}
    public VerificationContext(string origin,string appId,string subject,KeyRecord? key,long now,IReplayStore replay)
    {
        Validation.Origin(origin);Validation.Identifier(appId);Validation.Identifier(subject);
        Origin=origin;AppId=appId;Subject=subject;Key=key;Now=now;Replay=replay??throw new AppGuardException("REPLAY_STORE_UNAVAILABLE");
    }
}
/// <summary>Request proof only; does not establish authentication, authorization or platform attestation.</summary>
public sealed record VerificationResult
{
    public string AppId{get;}public string KeyId{get;}public long Expires{get;}public string Code=>"VERIFIED";
    internal VerificationResult(string appId,string keyId,long expires){AppId=appId;KeyId=keyId;Expires=expires;}
}
public sealed class SignatureEnvelope
{
    readonly byte[] _signature;
    public SignatureParameters Parameters{get;}
    public ReadOnlyMemory<byte> Signature=>_signature.ToArray();
    internal SignatureEnvelope(SignatureParameters parameters,byte[] signature){Parameters=parameters;_signature=signature.ToArray();}
}
public static class Profile
{
    public const string Algorithm="ecdsa-p256-sha256";
    public const string Tag="appguard-request-v0";
    public const int MaxBodyBytes=1048576;
    public const long MaxTime=999999999999999;
    public const string Covered="\"@method\" \"@target-uri\" \"content-type\" \"content-digest\" \"authorization\" \"appguard-app-id\"";
    internal static readonly string[] Components=["@method","@target-uri","content-type","content-digest","authorization","appguard-app-id"];
}
