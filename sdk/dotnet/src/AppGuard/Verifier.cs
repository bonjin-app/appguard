using System.Security.Cryptography;
using System.Text;
namespace AppGuard;
public static class Verifier
{
    public static byte[] BuildSignatureBase(RequestData request,SignatureParameters parameters,string origin)
    {
        var h=Validation.Request(request);Validation.Origin(origin);Validation.Parameters(parameters);
        var values=new[]{request.Method,origin+request.Target,h["content-type"],h["content-digest"],h["authorization"],h["appguard-app-id"]};
        return Encoding.ASCII.GetBytes(string.Join('\n',Profile.Components.Select((name,i)=>$"\"{name}\": {values[i]}").Append("\"@signature-params\": "+parameters.Serialize())));
    }
    public static async ValueTask<VerificationResult> VerifyAsync(RequestData request,SignatureParameters parameters,ReadOnlyMemory<byte> signature,VerificationContext context,CancellationToken cancellationToken=default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if(context is null)throw new AppGuardException("INVALID_REQUEST");
        var signatureBase=BuildSignatureBase(request,parameters,context.Origin);var now=context.Now;
        if(!Validation.IsTime(now)||parameters.Created>=parameters.Expires||parameters.Expires-parameters.Created>120||parameters.Created>now+30||now>=parameters.Expires)throw new AppGuardException("INVALID_TIME");
        var key=context.Key;var signedApp=request.Headers.First(h=>h.Name.Equals("appguard-app-id",StringComparison.OrdinalIgnoreCase)).Value;
        if(key is null||key.Revoked||key.AppId!=context.AppId||signedApp!=context.AppId||key.Subject!=context.Subject||key.KeyId!=parameters.KeyId||key.Algorithm!=Profile.Algorithm||key.NotAfter is not null&&now>=key.NotAfter)throw new AppGuardException("KEY_REJECTED");
        using var publicKey=LoadKey(key.PublicKeyPem);
        if(!CryptographicOperations.FixedTimeEquals(Validation.Digest(request.Headers.First(h=>h.Name.Equals("content-digest",StringComparison.OrdinalIgnoreCase)).Value),SHA256.HashData(request.BodySpan)))throw new AppGuardException("DIGEST_MISMATCH");
        if(signature.Length!=64)throw new AppGuardException("INVALID_SIGNATURE");
        bool valid;
        try{valid=publicKey.VerifyData(signatureBase,signature.Span,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation);}catch(CryptographicException){valid=false;}
        if(!valid)throw new AppGuardException("INVALID_SIGNATURE");
        cancellationToken.ThrowIfCancellationRequested();bool claimed;
        try{claimed=await context.Replay.ClaimAsync(new ReplayScope(context.AppId,key.KeyId,parameters.Nonce),parameters.Expires,now,cancellationToken).ConfigureAwait(false);}
        catch(Exception){throw new AppGuardException("REPLAY_STORE_UNAVAILABLE");}
        if(!claimed)throw new AppGuardException("REPLAY_DETECTED");
        return new(context.AppId,key.KeyId,parameters.Expires);
    }
    static ECDsa LoadKey(string pem)
    {
        ECDsa? key=null;
        try
        {
            if(!pem.StartsWith("-----BEGIN PUBLIC KEY-----",StringComparison.Ordinal)||!PemEncoding.TryFind(pem,out var fields)||!pem.AsSpan()[fields.Label].SequenceEqual("PUBLIC KEY"))throw new CryptographicException();
            var (start,length)=fields.Location.GetOffsetAndLength(pem.Length);
            if(start!=0||pem.AsSpan()[(start+length)..].ToArray().Any(c=>c!='\r'&&c!='\n'))throw new CryptographicException();
            var der=Convert.FromBase64String(pem[fields.Base64Data]);key=ECDsa.Create();key.ImportSubjectPublicKeyInfo(der,out int consumed);
            if(consumed!=der.Length||key.KeySize!=256||key.ExportParameters(false).Curve.Oid.Value!="1.2.840.10045.3.1.7")throw new CryptographicException();
            return key;
        }
        catch(Exception){key?.Dispose();throw new AppGuardException("KEY_REJECTED");}
    }
}
