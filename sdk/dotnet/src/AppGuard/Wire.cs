using System.Globalization;
using System.Text.RegularExpressions;
namespace AppGuard;
/// <summary>Strict one-label, exact component/parameter-order wire parser, not a general RFC 9421 parser.</summary>
public static class Wire
{
    static readonly Regex Input=new("\\Aappguard=\\("+Regex.Escape(Profile.Covered)+"\\);created=(0|-?[1-9][0-9]{0,14});expires=(0|-?[1-9][0-9]{0,14});nonce=\"([A-Za-z0-9_-]{22})\";keyid=\"([A-Za-z0-9._:-]{1,128})\";alg=\"([A-Za-z0-9._:-]{1,64})\";tag=\"([A-Za-z0-9._:-]{1,64})\"\\z",RegexOptions.CultureInvariant|RegexOptions.NonBacktracking);
    public static SignatureEnvelope Parse(IEnumerable<HeaderPair> headers)
    {
        var h=Framing(headers,null);var input=Input.Match(h.GetValueOrDefault("signature-input", ""));var signature=Regex.Match(h.GetValueOrDefault("signature",""),@"\Aappguard=:([A-Za-z0-9+/]{86}==):\z",RegexOptions.CultureInvariant);
        if(!input.Success||!signature.Success)throw new AppGuardException("INVALID_REQUEST");
        var b64=signature.Groups[1].Value;var bytes=Convert.FromBase64String(b64);if(bytes.Length!=64||Convert.ToBase64String(bytes)!=b64)throw new AppGuardException("INVALID_REQUEST");
        var p=new SignatureParameters(long.Parse(input.Groups[1].Value,CultureInfo.InvariantCulture),long.Parse(input.Groups[2].Value,CultureInfo.InvariantCulture),input.Groups[3].Value,input.Groups[4].Value,input.Groups[5].Value,input.Groups[6].Value);
        if(p.Algorithm!=Profile.Algorithm||p.Tag!=Profile.Tag)throw new AppGuardException("UNSUPPORTED_PROFILE");
        return new(p,bytes);
    }
    public static void ValidateFraming(IEnumerable<HeaderPair> headers,int? bodyLength=null)=>Framing(headers,bodyLength);
    static Dictionary<string,string> Framing(IEnumerable<HeaderPair> headers,int? bodyLength)
    {
        var h=Validation.Headers(headers,true);bool cl=h.TryGetValue("content-length",out var length),te=h.TryGetValue("transfer-encoding",out var encoding);
        if(cl&&te||te&&encoding!="chunked"||h.TryGetValue("content-encoding",out var ce)&&ce!="identity"||bodyLength<0||bodyLength>Profile.MaxBodyBytes)throw new AppGuardException("INVALID_REQUEST");
        if(cl)
        {
            if(!Regex.IsMatch(length!,@"\A(?:0|[1-9][0-9]*)\z",RegexOptions.CultureInvariant))throw new AppGuardException("INVALID_REQUEST");
            if(length!.Length>7||!int.TryParse(length,NumberStyles.None,CultureInfo.InvariantCulture,out int n)||n>Profile.MaxBodyBytes)throw new AppGuardException("INVALID_REQUEST",413);
            if(bodyLength is not null&&n!=bodyLength)throw new AppGuardException("INVALID_REQUEST");
        }
        return h;
    }
}
