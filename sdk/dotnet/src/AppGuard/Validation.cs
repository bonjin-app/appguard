using System.Globalization;
using System.Text.RegularExpressions;
namespace AppGuard;
internal static class Validation
{
    static bool Match(string? value,string pattern)=>value is not null && Regex.IsMatch(value,"\\A(?:"+pattern+")\\z",RegexOptions.CultureInvariant|RegexOptions.NonBacktracking);
    const string Token="[!#$%&'*+.^_`|~0-9A-Za-z-]+";
    static readonly HashSet<string> CoreSingletons=["content-type","content-digest","authorization","appguard-app-id","content-encoding"];
    internal static readonly HashSet<string> WireSingletons=[..CoreSingletons,"signature-input","signature","content-length","transfer-encoding","host"];
    internal static bool IsTime(long value)=>value>=0&&value<=Profile.MaxTime;
    internal static bool IsIdentifier(string? value,int max=128)=>value is not null&&value.Length>=1&&value.Length<=max&&Match(value,"[A-Za-z0-9._:-]+");
    internal static void Identifier(string value){if(!IsIdentifier(value))throw new AppGuardException("INVALID_REQUEST");}
    internal static void Nonce(string nonce)
    {
        if(!Match(nonce,"[A-Za-z0-9_-]{22}"))throw new AppGuardException("INVALID_REQUEST");
        try{if(Convert.ToBase64String(Convert.FromBase64String(nonce.Replace('-','+').Replace('_','/')+"==")).TrimEnd('=').Replace('+','-').Replace('/','_')!=nonce)throw new FormatException();}
        catch(FormatException){throw new AppGuardException("INVALID_REQUEST");}
    }
    internal static void Origin(string origin)
    {
        if(origin is null||origin.Length>512)throw new AppGuardException("INVALID_REQUEST");
        var m=Regex.Match(origin,@"\Ahttps://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?\z",RegexOptions.CultureInvariant);
        if(!m.Success||m.Groups[1].Length>253||m.Groups[1].Value.Split('.').Any(l=>!Match(l,"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))||m.Groups[2].Success&&(int.Parse(m.Groups[2].Value,CultureInfo.InvariantCulture)>65535||m.Groups[2].Value=="443"))throw new AppGuardException("INVALID_REQUEST");
    }
    static void Target(string target)
    {
        if(target is null||target.Length>8192||target.StartsWith("//",StringComparison.Ordinal)||!Match(target,@"/[A-Za-z0-9._~!$&'()*+,;=:@/?%\-]*")||Regex.IsMatch(target,@"%(?![0-9A-Fa-f]{2})"))throw new AppGuardException("INVALID_REQUEST");
        var decoded=Regex.Replace(target,@"%([0-9A-Fa-f]{2})",m=>((char)int.Parse(m.Groups[1].Value,NumberStyles.HexNumber,CultureInfo.InvariantCulture)).ToString());
        var path=target.Split('?',2)[0];var decodedPath=Regex.Replace(path,@"%([0-9A-Fa-f]{2})",m=>((char)int.Parse(m.Groups[1].Value,NumberStyles.HexNumber,CultureInfo.InvariantCulture)).ToString());
        if(decoded.Any(c=>c<32||c==127||c=='\\')||decodedPath.Split('/').Any(s=>s=="."||s==".."))throw new AppGuardException("INVALID_REQUEST");
    }
    internal static Dictionary<string,string> Headers(IEnumerable<HeaderPair> headers,bool wire=false)
    {
        if(headers is null)throw new AppGuardException("INVALID_REQUEST");
        var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);int count=0,size=0;var singletons=wire?WireSingletons:CoreSingletons;
        foreach(var p in headers)
        {
            if(++count>64||p.Name is null||p.Value is null||p.Name.Length>16384||p.Value.Length>16384||!Match(p.Name,Token)||p.Value.Any(c=>c<32||c>126)||p.Value.StartsWith(' ')||p.Value.EndsWith(' '))throw new AppGuardException("INVALID_REQUEST");
            size+=p.Name.Length+p.Value.Length;if(size>16384||singletons.Contains(p.Name.ToLowerInvariant())&&result.ContainsKey(p.Name))throw new AppGuardException("INVALID_REQUEST");result[p.Name]=p.Value;
        }
        return result;
    }
    internal static byte[] Digest(string value)
    {
        if(!Match(value,"sha-256=:[A-Za-z0-9+/]{43}=:") )throw new AppGuardException("INVALID_REQUEST");
        var b64=value[9..^1];var bytes=Convert.FromBase64String(b64);if(bytes.Length!=32||Convert.ToBase64String(bytes)!=b64)throw new AppGuardException("INVALID_REQUEST");return bytes;
    }
    internal static Dictionary<string,string> Request(RequestData request)
    {
        if(request is null||request.Method is null||request.Method.Length>32||request.Method.ToUpperInvariant()!=request.Method||!Match(request.Method,Token))throw new AppGuardException("INVALID_REQUEST");
        Target(request.Target);var h=Headers(request.Headers);
        if(Profile.Components.Skip(2).Any(n=>!h.ContainsKey(n))||h["content-type"].Length==0||h.TryGetValue("content-encoding",out var enc)&&enc!="identity"||!Regex.IsMatch(h["authorization"],@"\ABearer [A-Za-z0-9._~+/-]+=*\z",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant))throw new AppGuardException("INVALID_REQUEST");
        Identifier(h["appguard-app-id"]);Digest(h["content-digest"]);return h;
    }
    internal static void Parameters(SignatureParameters p)
    {
        if(p is null)throw new AppGuardException("INVALID_REQUEST");
        if(p.Algorithm!=Profile.Algorithm||p.Tag!=Profile.Tag)throw new AppGuardException("UNSUPPORTED_PROFILE");
        if(!IsTime(p.Created)||!IsTime(p.Expires))throw new AppGuardException("INVALID_TIME");
    }
}
