using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
namespace AppGuard.AspNetCore;

/// <summary>All identity/key/store dependencies are explicit; no local store or token acceptance is installed.</summary>
public sealed class AppGuardOptions
{
    internal string AppId{get;}internal string Origin{get;}internal IReplayStore Replay{get;}
    internal Func<HttpContext,CancellationToken,ValueTask<string?>> Authenticate{get;}
    internal Func<HttpContext,string,SignatureParameters,CancellationToken,ValueTask<KeyRecord?>> ResolveKey{get;}
    internal Func<long> Clock{get;}internal bool AllowInsecureTransport{get;}
    public AppGuardOptions(string appId,string origin,IReplayStore replay,Func<HttpContext,CancellationToken,ValueTask<string?>> authenticate,Func<HttpContext,string,SignatureParameters,CancellationToken,ValueTask<KeyRecord?>> resolveKey,Func<long>? clock=null,bool allowInsecureTransport=false)
    {
        Validation.Identifier(appId);Validation.Origin(origin);
        AppId=appId;Origin=origin;Replay=replay??throw new ArgumentNullException(nameof(replay));Authenticate=authenticate??throw new ArgumentNullException(nameof(authenticate));ResolveKey=resolveKey??throw new ArgumentNullException(nameof(resolveKey));Clock=clock??(()=>DateTimeOffset.UtcNow.ToUnixTimeSeconds());AllowInsecureTransport=allowInsecureTransport;
    }
}
public interface IAppGuardVerificationFeature{VerificationResult Result{get;}}
sealed class AppGuardVerificationFeature(VerificationResult result):IAppGuardVerificationFeature{public VerificationResult Result{get;}=result;}
/// <summary>Install before body parsing/decompression/rewriting and after existing authentication that preserves raw input.</summary>
public sealed class AppGuardMiddleware
{
    readonly RequestDelegate _next;readonly AppGuardOptions _options;
    public AppGuardMiddleware(RequestDelegate next,AppGuardOptions options){_next=next??throw new ArgumentNullException(nameof(next));_options=options??throw new ArgumentNullException(nameof(options));}
    public async Task InvokeAsync(HttpContext context)
    {
        MemoryStream? captured=null;Stream? original=null;VerificationResult result;
        try
        {
            var raw=context.Features.Get<IHttpRequestFeature>();
            if(raw is null||string.IsNullOrEmpty(raw.RawTarget)||!_options.AllowInsecureTransport&&(!string.Equals(raw.Scheme,"https",StringComparison.OrdinalIgnoreCase)||context.Features.Get<ITlsConnectionFeature>() is null))throw new AppGuardException("INVALID_REQUEST");
            context.RequestAborted.ThrowIfCancellationRequested();
            var headers=new List<HeaderPair>();int size=0;
            foreach(var h in raw.Headers)
            {
                if(h.Value.Count==0)throw new AppGuardException("INVALID_REQUEST");
                foreach(var value in h.Value)
                {
                    if(value is null||headers.Count==64||h.Key.Length>16384||value.Length>16384||(size+=h.Key.Length+value.Length)>16384)throw new AppGuardException("INVALID_REQUEST");
                    headers.Add(new(h.Key,value));
                }
            }
            var envelope=Wire.Parse(headers);
            original=raw.Body;
            if(original is null||!original.CanRead||original.CanSeek&&original.Position!=0)throw new AppGuardException("INVALID_REQUEST");
            captured=new MemoryStream();var buffer=new byte[8192];int count;
            try
            {
                while((count=await original.ReadAsync(buffer.AsMemory(0,Math.Min(buffer.Length,Profile.MaxBodyBytes+1-(int)captured.Length)),context.RequestAborted).ConfigureAwait(false))!=0)
                {
                    await captured.WriteAsync(buffer.AsMemory(0,count),context.RequestAborted).ConfigureAwait(false);
                    if(captured.Length>Profile.MaxBodyBytes)throw new AppGuardException("INVALID_REQUEST",413);
                }
            }
            catch(AppGuardException){throw;}catch(Exception){throw new AppGuardException("INVALID_REQUEST");}
            Wire.ValidateFraming(headers,(int)captured.Length);
            var request=new RequestData(raw.Method,raw.RawTarget,headers,captured.ToArray());
            string? subject;
            try{subject=await _options.Authenticate(context,context.RequestAborted).ConfigureAwait(false);}
            catch(Exception){throw new AppGuardException("IDENTITY_UNAVAILABLE");}
            if(subject is null)throw new AppGuardException("AUTHENTICATION_REQUIRED");
            if(!Validation.IsIdentifier(subject))throw new AppGuardException("IDENTITY_UNAVAILABLE");
            KeyRecord? key;
            try{key=await _options.ResolveKey(context,subject,envelope.Parameters,context.RequestAborted).ConfigureAwait(false);}
            catch(Exception){throw new AppGuardException("KEY_RESOLVER_UNAVAILABLE");}
            long now;
            try{now=_options.Clock();}catch(Exception){throw new AppGuardException("VERIFICATION_UNAVAILABLE");}
            result=await Verifier.VerifyAsync(request,envelope.Parameters,envelope.Signature,new VerificationContext(_options.Origin,_options.AppId,subject,key,now,_options.Replay),context.RequestAborted).ConfigureAwait(false);
        }
        catch(AppGuardException e){captured?.Dispose();await Reject(context,e).ConfigureAwait(false);return;}
        catch(OperationCanceledException){captured?.Dispose();await Reject(context,new AppGuardException("INVALID_REQUEST")).ConfigureAwait(false);return;}
        catch(Exception){captured?.Dispose();await Reject(context,new AppGuardException("VERIFICATION_UNAVAILABLE")).ConfigureAwait(false);return;}
        context.Features.Set<IAppGuardVerificationFeature>(new AppGuardVerificationFeature(result));
        captured.Position=0;context.Request.Body=captured;
        try{await _next(context).ConfigureAwait(false);}
        finally{context.Request.Body=original!;await captured.DisposeAsync().ConfigureAwait(false);}
    }
    static async Task Reject(HttpContext context,AppGuardException error)
    {
        context.Response.StatusCode=error.StatusCode;context.Response.ContentType="application/json";
        if(!context.RequestAborted.IsCancellationRequested)await context.Response.WriteAsync("{\"code\":\""+error.Code+"\"}",context.RequestAborted).ConfigureAwait(false);
    }
}
public static class AppGuardExtensions
{
    public static IApplicationBuilder UseAppGuard(this IApplicationBuilder app,AppGuardOptions options)=>app.UseMiddleware<AppGuardMiddleware>(options);
}
