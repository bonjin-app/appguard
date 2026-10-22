using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using System.Diagnostics;
namespace AppGuard.AspNetCore;

/// <summary>All identity/key/store dependencies are explicit; no local store or token acceptance is installed.</summary>
public sealed class AppGuardOptions
{
    internal string AppId{get;}internal string Origin{get;}internal IReplayStore Replay{get;}
    internal Func<HttpContext,CancellationToken,ValueTask<string?>> Authenticate{get;}
    internal Func<HttpContext,string,SignatureParameters,CancellationToken,ValueTask<KeyRecord?>> ResolveKey{get;}
    internal Func<long> Clock{get;}internal bool AllowInsecureTransport{get;}internal TimeSpan BodyReadTimeout{get;}
    public AppGuardOptions(string appId,string origin,IReplayStore replay,Func<HttpContext,CancellationToken,ValueTask<string?>> authenticate,Func<HttpContext,string,SignatureParameters,CancellationToken,ValueTask<KeyRecord?>> resolveKey,Func<long>? clock=null,bool allowInsecureTransport=false)
        :this(appId,origin,replay,authenticate,resolveKey,TimeSpan.FromSeconds(30),clock,allowInsecureTransport){}
    /// <param name="bodyReadTimeout">Absolute body-capture deadline. Must be positive and at most five minutes.</param>
    public AppGuardOptions(string appId,string origin,IReplayStore replay,Func<HttpContext,CancellationToken,ValueTask<string?>> authenticate,Func<HttpContext,string,SignatureParameters,CancellationToken,ValueTask<KeyRecord?>> resolveKey,TimeSpan bodyReadTimeout,Func<long>? clock=null,bool allowInsecureTransport=false)
    {
        Validation.Identifier(appId);Validation.Origin(origin);
        if(bodyReadTimeout<=TimeSpan.Zero||bodyReadTimeout>TimeSpan.FromMinutes(5))throw new ArgumentOutOfRangeException(nameof(bodyReadTimeout));
        AppId=appId;Origin=origin;Replay=replay??throw new ArgumentNullException(nameof(replay));Authenticate=authenticate??throw new ArgumentNullException(nameof(authenticate));ResolveKey=resolveKey??throw new ArgumentNullException(nameof(resolveKey));Clock=clock??(()=>DateTimeOffset.UtcNow.ToUnixTimeSeconds());AllowInsecureTransport=allowInsecureTransport;
        BodyReadTimeout=bodyReadTimeout;
    }
}
public interface IAppGuardVerificationFeature{VerificationResult Result{get;}}
/// <summary>Trusted host capture of original duplicate-preserving header names/values before server normalization.
/// Never populate this feature from IHttpRequestFeature.Headers or client-supplied metadata.</summary>
public interface IAppGuardRawHeadersFeature{IReadOnlyList<HeaderPair> Headers{get;}}
sealed class AppGuardVerificationFeature(VerificationResult result):IAppGuardVerificationFeature{public VerificationResult Result{get;}=result;}
/// <summary>Install before body parsing/decompression/rewriting and after existing authentication that preserves raw input.</summary>
public sealed class AppGuardMiddleware
{
    readonly RequestDelegate _next;readonly AppGuardOptions _options;
    public AppGuardMiddleware(RequestDelegate next,AppGuardOptions options){_next=next??throw new ArgumentNullException(nameof(next));_options=options??throw new ArgumentNullException(nameof(options));}
    public async Task InvokeAsync(HttpContext context)
    {
        // Keep the original request's cancellation signal across host callbacks.
        var cancellationToken=context.RequestAborted;
        MemoryStream? captured=null;Stream? original=null;VerificationResult result;
        try
        {
            var raw=context.Features.Get<IHttpRequestFeature>();
            if(raw is null||string.IsNullOrEmpty(raw.RawTarget)||!_options.AllowInsecureTransport&&(!string.Equals(raw.Scheme,"https",StringComparison.OrdinalIgnoreCase)||context.Features.Get<ITlsConnectionFeature>() is null))throw new AppGuardException("INVALID_REQUEST");
            cancellationToken.ThrowIfCancellationRequested();
            var originalHeaders=context.Features.Get<IAppGuardRawHeadersFeature>();
            if(originalHeaders?.Headers is null)throw new AppGuardException("INVALID_REQUEST");
            var headers=new List<HeaderPair>();int size=0;
            foreach(var h in originalHeaders.Headers)
            {
                if(h.Name is null||h.Value is null||headers.Count==64||h.Name.Length>16384||h.Value.Length>16384||(size+=h.Name.Length+h.Value.Length)>16384)throw new AppGuardException("INVALID_REQUEST");
                headers.Add(new(h.Name,h.Value));
            }
            var envelope=Wire.Parse(headers);
            original=raw.Body;
            if(original is null||!original.CanRead||original.CanSeek&&original.Position!=0)throw new AppGuardException("INVALID_REQUEST");
            captured=new MemoryStream();var buffer=new byte[8192];RequestData request;
            var bodyStarted=Stopwatch.GetTimestamp();
            var bodyCancellation=new CancellationTokenSource();Task? bodyCancellationWork=null;
            try
            {
                // This token belongs only to capture. WaitAsync independently
                // observes the captured request token and the absolute deadline.
                while(true)
                {
                    CheckBodyDeadline(bodyStarted,cancellationToken);
                    Task<int>? pending=null;int count;
                    try
                    {
                        pending=original.ReadAsync(buffer.AsMemory(0,Math.Min(buffer.Length,Profile.MaxBodyBytes+1-(int)captured.Length)),bodyCancellation.Token).AsTask();
                        CheckBodyDeadline(bodyStarted,cancellationToken);
                        var remaining=_options.BodyReadTimeout-Stopwatch.GetElapsedTime(bodyStarted);
                        // Own the timeout independently of arbitrary stream token
                        // callbacks, which may themselves block or throw.
                        count=await pending.WaitAsync(remaining>TimeSpan.Zero?remaining:TimeSpan.Zero,cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        // A stream may ignore cancellation and still own buffer. It is
                        // an unpooled, per-request array: never reuse/clear/dispose it.
                        // Observe a late fault without awaiting or exposing its details.
                        if(pending is not null)ObserveLateFault(pending);
                        bodyCancellationWork=bodyCancellation.CancelAsync();
                        throw;
                    }
                    CheckBodyDeadline(bodyStarted,cancellationToken);
                    if(count==0)break;
                    if(count<0||count>Math.Min(buffer.Length,Profile.MaxBodyBytes+1-(int)captured.Length))throw new AppGuardException("INVALID_REQUEST");
                    captured.Write(buffer.AsSpan(0,count));
                    if(captured.Length>Profile.MaxBodyBytes)throw new AppGuardException("INVALID_REQUEST",413);
                }
                CheckBodyDeadline(bodyStarted,cancellationToken);
                Wire.ValidateFraming(headers,(int)captured.Length);
                request=new RequestData(raw.Method,raw.RawTarget,headers,captured.ToArray());
                CheckBodyDeadline(bodyStarted,cancellationToken);
            }
            catch(AppGuardException){throw;}catch(Exception){throw new AppGuardException("INVALID_REQUEST");}
            finally{ReleaseBodyCancellation(bodyCancellation,bodyCancellationWork);}
            // Final framing, feature getters and body copies may run after the
            // previous checkpoint. Timer teardown must not open a late handoff.
            CheckBodyDeadline(bodyStarted,cancellationToken);
            string? subject;
            try{subject=await _options.Authenticate(context,cancellationToken).ConfigureAwait(false);}
            catch(Exception){throw new AppGuardException("IDENTITY_UNAVAILABLE");}
            cancellationToken.ThrowIfCancellationRequested();
            if(subject is null)throw new AppGuardException("AUTHENTICATION_REQUIRED");
            if(!Validation.IsIdentifier(subject))throw new AppGuardException("IDENTITY_UNAVAILABLE");
            KeyRecord? key;
            try{key=await _options.ResolveKey(context,subject,envelope.Parameters,cancellationToken).ConfigureAwait(false);}
            catch(Exception){throw new AppGuardException("KEY_RESOLVER_UNAVAILABLE");}
            cancellationToken.ThrowIfCancellationRequested();
            long now;
            try{now=_options.Clock();}catch(Exception){throw new AppGuardException("VERIFICATION_UNAVAILABLE");}
            result=await Verifier.VerifyAsync(request,envelope.Parameters,envelope.Signature,new VerificationContext(_options.Origin,_options.AppId,subject,key,now,_options.Replay),cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch(AppGuardException e){captured?.Dispose();await Reject(context,e,cancellationToken).ConfigureAwait(false);return;}
        catch(OperationCanceledException){captured?.Dispose();await Reject(context,new AppGuardException("INVALID_REQUEST"),cancellationToken).ConfigureAwait(false);return;}
        catch(Exception){captured?.Dispose();await Reject(context,new AppGuardException("VERIFICATION_UNAVAILABLE"),cancellationToken).ConfigureAwait(false);return;}
        context.Features.Set<IAppGuardVerificationFeature>(new AppGuardVerificationFeature(result));
        captured.Position=0;context.Request.Body=captured;
        try{await _next(context).ConfigureAwait(false);}
        finally{context.Request.Body=original!;await captured.DisposeAsync().ConfigureAwait(false);}
    }
    void CheckBodyDeadline(long started,CancellationToken requestCancellation)
    {
        requestCancellation.ThrowIfCancellationRequested();
        if(Stopwatch.GetElapsedTime(started)>=_options.BodyReadTimeout)throw new AppGuardException("INVALID_REQUEST");
    }
    static void ObserveLateFault(Task pending)
    {
        _=pending.ContinueWith(task=>{_=task.Exception;},CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
    }
    static void ReleaseBodyCancellation(CancellationTokenSource source,Task? cancellationWork)
    {
        if(cancellationWork is null){source.Dispose();return;}
        // Disposing before CancelAsync's callbacks run can drop those callbacks.
        // Do not await an arbitrary host callback; release its source when done.
        _=cancellationWork.ContinueWith(static(task,state)=>
        {
            _=task.Exception;((CancellationTokenSource)state!).Dispose();
        },source,CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
    }
    static async Task Reject(HttpContext context,AppGuardException error,CancellationToken cancellationToken)
    {
        context.Response.StatusCode=error.StatusCode;context.Response.ContentType="application/json";
        if(!cancellationToken.IsCancellationRequested)await context.Response.WriteAsync("{\"code\":\""+error.Code+"\"}",cancellationToken).ConfigureAwait(false);
    }
}
public static class AppGuardExtensions
{
    public static IApplicationBuilder UseAppGuard(this IApplicationBuilder app,AppGuardOptions options)=>app.UseMiddleware<AppGuardMiddleware>(options);
}
