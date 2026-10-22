using AppGuard;
using AppGuard.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Xunit;

namespace AppGuard.Tests;

public class BodyHandoffTests
{
    sealed class ObservedBody(byte[] bytes):MemoryStream(bytes)
    {
        internal bool ReachedEof;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {
            var count=await base.ReadAsync(buffer,cancellationToken);
            if(count==0)ReachedEof=true;
            return count;
        }
    }

    // Preserve real request values, but synchronize a host cancellation with
    // the final RequestData snapshot. No delay or product test hook is needed.
    sealed class FinalizationFeature(IHttpRequestFeature inner,ObservedBody body,string trigger,Action action):IHttpRequestFeature
    {
        internal int Triggered;
        string Read(string field,string value)
        {
            if(field==trigger&&body.ReachedEof&&Interlocked.Exchange(ref Triggered,1)==0)action();
            return value;
        }
        public string Method {get=>Read("method",inner.Method);set=>inner.Method=value;}
        public string RawTarget {get=>Read("target",inner.RawTarget);set=>inner.RawTarget=value;}
        public string Protocol {get=>inner.Protocol;set=>inner.Protocol=value;}
        public string Scheme {get=>inner.Scheme;set=>inner.Scheme=value;}
        public string PathBase {get=>inner.PathBase;set=>inner.PathBase=value;}
        public string Path {get=>inner.Path;set=>inner.Path=value;}
        public string QueryString {get=>inner.QueryString;set=>inner.QueryString=value;}
        public IHeaderDictionary Headers {get=>inner.Headers;set=>inner.Headers=value;}
        public Stream Body {get=>inner.Body;set=>inner.Body=value;}
    }

    sealed class Counts:IReplayStore
    {
        internal int Authentication,Keys,Clocks,Claims,Dispatch;
        readonly InMemoryReplayStore _replay=new();
        public ValueTask<bool> ClaimAsync(ReplayScope scope,long expires,long now,CancellationToken cancellationToken=default)
        {Claims++;return _replay.ClaimAsync(scope,expires,now,cancellationToken);}
        internal AppGuardOptions Options(SecurityTests.Signed signed)=>new("app","https://api.example.test",this,
            (_,_)=>{Authentication++;return ValueTask.FromResult<string?>("subject");},
            (_,_,_,_)=>{Keys++;return ValueTask.FromResult<KeyRecord?>(signed.Key);},
            ()=>{Clocks++;return 100;},true);
    }

    static (DefaultHttpContext Context,ObservedBody Body,FinalizationFeature Feature) Context(
        SecurityTests.Signed signed,string trigger,Action<DefaultHttpContext> finalize)
    {
        var context=MiddlewareTests.Context(signed);
        var body=new ObservedBody(signed.Request.Body.ToArray());context.Request.Body=body;
        var feature=new FinalizationFeature(context.Features.Get<IHttpRequestFeature>()!,body,trigger,()=>finalize(context));
        context.Features.Set<IHttpRequestFeature>(feature);
        return (context,body,feature);
    }

    [Theory]
    [InlineData("method",false)] [InlineData("method",true)]
    [InlineData("target",false)] [InlineData("target",true)]
    public async Task CancellationDuringFinalBodySnapshotCannotStartAuthentication(string trigger,bool replaceContextToken)
    {
        using var signed=new SecurityTests.Signed();using var cancellation=new CancellationTokenSource();
        var counts=new Counts();
        var (context,body,feature)=Context(signed,trigger,c=>
        {
            Assert.False(cancellation.IsCancellationRequested);
            cancellation.Cancel();
            if(replaceContextToken)c.RequestAborted=CancellationToken.None;
        });
        context.RequestAborted=cancellation.Token;
        await new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed)).InvokeAsync(context);

        Assert.True(body.ReachedEof);Assert.Equal(1,feature.Triggered);
        Assert.True(cancellation.IsCancellationRequested);
        Assert.Equal(0,counts.Authentication);Assert.Equal(0,counts.Keys);Assert.Equal(0,counts.Clocks);
        Assert.Equal(0,counts.Claims);Assert.Equal(0,counts.Dispatch);
        Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
        Assert.Equal(400,context.Response.StatusCode);Assert.Equal(0,context.Response.Body.Length);
        Assert.Same(body,context.Request.Body);Assert.True(body.CanRead);
        Assert.Equal(signed.Request.Body.ToArray(),body.ToArray());
    }

    [Theory] [InlineData("method")] [InlineData("target")]
    public async Task UncanceledBodySnapshotStillVerifiesAndRestoresTheOriginalStream(string trigger)
    {
        using var signed=new SecurityTests.Signed(body:[0,255,128,13,10,0]);var counts=new Counts();
        var (context,body,feature)=Context(signed,trigger,_=>{});var principal=context.User;
        await new AppGuardMiddleware(async c=>
        {
            counts.Dispatch++;Assert.Same(principal,c.User);
            using var copied=new MemoryStream();await c.Request.Body.CopyToAsync(copied);
            Assert.Equal(signed.Request.Body.ToArray(),copied.ToArray());
        },counts.Options(signed)).InvokeAsync(context);

        Assert.Equal(1,feature.Triggered);Assert.True(body.ReachedEof);
        Assert.Equal(1,counts.Authentication);Assert.Equal(1,counts.Keys);Assert.Equal(1,counts.Clocks);
        Assert.Equal(1,counts.Claims);Assert.Equal(1,counts.Dispatch);
        Assert.Equal("VERIFIED",context.Features.Get<IAppGuardVerificationFeature>()!.Result.Code);
        Assert.Equal(200,context.Response.StatusCode);Assert.Same(body,context.Request.Body);Assert.True(body.CanRead);
    }

    [Fact]
    public async Task CanceledFinalSnapshotLeavesNonceUnusedAndDoesNotAffectAnIndependentRequest()
    {
        using var signed=new SecurityTests.Signed();using var cancellation=new CancellationTokenSource();var counts=new Counts();
        var (canceled,_,feature)=Context(signed,"method",_=>cancellation.Cancel());canceled.RequestAborted=cancellation.Token;
        var middleware=new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed));
        await middleware.InvokeAsync(canceled);
        Assert.Equal(1,feature.Triggered);Assert.Equal(0,counts.Authentication);Assert.Equal(0,counts.Claims);
        Assert.Null(canceled.Features.Get<IAppGuardVerificationFeature>());

        var healthy=MiddlewareTests.Context(signed);var original=healthy.Request.Body;
        await middleware.InvokeAsync(healthy);
        Assert.Equal(200,healthy.Response.StatusCode);Assert.Equal(1,counts.Dispatch);Assert.Equal(1,counts.Claims);
        Assert.Equal("VERIFIED",healthy.Features.Get<IAppGuardVerificationFeature>()!.Result.Code);Assert.Same(original,healthy.Request.Body);
        var repeated=MiddlewareTests.Context(signed);await middleware.InvokeAsync(repeated);
        Assert.Equal(403,repeated.Response.StatusCode);Assert.Equal(1,counts.Dispatch);Assert.Equal(2,counts.Claims);
        repeated.Response.Body.Position=0;
        Assert.Equal("{\"code\":\"REPLAY_DETECTED\"}",await new StreamReader(repeated.Response.Body).ReadToEndAsync());
    }
}
