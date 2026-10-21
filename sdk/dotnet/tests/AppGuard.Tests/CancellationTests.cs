using AppGuard;
using AppGuard.AspNetCore;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AppGuard.Tests;

public class CancellationTests
{
    sealed class Gate
    {
        readonly TaskCompletionSource _entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly TaskCompletionSource _release=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task Entered=>_entered.Task;
        internal async ValueTask Wait() {_entered.TrySetResult();await _release.Task;}
        internal void Release()=>_release.TrySetResult();
    }
    sealed class Store(Func<CancellationToken,ValueTask<bool>> callback):IReplayStore
    {
        internal int Calls;
        public ValueTask<bool> ClaimAsync(ReplayScope scope,long expires,long now,CancellationToken cancellationToken=default)
        {Interlocked.Increment(ref Calls);return callback(cancellationToken);}
    }
    sealed class EofGate(byte[] body,Gate gate):MemoryStream(body)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {
            if(Position==Length){await gate.Wait();return 0;}
            return await base.ReadAsync(buffer,cancellationToken);
        }
    }
    static Task Bounded(Task task)=>task.WaitAsync(TimeSpan.FromSeconds(10));
    static AppGuardOptions Options(SecurityTests.Signed s,IReplayStore store,
        Func<HttpContext,CancellationToken,ValueTask<string?>>? auth=null,
        Func<HttpContext,string,SignatureParameters,CancellationToken,ValueTask<KeyRecord?>>? key=null,Func<long>? clock=null)
        =>new("app","https://api.example.test",store,auth??((_,_)=>ValueTask.FromResult<string?>("subject")),
            key??((_,_,_,_)=>ValueTask.FromResult<KeyRecord?>(s.Key)),clock??(()=>100),true);

    [Theory] [InlineData("body")] [InlineData("identity")] [InlineData("key")] [InlineData("replay")]
    public async Task LateReturnAfterRequestCancellationCannotAdvanceToTheNextPhase(string phase)
    {
        using var s=new SecurityTests.Signed();using var cancellation=new CancellationTokenSource();var gate=new Gate();
        var context=MiddlewareTests.Context(s);context.RequestAborted=cancellation.Token;
        if(phase=="body")context.Request.Body=new EofGate(s.Request.Body.ToArray(),gate);
        var original=context.Request.Body;int auth=0,key=0,clocks=0,dispatch=0;
        var store=new Store(async token=>{Assert.Equal(cancellation.Token,token);if(phase=="replay")await gate.Wait();return true;});
        var options=Options(s,store,auth:async(_,token)=>{auth++;Assert.Equal(cancellation.Token,token);if(phase=="identity")await gate.Wait();return "subject";},
            key:async(_,_,_,token)=>{key++;Assert.Equal(cancellation.Token,token);if(phase=="key")await gate.Wait();return s.Key;},clock:()=>{clocks++;return 100;});
        var invocation=new AppGuardMiddleware(_=>{dispatch++;return Task.CompletedTask;},options).InvokeAsync(context);
        try
        {
            await Bounded(gate.Entered);cancellation.Cancel();
            // The fixture ignores its token. The SDK does not promise to terminate it.
            Assert.False(invocation.IsCompleted);gate.Release();await Bounded(invocation);
            Assert.Equal(0,dispatch);Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
            Assert.Equal(phase=="body"?0:1,auth);
            Assert.Equal(phase is "key" or "replay"?1:0,key);
            Assert.Equal(phase=="replay"?1:0,clocks);Assert.Equal(phase=="replay"?1:0,store.Calls);
            Assert.Equal(400,context.Response.StatusCode);Assert.Equal(0,context.Response.Body.Length);
            Assert.Same(original,context.Request.Body);Assert.True(original.CanRead);
        }
        finally{gate.Release();await Bounded(invocation);}
    }

    [Theory] [InlineData("identity")] [InlineData("key")] [InlineData("replay")]
    public async Task ReplacingHttpContextTokenCannotEraseCancellationOfTheCapturedRequest(string phase)
    {
        using var s=new SecurityTests.Signed();using var cancellation=new CancellationTokenSource();var gate=new Gate();
        var context=MiddlewareTests.Context(s);context.RequestAborted=cancellation.Token;int dispatch=0,keys=0,clocks=0;
        async ValueTask Replace(CancellationToken token)
        {
            Assert.Equal(cancellation.Token,token);context.RequestAborted=CancellationToken.None;await gate.Wait();
        }
        var store=new Store(async token=>{if(phase=="replay")await Replace(token);return true;});
        var options=Options(s,store,auth:async(_,token)=>{if(phase=="identity")await Replace(token);return "subject";},
            key:async(_,_,_,token)=>{keys++;if(phase=="key")await Replace(token);return s.Key;},clock:()=>{clocks++;return 100;});
        var invocation=new AppGuardMiddleware(_=>{dispatch++;return Task.CompletedTask;},options).InvokeAsync(context);
        try
        {
            await Bounded(gate.Entered);cancellation.Cancel();gate.Release();await Bounded(invocation);
            Assert.Equal(0,dispatch);Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
            Assert.Equal(phase=="identity"?0:1,keys);Assert.Equal(phase=="replay"?1:0,clocks);
            Assert.Equal(phase=="replay"?1:0,store.Calls);Assert.Equal(0,context.Response.Body.Length);
        }
        finally{gate.Release();await Bounded(invocation);}
    }

    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task DirectVerifierDoesNotReturnAResultFromALateCanceledReplay(bool claimResult)
    {
        using var s=new SecurityTests.Signed();using var cancellation=new CancellationTokenSource();var gate=new Gate();
        var store=new Store(async token=>{Assert.Equal(cancellation.Token,token);await gate.Wait();return claimResult;});
        var verification=Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store),cancellation.Token).AsTask();
        await Bounded(gate.Entered);cancellation.Cancel();gate.Release();
        var error=await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Bounded(verification));
        Assert.Equal(cancellation.Token,error.CancellationToken);Assert.Equal(1,store.Calls);
    }

    [Fact] public async Task CanceledAuthenticationCannotAffectAnIndependentRequestOrItsBody()
    {
        using var s=new SecurityTests.Signed();using var cancellation=new CancellationTokenSource();var gate=new Gate();
        var blocked=MiddlewareTests.Context(s);blocked.RequestAborted=cancellation.Token;
        var healthy=MiddlewareTests.Context(s);var healthyOriginal=healthy.Request.Body;int blockedKeys=0,dispatch=0;
        var options=Options(s,new InMemoryReplayStore(),auth:async(ctx,_)=>{if(ReferenceEquals(ctx,blocked))await gate.Wait();return "subject";},
            key:(ctx,_,_,_)=>{if(ReferenceEquals(ctx,blocked))blockedKeys++;return ValueTask.FromResult<KeyRecord?>(s.Key);});
        var middleware=new AppGuardMiddleware(async ctx=>
        {
            Assert.Same(healthy,ctx);dispatch++;
            using var copy=new MemoryStream();await ctx.Request.Body.CopyToAsync(copy);Assert.Equal(s.Request.Body.ToArray(),copy.ToArray());
        },options);
        var pending=middleware.InvokeAsync(blocked);
        try
        {
            await Bounded(gate.Entered);cancellation.Cancel();await Bounded(middleware.InvokeAsync(healthy));
            Assert.Equal(200,healthy.Response.StatusCode);Assert.NotNull(healthy.Features.Get<IAppGuardVerificationFeature>());
            Assert.Same(healthyOriginal,healthy.Request.Body);gate.Release();await Bounded(pending);
            Assert.Equal(1,dispatch);Assert.Equal(0,blockedKeys);Assert.Null(blocked.Features.Get<IAppGuardVerificationFeature>());
        }
        finally{gate.Release();await Bounded(pending);}
    }

    [Theory] [InlineData("identity")] [InlineData("key")] [InlineData("replay")]
    public async Task CallbackFailureAfterCancellationRemainsPrivateAndDoesNotDispatch(string phase)
    {
        using var s=new SecurityTests.Signed();using var cancellation=new CancellationTokenSource();var gate=new Gate();
        var context=MiddlewareTests.Context(s);context.RequestAborted=cancellation.Token;int dispatch=0;
        async ValueTask Fail(){await gate.Wait();throw new InvalidOperationException("PRIVATE DEPENDENCY DETAIL");}
        var store=new Store(async _=>{if(phase=="replay")await Fail();return true;});
        var options=Options(s,store,auth:async(_,_)=>{if(phase=="identity")await Fail();return "subject";},
            key:async(_,_,_,_)=>{if(phase=="key")await Fail();return s.Key;});
        var invocation=new AppGuardMiddleware(_=>{dispatch++;return Task.CompletedTask;},options).InvokeAsync(context);
        try
        {
            await Bounded(gate.Entered);cancellation.Cancel();gate.Release();await Bounded(invocation);
            Assert.Equal(503,context.Response.StatusCode);Assert.Equal(0,context.Response.Body.Length);
            Assert.Equal(0,dispatch);Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
            Assert.Equal(phase=="replay"?1:0,store.Calls);
        }
        finally{gate.Release();await Bounded(invocation);}
    }

    [Fact] public async Task AlreadyCanceledDirectVerificationDoesNotCallReplay()
    {
        using var s=new SecurityTests.Signed();var store=new Store(_=>ValueTask.FromResult(true));
        using var cancellation=new CancellationTokenSource();cancellation.Cancel();
        var error=await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store),cancellation.Token));
        Assert.Equal(cancellation.Token,error.CancellationToken);Assert.Equal(0,store.Calls);
    }

    [Fact] public async Task CancellationDoesNotRollBackAReplayClaimAlreadyCommitted()
    {
        using var s=new SecurityTests.Signed();using var cancellation=new CancellationTokenSource();var gate=new Gate();
        var durableOutcome=new InMemoryReplayStore();
        var store=new Store(async token=>{var claimed=await durableOutcome.ClaimAsync(new ReplayScope("app","key",s.Parameters.Nonce),220,100,token);await gate.Wait();return claimed;});
        var verification=Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(store),cancellation.Token).AsTask();
        await Bounded(gate.Entered);cancellation.Cancel();gate.Release();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Bounded(verification));Assert.Equal(1,store.Calls);
        var error=await Assert.ThrowsAsync<AppGuardException>(async()=>await Verifier.VerifyAsync(s.Request,s.Parameters,s.Signature,s.Context(durableOutcome)));
        Assert.Equal("REPLAY_DETECTED",error.Code);Assert.Null(error.InnerException);
    }
}
