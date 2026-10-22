using AppGuard;
using AppGuard.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using System.Runtime.CompilerServices;
using Xunit;

namespace AppGuard.Tests;

public class BodyDeadlineTests
{
    sealed class PendingBody:MemoryStream
    {
        readonly TaskCompletionSource<int> _completion=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Memory<byte> PendingBuffer{get;private set;}
        internal CancellationToken ReadToken{get;private set;}
        internal bool Disposed;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {PendingBuffer=buffer;ReadToken=cancellationToken;Entered.TrySetResult();return new ValueTask<int>(_completion.Task);}
        internal void Release()=>_completion.TrySetResult(0);
        internal void Fail(string message)=>_completion.TrySetException(new IOException(message));
        internal Task ReadCompletion=>_completion.Task;
        protected override void Dispose(bool disposing){Disposed=true;base.Dispose(disposing);}
    }

    sealed class Counts:IReplayStore
    {
        internal int Authentication,Keys,Clocks,Claims,Dispatch;
        readonly InMemoryReplayStore _replay=new();
        public ValueTask<bool> ClaimAsync(ReplayScope scope,long expires,long now,CancellationToken cancellationToken=default)
        {Claims++;return _replay.ClaimAsync(scope,expires,now,cancellationToken);}
        internal AppGuardOptions Options(SecurityTests.Signed signed,TimeSpan? timeout,
            Func<HttpContext,CancellationToken,ValueTask<string?>>? authenticate=null)
            =>new("app","https://api.example.test",this,
                authenticate??((_,_)=>{Authentication++;return ValueTask.FromResult<string?>("subject");}),
                (_,_,_,_)=>{Keys++;return ValueTask.FromResult<KeyRecord?>(signed.Key);},
                bodyReadTimeout:timeout??TimeSpan.FromSeconds(30),clock:()=>{Clocks++;return 100;},allowInsecureTransport:true);
        internal void NoWork()
        {Assert.Equal(0,Authentication);Assert.Equal(0,Keys);Assert.Equal(0,Clocks);Assert.Equal(0,Claims);Assert.Equal(0,Dispatch);}
    }

    static async Task AssertInvalid(DefaultHttpContext context,Stream original,Counts counts)
    {
        Assert.Equal(400,context.Response.StatusCode);context.Response.Body.Position=0;
        Assert.Equal("{\"code\":\"INVALID_REQUEST\"}",await new StreamReader(context.Response.Body).ReadToEndAsync());
        counts.NoWork();Assert.Same(original,context.Request.Body);Assert.True(original.CanRead);
        Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
    }

    [Fact]
    public async Task DefaultBodyDeadlineRejectsAnIgnoredCancellationReadBeforeAuthentication()
    {
        using var signed=new SecurityTests.Signed();using var body=new PendingBody();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;int authenticated=0,keys=0,clock=0,dispatch=0;
        var replay=new SecurityTests.CountingStore();
        var options=new AppGuardOptions("app","https://api.example.test",replay,
            (_,_)=>{authenticated++;return ValueTask.FromResult<string?>("subject");},
            (_,_,_,_)=>{keys++;return ValueTask.FromResult<KeyRecord?>(signed.Key);},
            ()=>{clock++;return 100;},true);
        var invocation=new AppGuardMiddleware(_=>{dispatch++;return Task.CompletedTask;},options).InvokeAsync(context);
        try
        {
            await body.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var winner=await Task.WhenAny(invocation,Task.Delay(TimeSpan.FromSeconds(32)));
            Assert.Same(invocation,winner);
            await invocation;
            Assert.Equal(400,context.Response.StatusCode);context.Response.Body.Position=0;
            Assert.Equal("{\"code\":\"INVALID_REQUEST\"}",await new StreamReader(context.Response.Body).ReadToEndAsync());
            Assert.Equal(0,authenticated);Assert.Equal(0,keys);Assert.Equal(0,clock);Assert.Equal(0,replay.Count);Assert.Equal(0,dispatch);
            Assert.Same(body,context.Request.Body);Assert.True(body.CanRead);
            Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
        }
        finally{body.Release();await invocation.WaitAsync(TimeSpan.FromSeconds(5));}
    }

    [Theory] [InlineData(0L)] [InlineData(-1L)] [InlineData(3000000001L)] [InlineData(long.MaxValue)]
    public void InvalidAbsoluteBodyTimeoutIsRejectedAtConfiguration(long ticks)
    {
        using var signed=new SecurityTests.Signed();var counts=new Counts();
        Assert.Equal("bodyReadTimeout",Assert.Throws<ArgumentOutOfRangeException>(()=>counts.Options(signed,TimeSpan.FromTicks(ticks))).ParamName);
    }

    [Theory] [InlineData(1L)] [InlineData(3000000000L)]
    public void PositiveTimeoutAndFiveMinuteUpperBoundaryAreAccepted(long ticks)
    {
        using var signed=new SecurityTests.Signed();var counts=new Counts();counts.Options(signed,TimeSpan.FromTicks(ticks));
    }

    [Fact]
    public async Task ConfiguredDeadlineFinishesAnIgnoredReadWithoutClosingItsOwnedStreamOrReusingItsBuffer()
    {
        using var signed=new SecurityTests.Signed();using var body=new PendingBody();var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;
        var middleware=new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromMilliseconds(80)));
        var pending=middleware.InvokeAsync(context);
        try
        {
            await body.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));await pending.WaitAsync(TimeSpan.FromSeconds(5));
            await AssertInvalid(context,body,counts);Assert.True(body.ReadToken.IsCancellationRequested);
            Assert.False(body.Disposed);Assert.False(body.ReadCompletion.IsCompleted);
            // The outstanding read still owns its array after rejection. A separate
            // request must never reuse it or have its bytes changed by this write.
            body.PendingBuffer.Span.Fill(0xA5);
            var healthy=MiddlewareTests.Context(signed);var healthyOriginal=healthy.Request.Body;
            await middleware.InvokeAsync(healthy).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(200,healthy.Response.StatusCode);Assert.Equal(1,counts.Dispatch);Assert.Equal(1,counts.Claims);
            Assert.Same(healthyOriginal,healthy.Request.Body);Assert.Equal(signed.Request.Body.ToArray(),((MemoryStream)healthyOriginal).ToArray());
            body.Release();await body.ReadCompletion.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1,counts.Authentication);Assert.Equal(1,counts.Keys);Assert.Equal(1,counts.Clocks);Assert.Equal(1,counts.Dispatch);
            Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
        }
        finally{body.Release();await pending.WaitAsync(TimeSpan.FromSeconds(5));}
    }

    sealed class DripBody(byte[] bytes):MemoryStream(bytes)
    {
        internal int Reads;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {
            Reads++;await Task.Delay(40,cancellationToken);
            return await base.ReadAsync(buffer[..Math.Min(buffer.Length,1)],cancellationToken);
        }
    }

    [Fact]
    public async Task SlowDripProgressDoesNotResetTheAbsoluteDeadline()
    {
        using var signed=new SecurityTests.Signed();using var body=new DripBody(signed.Request.Body.ToArray());var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;
        await new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromMilliseconds(150))).InvokeAsync(context).WaitAsync(TimeSpan.FromSeconds(5));
        await AssertInvalid(context,body,counts);Assert.True(body.Reads<signed.Request.Body.Length);
    }

    sealed class LateEofBody(byte[] bytes):MemoryStream(bytes)
    {
        readonly TaskCompletionSource _release=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource EofEntered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource EofReturned=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {
            if(Position<Length)return await base.ReadAsync(buffer,cancellationToken);
            EofEntered.TrySetResult();await _release.Task;EofReturned.TrySetResult();return 0;
        }
        internal void Release()=>_release.TrySetResult();
    }

    [Fact]
    public async Task EofReturningAfterTimeoutCannotResumeAuthenticationOrConsumeTheNonce()
    {
        using var signed=new SecurityTests.Signed();using var body=new LateEofBody(signed.Request.Body.ToArray());var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;
        var middleware=new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromMilliseconds(100)));
        var pending=middleware.InvokeAsync(context);
        try
        {
            await body.EofEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));await pending.WaitAsync(TimeSpan.FromSeconds(5));
            await AssertInvalid(context,body,counts);body.Release();await body.EofReturned.Task.WaitAsync(TimeSpan.FromSeconds(5));
            counts.NoWork();Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
            var healthy=MiddlewareTests.Context(signed);await middleware.InvokeAsync(healthy).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(200,healthy.Response.StatusCode);Assert.Equal(1,counts.Claims);Assert.Equal(1,counts.Dispatch);
        }
        finally{body.Release();await pending.WaitAsync(TimeSpan.FromSeconds(5));}
    }

    sealed class BlockingEofBody(byte[] bytes):MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {
            if(Position<Length)return base.ReadAsync(buffer,cancellationToken);
            Thread.Sleep(150);return ValueTask.FromResult(0);
        }
    }

    [Fact]
    public async Task SynchronouslyCompletedLateEofFailsTheMonotonicCheckpointBeforeAuthentication()
    {
        using var signed=new SecurityTests.Signed();using var body=new BlockingEofBody(signed.Request.Body.ToArray());var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;
        await new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromMilliseconds(50))).InvokeAsync(context);
        await AssertInvalid(context,body,counts);
    }

    sealed class LateSnapshotFeature(IHttpRequestFeature inner):IHttpRequestFeature
    {
        public string Method{get{Thread.Sleep(150);return inner.Method;}set=>inner.Method=value;}
        public string RawTarget{get=>inner.RawTarget;set=>inner.RawTarget=value;}
        public string Protocol{get=>inner.Protocol;set=>inner.Protocol=value;}
        public string Scheme{get=>inner.Scheme;set=>inner.Scheme=value;}
        public string PathBase{get=>inner.PathBase;set=>inner.PathBase=value;}
        public string Path{get=>inner.Path;set=>inner.Path=value;}
        public string QueryString{get=>inner.QueryString;set=>inner.QueryString=value;}
        public IHeaderDictionary Headers{get=>inner.Headers;set=>inner.Headers=value;}
        public Stream Body{get=>inner.Body;set=>inner.Body=value;}
    }

    [Fact]
    public async Task DeadlineExpiringDuringFinalRequestSnapshotCannotStartAuthentication()
    {
        using var signed=new SecurityTests.Signed();var counts=new Counts();var context=MiddlewareTests.Context(signed);var original=context.Request.Body;
        context.Features.Set<IHttpRequestFeature>(new LateSnapshotFeature(context.Features.Get<IHttpRequestFeature>()!));
        await new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromMilliseconds(50))).InvokeAsync(context);
        await AssertInvalid(context,original,counts);
    }

    [Fact]
    public async Task BodySizeOverflowStillReturns413BeforeAuthenticationAndDoesNotConsumeTheNonce()
    {
        using var signed=new SecurityTests.Signed();var counts=new Counts();var context=MiddlewareTests.Context(signed);
        using var original=new MemoryStream(new byte[1048577]);context.Request.Body=original;
        await new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromSeconds(5))).InvokeAsync(context);
        Assert.Equal(413,context.Response.StatusCode);context.Response.Body.Position=0;
        Assert.Equal("{\"code\":\"INVALID_REQUEST\"}",await new StreamReader(context.Response.Body).ReadToEndAsync());
        counts.NoWork();Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());Assert.Same(original,context.Request.Body);Assert.True(original.CanRead);
    }

    [Fact]
    public async Task ClientDisconnectBoundsAnIgnoredReadUsingTheCapturedOriginalRequestToken()
    {
        using var signed=new SecurityTests.Signed();using var body=new PendingBody();using var cancellation=new CancellationTokenSource();var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;context.RequestAborted=cancellation.Token;
        var pending=new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromMinutes(1))).InvokeAsync(context);
        try
        {
            await body.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));context.RequestAborted=CancellationToken.None;cancellation.Cancel();
            await pending.WaitAsync(TimeSpan.FromSeconds(5));counts.NoWork();Assert.Equal(400,context.Response.StatusCode);
            Assert.Equal(0,context.Response.Body.Length);Assert.Same(body,context.Request.Body);Assert.True(body.ReadToken.IsCancellationRequested);
            Assert.False(body.Disposed);Assert.False(body.ReadCompletion.IsCompleted);Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
        }
        finally{body.Release();await pending.WaitAsync(TimeSpan.FromSeconds(5));}
    }

    sealed class CallbackBody(bool block,string? failure=null):MemoryStream
    {
        readonly TaskCompletionSource<int> _read=new(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly ManualResetEventSlim _release=new();
        internal readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Canceled=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CallbackFinished=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal WeakReference? Fault{get;private set;}
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {
            cancellationToken.Register(()=>
            {
                try
                {
                    Canceled.TrySetResult();if(block)_release.Wait();
                    if(failure is not null){var error=new IOException(failure);Fault=new WeakReference(error);throw error;}
                }
                finally{_read.TrySetCanceled(cancellationToken);CallbackFinished.TrySetResult();}
            });
            Entered.TrySetResult();
            return new ValueTask<int>(_read.Task);
        }
        internal void Release()=>_release.Set();
        protected override void Dispose(bool disposing){_release.Set();base.Dispose(disposing);}
    }

    [Theory] [InlineData(false,false)] [InlineData(true,false)] [InlineData(false,true)] [InlineData(true,true)]
    public async Task DeadlineOrDisconnectDeliversCancellationWithoutWaitingForOrDroppingStreamCallbacks(bool block,bool disconnect)
    {
        using var signed=new SecurityTests.Signed();using var body=new CallbackBody(block);using var cancellation=new CancellationTokenSource();var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;context.RequestAborted=cancellation.Token;Task? abort=null;
        var pending=new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,disconnect?TimeSpan.FromMinutes(1):TimeSpan.FromMilliseconds(80))).InvokeAsync(context);
        try
        {
            await body.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            if(disconnect){abort=Task.Run(()=>cancellation.Cancel());await abort.WaitAsync(TimeSpan.FromSeconds(5));}
            await pending.WaitAsync(TimeSpan.FromSeconds(5));
            if(disconnect)
            {
                Assert.Equal(400,context.Response.StatusCode);Assert.Equal(0,context.Response.Body.Length);counts.NoWork();
                Assert.Same(body,context.Request.Body);Assert.True(body.CanRead);Assert.Null(context.Features.Get<IAppGuardVerificationFeature>());
            }
            else await AssertInvalid(context,body,counts);
            await body.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(5));
            if(block)Assert.False(body.CallbackFinished.Task.IsCompleted);
            body.Release();await body.CallbackFinished.Task.WaitAsync(TimeSpan.FromSeconds(5));counts.NoWork();
        }
        finally{body.Release();await pending.WaitAsync(TimeSpan.FromSeconds(5));if(abort is not null)await abort.WaitAsync(TimeSpan.FromSeconds(5));}
    }

    [Fact]
    public async Task CompletedBodyReplaysExactBytesAndBodyTimerDoesNotCancelHostCallbacksOrDownstream()
    {
        using var signed=new SecurityTests.Signed(body:[0,255,128,13,10,0]);using var cancellation=new CancellationTokenSource();var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.RequestAborted=cancellation.Token;var original=context.Request.Body;
        var options=counts.Options(signed,TimeSpan.FromMilliseconds(80),async(_,token)=>
        {counts.Authentication++;Assert.Equal(cancellation.Token,token);await Task.Delay(150);Assert.False(token.IsCancellationRequested);return "subject";});
        await new AppGuardMiddleware(async c=>
        {
            counts.Dispatch++;Assert.Equal(cancellation.Token,c.RequestAborted);await Task.Delay(100);
            Assert.False(c.RequestAborted.IsCancellationRequested);using var copied=new MemoryStream();await c.Request.Body.CopyToAsync(copied);
            Assert.Equal(new byte[]{0,255,128,13,10,0},copied.ToArray());
        },options).InvokeAsync(context).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(200,context.Response.StatusCode);Assert.Equal(1,counts.Authentication);Assert.Equal(1,counts.Keys);Assert.Equal(1,counts.Clocks);Assert.Equal(1,counts.Claims);Assert.Equal(1,counts.Dispatch);
        Assert.Same(original,context.Request.Body);Assert.True(original.CanRead);Assert.NotNull(context.Features.Get<IAppGuardVerificationFeature>());
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static async Task<WeakReference> DeadlineFault(string marker)
    {
        using var signed=new SecurityTests.Signed();using var body=new PendingBody();var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;
        await new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromMilliseconds(50))).InvokeAsync(context).WaitAsync(TimeSpan.FromSeconds(5));
        await AssertInvalid(context,body,counts);body.Fail(marker);return new WeakReference(body.ReadCompletion);
    }
    [MethodImpl(MethodImplOptions.NoInlining)]
    static WeakReference UnobservedControlFault(string marker)=>new(Task.FromException(new IOException(marker)));

    [MethodImpl(MethodImplOptions.NoInlining)]
    static async Task<WeakReference> CancellationCallbackFault(string marker)
    {
        using var signed=new SecurityTests.Signed();using var body=new CallbackBody(false,marker);var counts=new Counts();
        var context=MiddlewareTests.Context(signed);context.Request.Body=body;
        await new AppGuardMiddleware(_=>{counts.Dispatch++;return Task.CompletedTask;},counts.Options(signed,TimeSpan.FromMilliseconds(50))).InvokeAsync(context).WaitAsync(TimeSpan.FromSeconds(5));
        await body.CallbackFinished.Task.WaitAsync(TimeSpan.FromSeconds(5));await AssertInvalid(context,body,counts);
        return Assert.IsType<WeakReference>(body.Fault);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task LateReadOrCancellationCallbackFaultIsCollectedWithoutPrivateUnobservedTaskEvent(bool cancellationCallback)
    {
        var privateMarker="PRIVATE-body-"+Guid.NewGuid().ToString("N");var controlMarker="control-body-"+Guid.NewGuid().ToString("N");
        using var privateSeen=new ManualResetEventSlim();using var controlSeen=new ManualResetEventSlim();
        EventHandler<UnobservedTaskExceptionEventArgs> handler=(_,args)=>
        {
            foreach(var error in args.Exception.Flatten().InnerExceptions)
            {if(error.Message==privateMarker)privateSeen.Set();if(error.Message==controlMarker)controlSeen.Set();}
            args.SetObserved();
        };
        TaskScheduler.UnobservedTaskException+=handler;
        try
        {
            var pending=cancellationCallback?await CancellationCallbackFault(privateMarker):await DeadlineFault(privateMarker);var control=UnobservedControlFault(controlMarker);
            for(var attempt=0;attempt<50&&(!controlSeen.IsSet||pending.IsAlive||control.IsAlive);attempt++)
            {GC.Collect();GC.WaitForPendingFinalizers();GC.Collect();await Task.Delay(10);}
            Assert.True(controlSeen.IsSet,"Control fault must establish that finalization ran.");
            Assert.False(pending.IsAlive,"Completed abandoned reads must be collectible.");Assert.False(privateSeen.IsSet,"Private stream failure reached the host's unobserved-task event.");
        }
        finally{TaskScheduler.UnobservedTaskException-=handler;}
    }
}
