using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using AppGuard;
using StackExchange.Redis;
using Xunit;

namespace AppGuard.Tests;

public class RedisReplayTests
{
    const string Nonce = "AAECAwQFBgcICQoLDA0ODw";
    static ReplayScope Scope() => new("test-" + Guid.NewGuid().ToString("N"), "key", Nonce);
    public class DatabaseProxy : DispatchProxy
    {
        public Func<Task<RedisResult>> Reply = () => Task.FromResult(RedisResult.Create("OK", ResultType.SimpleString));
        public int Calls;
        public string? Command;
        public object[]? Arguments;
        protected override object? Invoke(MethodInfo? method, object?[]? args)
        {
            Assert.Equal("ExecuteAsync", method!.Name);
            Calls++; Command = (string)args![0]!; Arguments = (object[])args[1]!;
            return Reply();
        }
    }
    static (RedisReplayStore Store, DatabaseProxy Proxy) Mock()
    {
        var db = DispatchProxy.Create<IDatabaseAsync, DatabaseProxy>();
        return (new RedisReplayStore(db), (DatabaseProxy)db);
    }
    static void Redacted(AppGuardException error)
    {
        Assert.Equal("REPLAY_STORE_UNAVAILABLE", error.Code);
        Assert.Equal(503, error.StatusCode); Assert.Null(error.InnerException);
        Assert.DoesNotContain("PRIVATE", error.ToString());
    }

    [Fact] public async Task ExactPortableKeyAndSingleAtomicWholeSecondCommand()
    {
        var (store, proxy) = Mock();
        var scope = new ReplayScope("app", "key", Nonce);
        Assert.Equal("appguard:v0:replay:1a3a9e8f54a1f78b7dd93d4bb4bbd47ac0767b406779f6dfb309b40b6eb97ab2", scope.StorageKey);
        Assert.True(await store.ClaimAsync(scope, 250, 100));
        Assert.Equal(1, proxy.Calls); Assert.Equal("SET", proxy.Command);
        Assert.Equal(new object[] { scope.StorageKey, "1", "NX", "EX", "150" }, proxy.Arguments);
        proxy.Reply = () => Task.FromResult(RedisResult.Create(RedisValue.Null));
        Assert.False(await store.ClaimAsync(scope, 101, 100));
    }

    [Theory]
    [InlineData(-1, 1)] [InlineData(0, 0)] [InlineData(100, 99)]
    [InlineData(0, 151)] [InlineData(999999999999999, 1000000000000000)]
    [InlineData(long.MinValue, long.MaxValue)]
    public async Task InvalidTimesNeverReachRedis(long now, long expires)
    {
        var (store, proxy) = Mock();
        Redacted(await Assert.ThrowsAsync<AppGuardException>(() => store.ClaimAsync(Scope(), expires, now).AsTask()));
        Assert.Equal(0, proxy.Calls);
    }

    [Fact] public async Task InvalidScopeAndNullDatabaseRejectBeforeMutation()
    {
        Assert.Throws<ArgumentNullException>(() => new RedisReplayStore(null!));
        var (store, proxy) = Mock();
        Redacted(await Assert.ThrowsAsync<AppGuardException>(() => store.ClaimAsync(null!, 101, 100).AsTask()));
        foreach (var nonce in new[] { "", Nonce + "=", "AAECAwQFBgcICQoLDA0ODx", "PRIVATE" })
            Redacted(Assert.Throws<AppGuardException>(() => new ReplayScope("app", "key", nonce)));
        Redacted(Assert.Throws<AppGuardException>(() => new ReplayScope("app\nPRIVATE", "key", Nonce)));
        Assert.Equal(0, proxy.Calls);
    }

    [Fact] public async Task BackendFailuresAndUnexpectedRepliesFailClosedAndPrivate()
    {
        var (store, proxy) = Mock();
        foreach (var reply in new Func<Task<RedisResult>>[] {
            () => throw new InvalidOperationException("PRIVATE redis://user:password@host"),
            () => Task.FromException<RedisResult>(new TimeoutException("PRIVATE")),
            () => Task.FromException<RedisResult>(new OperationCanceledException("PRIVATE")),
            () => Task.FromResult<RedisResult>(null!),
            () => Task.FromResult(RedisResult.Create("OK", ResultType.BulkString)),
            () => Task.FromResult(RedisResult.Create(Array.Empty<RedisResult>())),
            () => Task.FromResult(RedisResult.Create("PRIVATE", ResultType.SimpleString)),
            () => Task.FromResult(RedisResult.Create(1)) })
        {
            proxy.Reply = reply;
            Redacted(await Assert.ThrowsAsync<AppGuardException>(() => store.ClaimAsync(Scope(), 101, 100).AsTask()));
        }
    }

    [Fact] public async Task CancellationBeforeAndDuringPendingClaimNeverReturnsSuccess()
    {
        var (store, proxy) = Mock();
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.ClaimAsync(Scope(), 101, 100, canceled.Token).AsTask());
        Assert.Equal(canceled.Token, error.CancellationToken); Assert.Equal(0, proxy.Calls);
        using var pendingCancellation = new CancellationTokenSource();
        var pending = new TaskCompletionSource<RedisResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        proxy.Reply = () => pending.Task;
        var claim = store.ClaimAsync(Scope(), 101, 100, pendingCancellation.Token).AsTask();
        pendingCancellation.Cancel();
        error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => claim.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.Equal(pendingCancellation.Token, error.CancellationToken);
        pending.SetResult(RedisResult.Create("OK", ResultType.SimpleString));
        Assert.Equal(1, proxy.Calls);
    }

    [Fact] public async Task CancellationInsideCommandCompletionCannotReturnALateSuccess()
    {
        var (store, proxy) = Mock(); using var cancellation = new CancellationTokenSource();
        proxy.Reply = () => {
            cancellation.Cancel(); return Task.FromResult(RedisResult.Create("OK", ResultType.SimpleString));
        };
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.ClaimAsync(Scope(), 101, 100, cancellation.Token).AsTask());
        Assert.Equal(cancellation.Token, error.CancellationToken); Assert.Equal(1, proxy.Calls);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static async Task<WeakReference> CanceledBackendFault(string marker)
    {
        var (store, proxy) = Mock();
        var pending = new TaskCompletionSource<RedisResult>();
        proxy.Reply = () => pending.Task;
        using var cancellation = new CancellationTokenSource();
        var claim = store.ClaimAsync(Scope(), 130, 100, cancellation.Token).AsTask();
        cancellation.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => claim);
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.Null(error.InnerException);
        pending.SetException(new InvalidOperationException(marker));
        proxy.Reply = () => Task.FromResult(RedisResult.Create("OK", ResultType.SimpleString));
        return new WeakReference(pending.Task);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static WeakReference UnobservedControlFault(string marker) =>
        new(Task.FromException(new InvalidOperationException(marker)));

    [Fact] public async Task CancellationConsumesLatePrivateFaultWithoutRetainingTaskOrPublishingIt()
    {
        var privateMarker = "PRIVATE-late-backend-" + Guid.NewGuid().ToString("N");
        var controlMarker = "control-unobserved-" + Guid.NewGuid().ToString("N");
        using var privateSeen = new ManualResetEventSlim();
        using var controlSeen = new ManualResetEventSlim();
        EventHandler<UnobservedTaskExceptionEventArgs> handler = (_, args) => {
            foreach (var error in args.Exception.Flatten().InnerExceptions)
            {
                if (error.Message == privateMarker) privateSeen.Set();
                if (error.Message == controlMarker) controlSeen.Set();
            }
            args.SetObserved();
        };
        TaskScheduler.UnobservedTaskException += handler;
        try
        {
            var backend = await CanceledBackendFault(privateMarker);
            var control = UnobservedControlFault(controlMarker);
            for (var attempt = 0; attempt < 50 && (!controlSeen.IsSet || backend.IsAlive || control.IsAlive); attempt++)
            {
                GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
                await Task.Delay(10);
            }
            Assert.True(controlSeen.IsSet, "Control fault must prove the unobserved-event check ran.");
            Assert.False(backend.IsAlive, "Cancellation must not retain the failed backend task.");
            Assert.False(privateSeen.IsSet, "A private late backend fault reached the host's unobserved-task event.");
        }
        finally { TaskScheduler.UnobservedTaskException -= handler; }
    }

    public sealed class RedisFactAttribute : FactAttribute
    {
        public RedisFactAttribute()
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("APPGUARD_TEST_REDIS_URL")))
                Skip = "Requires APPGUARD_TEST_REDIS_URL pointing to an owned disposable Redis.";
        }
    }
    static ConfigurationOptions LiveConfiguration()
    {
        var uri = new Uri(Environment.GetEnvironmentVariable("APPGUARD_TEST_REDIS_URL")!);
        // This test harness deliberately accepts only an owned, credential-free loopback instance.
        if (uri.Scheme != "redis" || !uri.IsLoopback || !string.IsNullOrEmpty(uri.UserInfo) ||
            !int.TryParse(uri.AbsolutePath.TrimStart('/'), out var database) || database < 0 || database > 15)
            throw new InvalidOperationException("Disposable loopback Redis database URL required.");
        return new ConfigurationOptions {
            EndPoints = { { uri.Host, uri.Port } }, DefaultDatabase = database,
            ConnectTimeout = 3000, AsyncTimeout = 3000, AbortOnConnectFail = true
        };
    }

    [RedisFact] public async Task LiveIndependentClientsHaveOneWinnerAndPreserveScopesAndTtl()
    {
        using var first = await ConnectionMultiplexer.ConnectAsync(LiveConfiguration());
        using var second = await ConnectionMultiplexer.ConnectAsync(LiveConfiguration());
        var a = new RedisReplayStore(first.GetDatabase()); var b = new RedisReplayStore(second.GetDatabase());
        var scope = Scope();
        var separateKey = new ReplayScope(scope.AppId, "other", scope.Nonce);
        var separateApp = Scope();
        var separateNonce = new ReplayScope(scope.AppId, scope.KeyId,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        var scopes = new[] { scope, separateKey, separateApp, separateNonce };
        try
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 48).Select(i =>
                (i % 2 == 0 ? a : b).ClaimAsync(scope, 130, 100).AsTask()));
            Assert.Equal(1, results.Count(x => x));
            Assert.False(await b.ClaimAsync(scope, 130, 100));
            Assert.Equal("1", (string?)await second.GetDatabase().StringGetAsync(scope.StorageKey));
            var ttl = await second.GetDatabase().KeyTimeToLiveAsync(scope.StorageKey);
            Assert.True(ttl > TimeSpan.Zero && ttl <= TimeSpan.FromSeconds(30));
            foreach (var distinct in scopes.Skip(1)) Assert.True(await b.ClaimAsync(distinct, 130, 100));
        }
        finally { foreach (var owned in scopes) await first.GetDatabase().KeyDeleteAsync(owned.StorageKey); }
    }

    [RedisFact] public async Task LiveExpiryAllowsClaimAgainFromIndependentConnection()
    {
        using var first = await ConnectionMultiplexer.ConnectAsync(LiveConfiguration());
        using var second = await ConnectionMultiplexer.ConnectAsync(LiveConfiguration());
        var scope = Scope(); var a = new RedisReplayStore(first.GetDatabase()); var b = new RedisReplayStore(second.GetDatabase());
        try
        {
            Assert.True(await a.ClaimAsync(scope, 101, 100));
            Assert.False(await b.ClaimAsync(scope, 101, 100));
            await Task.Delay(1200);
            Assert.True(await b.ClaimAsync(scope, 102, 101));
        }
        finally { await first.GetDatabase().KeyDeleteAsync(scope.StorageKey); }
    }

    [RedisFact] public async Task LiveDisposedClientFailureIsRedactedAndMiddlewareNeverDispatches()
    {
        var connection = await ConnectionMultiplexer.ConnectAsync(LiveConfiguration());
        var store = new RedisReplayStore(connection.GetDatabase());
        await connection.CloseAsync(); connection.Dispose();
        Redacted(await Assert.ThrowsAsync<AppGuardException>(() => store.ClaimAsync(Scope(), 101, 100).AsTask()));
        using var signed = new SecurityTests.Signed();
        Redacted(await Assert.ThrowsAsync<AppGuardException>(() => Verifier.VerifyAsync(signed.Request,
            signed.Parameters, signed.Signature, signed.Context(store)).AsTask()));
        var context = MiddlewareTests.Context(signed); var dispatched = false;
        var options = new AppGuard.AspNetCore.AppGuardOptions("app", "https://api.example.test", store,
            (_, _) => ValueTask.FromResult<string?>("subject"),
            (_, _, _, _) => ValueTask.FromResult<KeyRecord?>(signed.Key), () => 100, true);
        await new AppGuard.AspNetCore.AppGuardMiddleware(_ => {
            dispatched = true; return Task.CompletedTask;
        }, options).InvokeAsync(context);
        Assert.False(dispatched); Assert.Equal(503, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        Assert.Equal("{\"code\":\"REPLAY_STORE_UNAVAILABLE\"}", await new StreamReader(context.Response.Body).ReadToEndAsync());
    }
}
