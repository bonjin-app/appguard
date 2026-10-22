using System.Globalization;
using StackExchange.Redis;

namespace AppGuard;

/// <summary>
/// Opt-in deployment-wide atomic replay claims using a host-configured Redis database.
/// The host owns connections, timeouts, persistence, replication, capacity and lifecycle.
/// </summary>
public sealed class RedisReplayStore : IReplayStore
{
    readonly IDatabaseAsync _database;

    /// <summary>Accepts an existing database; never connects or disposes the client.</summary>
    public RedisReplayStore(IDatabaseAsync database) =>
        _database = database ?? throw new ArgumentNullException(nameof(database));

    public async ValueTask<bool> ClaimAsync(ReplayScope scope, long expires, long now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (scope is null || !Validation.IsTime(now) || !Validation.IsTime(expires) ||
            expires <= now || expires - now > 150)
            throw new AppGuardException("REPLAY_STORE_UNAVAILABLE");

        Task<RedisResult>? pending = null;
        try
        {
            // Revalidate at the storage boundary, before issuing any command.
            var validated = new ReplayScope(scope.AppId, scope.KeyId, scope.Nonce);
            cancellationToken.ThrowIfCancellationRequested();
            // One atomic command, with explicit whole-second expiry and no fire-and-forget.
            pending = _database.ExecuteAsync("SET", new object[] {
                validated.StorageKey, "1", "NX", "EX",
                (expires - now).ToString(CultureInfo.InvariantCulture)
            });
            var result = await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (result is not null && result.Resp2Type == ResultType.BulkString && result.IsNull) return false;
            if (result is not null && result.Resp2Type == ResultType.SimpleString &&
                (string?)result == "OK") return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // WaitAsync cancels our wait, not the client operation. Observe any
            // later backend fault so the host's global unobserved-task handler
            // cannot receive private Redis endpoint/credential error details.
            // The static void continuation neither logs nor returns the error.
            if (pending is not null)
                _ = pending.ContinueWith(static completed => { _ = completed.Exception; },
                    CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted |
                    TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception)
        {
            // Redis errors may contain endpoints, credentials or request material.
            throw new AppGuardException("REPLAY_STORE_UNAVAILABLE");
        }
        throw new AppGuardException("REPLAY_STORE_UNAVAILABLE");
    }
}
