using System.Globalization;
using AppGuard;
using StackExchange.Redis;

// Test-only independent-process cross-SDK claim probe. No key deletion or server mutation.
try
{
    if (args.Length != 6) throw new ArgumentException();
    var uri = new Uri(args[0]);
    if (uri.Scheme != "redis" || !uri.IsLoopback || !string.IsNullOrEmpty(uri.UserInfo) ||
        !int.TryParse(uri.AbsolutePath.TrimStart('/'), out var database) || database < 0 || database > 15)
        throw new ArgumentException();
    var options = new ConfigurationOptions {
        EndPoints = { { uri.Host, uri.Port } }, DefaultDatabase = database,
        ConnectTimeout = 3000, AsyncTimeout = 3000, AbortOnConnectFail = true
    };
    using var client = await ConnectionMultiplexer.ConnectAsync(options);
    var claimed = await new RedisReplayStore(client.GetDatabase()).ClaimAsync(
        new ReplayScope(args[1], args[2], args[3]),
        long.Parse(args[5], CultureInfo.InvariantCulture), long.Parse(args[4], CultureInfo.InvariantCulture));
    Console.WriteLine(claimed ? "CLAIMED" : "REPLAY");
    return 0;
}
catch (Exception)
{
    Console.Error.WriteLine("REPLAY_STORE_UNAVAILABLE");
    return 2;
}
