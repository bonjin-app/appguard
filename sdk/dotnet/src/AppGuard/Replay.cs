using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace AppGuard;
public sealed record ReplayScope
{
    public string AppId{get;}public string KeyId{get;}public string Nonce{get;}
    public ReplayScope(string appId,string keyId,string nonce)
    {
        try{Validation.Identifier(appId);Validation.Identifier(keyId);Validation.Nonce(nonce);}catch(AppGuardException){throw new AppGuardException("REPLAY_STORE_UNAVAILABLE");}
        AppId=appId;KeyId=keyId;Nonce=nonce;
    }
    /// <summary>The portable compact-JSON SHA256 key; no Redis backend is supplied by this package.</summary>
    public string StorageKey=>"appguard:v0:replay:"+Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new[]{AppId,KeyId,Nonce}))));
}
/// <summary>Implement atomic single-winner claims for the whole deployment. Errors must throw; never fail open.</summary>
public interface IReplayStore
{
    ValueTask<bool> ClaimAsync(ReplayScope scope,long expires,long now,CancellationToken cancellationToken=default);
}
/// <summary>Explicit opt-in, volatile, bounded, process-local store for tests/development only.</summary>
public sealed class InMemoryReplayStore:IReplayStore
{
    readonly object _gate=new();readonly int _capacity;readonly Dictionary<ReplayScope,long> _claims=[];
    public InMemoryReplayStore(int capacity=10000){if(capacity<1)throw new ArgumentOutOfRangeException(nameof(capacity));_capacity=capacity;}
    public ValueTask<bool> ClaimAsync(ReplayScope scope,long expires,long now,CancellationToken cancellationToken=default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if(scope is null||!Validation.IsTime(now)||!Validation.IsTime(expires)||expires<=now||expires-now>150)throw new AppGuardException("REPLAY_STORE_UNAVAILABLE");
        lock(_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach(var key in _claims.Where(p=>p.Value<=now).Select(p=>p.Key).ToArray())_claims.Remove(key);
            if(_claims.ContainsKey(scope))return ValueTask.FromResult(false);
            if(_claims.Count>=_capacity)throw new AppGuardException("REPLAY_STORE_UNAVAILABLE");
            _claims.Add(scope,expires);return ValueTask.FromResult(true);
        }
    }
}
