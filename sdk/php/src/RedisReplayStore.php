<?php
declare(strict_types=1);
namespace AppGuard;

/** Host-owned synchronous client: exact SET returns 'OK' or null; all other outcomes fail. */
interface RedisCommandClient {
    public function execute(array $command):mixed;
}

/** Optional phpredis bridge. The host enables literal replies and owns TLS/timeouts. */
final class ExtRedisCommandClient implements RedisCommandClient {
    public function __construct(private \Redis $client) {}

    public function execute(array $command):mixed {
        try {
            // Default phpredis status coercion maps BOTH OK and QUEUED to true.
            // Require host-configured literal replies on every operation without
            // changing the host's options. Local mode alone cannot detect MULTI
            // started through rawCommand instead of phpredis's transaction API.
            if ($this->client->getMode() !== \Redis::ATOMIC ||
                $this->client->getOption(\Redis::OPT_REPLY_LITERAL) !== 1) throw new \RuntimeException();
            $this->client->clearLastError();
            // rawCommand avoids host serializers, compression and key-prefix rewriting.
            $result=$this->client->rawCommand(...$command);
            if ($this->client->getLastError() !== null) throw new \RuntimeException();
            if ($result === 'OK') return 'OK';
            if ($result === false || $result === null) return null;
        } catch (\Throwable) {
            throw new VerificationError('REPLAY_STORE_UNAVAILABLE');
        }
        throw new VerificationError('REPLAY_STORE_UNAVAILABLE');
    }
}

/** One shared canonical key and one atomic SET NX EX; never connects or falls back. */
final class RedisReplayStore implements ReplayStore {
    public function __construct(private RedisCommandClient $client) {}

    public static function key(array $scope):string {
        ReplayValidation::check($scope,1,0);
        return 'appguard:v0:replay:'.hash('sha256',json_encode($scope,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
    }

    public function claim(array $scope,mixed $expires,mixed $now):mixed {
        ReplayValidation::check($scope,$expires,$now);
        try {
            $result=$this->client->execute(['SET',self::key($scope),'1','NX','EX',(string)($expires-$now)]);
        } catch (\Throwable) {
            throw new VerificationError('REPLAY_STORE_UNAVAILABLE');
        }
        if ($result === 'OK') return true;
        if ($result === null) return false;
        throw new VerificationError('REPLAY_STORE_UNAVAILABLE');
    }
}
