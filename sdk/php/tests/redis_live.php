<?php
declare(strict_types=1);
require __DIR__.'/../src/AppGuard.php';
require __DIR__.'/../src/RedisReplayStore.php';
try {
    if (!extension_loaded('redis')) throw new RuntimeException();
    $url=getenv('APPGUARD_TEST_REDIS_URL');
    if (!is_string($url) || $url==='') throw new RuntimeException();
    $parts=parse_url($url);
    if (!is_array($parts) || !in_array($parts['scheme']??'', ['redis','rediss'],true) || !isset($parts['host']) || isset($parts['query']) || isset($parts['fragment'])) throw new RuntimeException();
    $db=ltrim($parts['path']??'', '/');
    if ($db!=='' && !preg_match('/\A[0-9]{1,2}\z/D',$db)) throw new RuntimeException();
    $client=new Redis();
    if (!$client->connect(($parts['scheme']==='rediss'?'tls://':'').$parts['host'],$parts['port']??6379,2.0,null,0,2.0)) throw new RuntimeException();
    if (isset($parts['pass'])) {
        $auth=isset($parts['user'])&&$parts['user']!==''?[rawurldecode($parts['user']),rawurldecode($parts['pass'])]:rawurldecode($parts['pass']);
        if (!$client->auth($auth)) throw new RuntimeException();
    } elseif (isset($parts['user'])) throw new RuntimeException();
    if ($db!=='' && !$client->select((int)$db)) throw new RuntimeException();
    $action=$argv[1]??'';
    // Explicit host configuration, never an option changed by the SDK.
    if ($action!=='literal-required') $client->setOption(Redis::OPT_REPLY_LITERAL,true);
    $scope=['php-live',$argv[2]??'', $argv[3]??''];
    $store=new AppGuard\RedisReplayStore(new AppGuard\ExtRedisCommandClient($client));
    if ($action==='claim' || $action==='claim-literal') {
        if ($action==='claim-literal') {$client->setOption(Redis::OPT_REPLY_LITERAL,true);$client->setOption(Redis::OPT_PREFIX,'ignored-test-prefix:');$client->setOption(Redis::OPT_SERIALIZER,Redis::SERIALIZER_PHP);}
        if (getenv('APPGUARD_REDIS_BARRIER')==='1') {echo "READY\n";fflush(STDOUT);if(fread(STDIN,1)!=='1')throw new RuntimeException();}
        $now=time();echo $store->claim($scope,$now+(int)($argv[4]??'30'),$now)?"WON\n":"CONFLICT\n";
    } elseif ($action==='inspect') {
        $key=AppGuard\RedisReplayStore::key($scope);
        if ($client->rawCommand('GET',$key)!=='1') throw new RuntimeException();
        $ttl=$client->rawCommand('TTL',$key);
        if (!is_int($ttl)||$ttl<1||$ttl>30) throw new RuntimeException();
        echo "STORED\n";
    } elseif ($action==='delete') {
        $client->rawCommand('DEL',AppGuard\RedisReplayStore::key($scope));echo "DELETED\n";
    } elseif ($action==='mode') {
        $client->multi(Redis::PIPELINE);
        try {$store->claim($scope,time()+30,time());throw new RuntimeException();}
        catch (AppGuard\VerificationError $e) {if($e->reason!=='REPLAY_STORE_UNAVAILABLE'||$e->getPrevious()!==null)throw new RuntimeException();}
        $client->discard();echo "DENIED\n";
    } elseif ($action==='literal-required') {
        $client->setOption(Redis::OPT_REPLY_LITERAL,false);
        $key=AppGuard\RedisReplayStore::key($scope);
        try {
            try {$store->claim($scope,time()+30,time());throw new RuntimeException();}
            catch (AppGuard\VerificationError $e) {if($e->reason!=='REPLAY_STORE_UNAVAILABLE'||$e->getPrevious()!==null)throw new RuntimeException();}
            if ($client->getOption(Redis::OPT_REPLY_LITERAL)!==0||$client->rawCommand('EXISTS',$key)!==0) throw new RuntimeException();
            echo "DENIED\n";
        } finally {$client->rawCommand('DEL',$key);}
    } elseif ($action==='raw-mode') {
        $key=AppGuard\RedisReplayStore::key($scope);
        if ($client->rawCommand('MULTI')!=='OK'||$client->getMode()!==Redis::ATOMIC) throw new RuntimeException();
        try {
            try {$store->claim($scope,time()+30,time());throw new RuntimeException();}
            catch (AppGuard\VerificationError $e) {if($e->reason!=='REPLAY_STORE_UNAVAILABLE'||$e->getPrevious()!==null)throw new RuntimeException();}
        } finally {if($client->rawCommand('DISCARD')!=='OK')throw new RuntimeException();}
        if ($client->rawCommand('EXISTS',$key)!==0) throw new RuntimeException();
        echo "DENIED\n";
    } elseif ($action==='backend-error') {
        try {(new AppGuard\ExtRedisCommandClient($client))->execute(['APPGUARD_INVALID_TEST_COMMAND']);throw new RuntimeException();}
        catch (AppGuard\VerificationError $e) {if($e->reason!=='REPLAY_STORE_UNAVAILABLE'||$e->getPrevious()!==null)throw new RuntimeException();}
        echo "DENIED\n";
    } elseif ($action==='unavailable') {
        $client->close();
        $store=new AppGuard\RedisReplayStore(new AppGuard\ExtRedisCommandClient(new Redis()));
        try {$store->claim($scope,time()+30,time());throw new RuntimeException();}
        catch (AppGuard\VerificationError $e) {if($e->reason!=='REPLAY_STORE_UNAVAILABLE'||$e->getPrevious()!==null)throw new RuntimeException();}
        echo "DENIED\n";
    } elseif ($action==='cross') {
        if (count($argv)!==5 && count($argv)!==7) throw new RuntimeException();
        if (($parts['scheme']??'')!=='redis'||($parts['host']??'')!=='127.0.0.1'||isset($parts['user'])||isset($parts['pass'])||!isset($parts['port'])) throw new RuntimeException();
        $scope=[$argv[2],$argv[3],$argv[4]];$now=time();$expires=$now+30;
        if (count($argv)===7) {
            if (!preg_match('/\A[0-9]{1,12}\z/D',$argv[5])||!preg_match('/\A[0-9]{1,12}\z/D',$argv[6])) throw new RuntimeException();
            $now=(int)$argv[5];$expires=(int)$argv[6];
        }
        echo $store->claim($scope,$expires,$now)?"CLAIMED\n":"REPLAY\n";
    } else throw new RuntimeException();
} catch (Throwable) {fwrite(STDERR,"REDIS_LIVE_FAILED\n");exit(1);}
