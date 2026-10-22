<?php
declare(strict_types=1);
require_once __DIR__.'/../src/RedisReplayStore.php';
final class RecordingRedisClient implements AppGuard\RedisCommandClient {
    public array $commands=[];
    public mixed $result='OK';
    public function execute(array $command):mixed {$this->commands[]=$command;if($this->result instanceof Throwable)throw $this->result;return $this->result;}
}
$redisClient=new RecordingRedisClient();$redisStore=new AppGuard\RedisReplayStore($redisClient);
$redisScope=['app','key','AAAAAAAAAAAAAAAAAAAAAA'];
$expectedRedisKey='appguard:v0:replay:'.hash('sha256','["app","key","AAAAAAAAAAAAAAAAAAAAAA"]');
eq($redisStore->claim($redisScope,101,100),true,'Redis claim');
eq($redisClient->commands,[['SET',$expectedRedisKey,'1','NX','EX','1']],'one exact Redis command');
eq(AppGuard\RedisReplayStore::key($redisScope),$expectedRedisKey,'canonical Redis key');
$redisClient->result=null;eq($redisStore->claim($redisScope,250,100),false,'Redis conflict');
eq($redisClient->commands[1][5],'150','maximum TTL');
foreach([true,false,1,0,'ok','QUEUED','',[],new stdClass(),new RuntimeException('SECRET redis://user:password@host')] as $result){$redisClient->result=$result;eq(code(fn()=>$redisStore->claim($redisScope,101,100)),'REPLAY_STORE_UNAVAILABLE','strict Redis return/error redaction');}
foreach([[['app','key','bad'],101,100],[['app','key','AAAAAAAAAAAAAAAAAAAAAB'],101,100],[['app','key','AAAAAAAAAAAAAAAAAAAAAA','extra'],101,100],[['app/key','key','AAAAAAAAAAAAAAAAAAAAAA'],101,100],[['app','key','AAAAAAAAAAAAAAAAAAAAAA'],251,100],[['app','key','AAAAAAAAAAAAAAAAAAAAAA'],100,100],[['app','key','AAAAAAAAAAAAAAAAAAAAAA'],101.0,100],[['app','key','AAAAAAAAAAAAAAAAAAAAAA'],101,true]] as $invalid){$before=count($redisClient->commands);eq(code(fn()=>$redisStore->claim(...$invalid)),'REPLAY_STORE_UNAVAILABLE','invalid Redis scope/deadline');eq(count($redisClient->commands),$before,'invalid Redis never reaches client');}
