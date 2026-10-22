<?php
declare(strict_types=1);
use AppGuard\{VerificationError,HttpAdapter,HttpEvidence,HttpFailure,RequestInput,KeyRecord,ReplayStore,InMemoryReplayStore,Wire};

// Standalone execution can exercise a genuinely installed Composer package.
if(!class_exists(VerificationError::class,false)){
    $autoload=getenv('APPGUARD_TEST_AUTOLOAD');
    if($autoload!==false)require $autoload;
    else{require __DIR__.'/../src/AppGuard.php';require __DIR__.'/../src/HttpAdapter.php';}
}
return (static function():int{
    $cases=0;$failures=[];
    $check=static function(bool $ok,string $label)use(&$cases,&$failures):void{$cases++;if(!$ok)$failures[]=$label;};
    $counts=['auth'=>0,'key'=>0,'clock'=>0,'replay'=>0,'next'=>0];
    $zero=$counts;$native=(object)['existing'=>'preserved'];
    $path=getenv('APPGUARD_TEST_REQUEST_CORPUS')?:__DIR__.'/../../../conformance/v0/requests.json';
    $vector=json_decode(file_get_contents($path),true,512,JSON_THROW_ON_ERROR)[0];
    $store=new InMemoryReplayStore();
    $replay=new class($store,static function()use(&$counts):void{$counts['replay']++;}) implements ReplayStore{
        public function __construct(private InMemoryReplayStore $store,private Closure $called){}
        public function claim(array $scope,mixed $expires,mixed $now):mixed{($this->called)();return $this->store->claim($scope,$expires,$now);}
    };
    $adapter=new HttpAdapter('https://api.example.test','test-app',
        static function()use(&$counts):string{$counts['auth']++;return 'test-user';},
        static function()use(&$counts,$vector):KeyRecord{$counts['key']++;return new KeyRecord(...$vector['key']);},
        $replay,static function()use(&$counts):int{$counts['clock']++;return 1700000000;});
    $next=static function($original,$verified)use(&$counts,$native,$vector):array{
        $counts['next']++;
        return [$original===$native,$original->existing,$verified->result->code,
            $verified->request->body===base64_decode($vector['request']['body_b64'],true),
            $verified->request->target===$vector['request']['target']];
    };
    $failure=static function(string $label,callable $capture,string $reason,int $status)use($adapter,$native,$next,$check,&$counts,$zero):void{
        $out=$adapter->handle($native,$capture,$next);
        $check($out instanceof HttpFailure&&$out->status===$status&&$out->body===json_encode(['code'=>$reason])&&
            $counts===$zero&&get_object_vars($native)===['existing'=>'preserved'],$label);
    };
    // Literal protocol/SDK mapping; expected values do not use the constructor.
    $reasons=['INVALID_REQUEST'=>400,'UNSUPPORTED_PROFILE'=>403,'INVALID_TIME'=>403,'KEY_REJECTED'=>403,
        'DIGEST_MISMATCH'=>403,'INVALID_SIGNATURE'=>403,'REPLAY_DETECTED'=>403,'REPLAY_STORE_UNAVAILABLE'=>503,
        'AUTHENTICATION_REQUIRED'=>401,'IDENTITY_UNAVAILABLE'=>503,'KEY_RESOLVER_UNAVAILABLE'=>503,'VERIFICATION_UNAVAILABLE'=>503];
    foreach($reasons as $reason=>$default){
        foreach([null,200,413] as $override){
            $wanted=$reason==='INVALID_REQUEST'&&$override===413?413:$default;
            $failure($reason.'/'.($override??'default'),static fn()=>throw new VerificationError($reason,$override),$reason,$wanted);
        }
    }
    foreach([PHP_INT_MIN,-1,0,100,199,204,302,418,599,600,PHP_INT_MAX] as $override)
        $failure('invalid-status/'.$override,static fn()=>throw new VerificationError('INVALID_REQUEST',$override),'INVALID_REQUEST',400);
    foreach([null,200,413] as $override)
        $failure('unknown-reason/'.($override??'default'),static fn()=>throw new VerificationError('TEST_ONLY_SECRET',$override),
            'INVALID_REQUEST',$override===413?413:400);
    $failure('generic-exception',static fn()=>throw new RuntimeException('TEST_ONLY_SECRET'),'INVALID_REQUEST',400);
    $failure('type-error',static fn()=>throw new TypeError('TEST_ONLY_SECRET'),'INVALID_REQUEST',400);
    $failure('real-header-overflow',static fn()=>Wire::framing([['Content-Length','1048577']]),'INVALID_REQUEST',413);
    $failure('real-captured-overflow',static fn()=>new HttpEvidence(new RequestInput('POST','/',[],str_repeat('x',1048577)),true),'INVALID_REQUEST',413);
    $stream=fopen('php://temp','w+b');fwrite($stream,str_repeat('x',1048577));rewind($stream);
    try{$failure('real-stream-overflow',static fn()=>HttpEvidence::fromStream('POST','/',[],$stream,true),'INVALID_REQUEST',413);}
    finally{fclose($stream);}

    // Failed capture must not consume a nonce; a real signed retry succeeds once.
    $wire=json_decode(file_get_contents(dirname($path).'/http.json'),true,512,JSON_THROW_ON_ERROR)[0]['headers'];
    $request=new RequestInput($vector['request']['method'],$vector['request']['target'],$wire,base64_decode($vector['request']['body_b64'],true));
    $capture=static fn()=>new HttpEvidence($request,true);
    $out=$adapter->handle($native,$capture,$next);
    $check($out===[true,'preserved','VERIFIED',true,true]&&$counts===['auth'=>1,'key'=>1,'clock'=>1,'replay'=>1,'next'=>1],'signed-retry');
    $out=$adapter->handle($native,$capture,$next);
    $check($out instanceof HttpFailure&&$out->status===403&&$out->body==='{"code":"REPLAY_DETECTED"}'&&
        $counts===['auth'=>2,'key'=>2,'clock'=>2,'replay'=>2,'next'=>1],'signed-replay');
    echo 'STATUS_CASES ',json_encode(['cases'=>$cases,'passed'=>$cases-count($failures),'failed'=>count($failures),'failures'=>$failures],JSON_THROW_ON_ERROR),"\n";
    if($failures!==[])throw new RuntimeException('HTTP failure status normalization regressions');
    return $cases;
})();
