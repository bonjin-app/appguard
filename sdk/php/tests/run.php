<?php
declare(strict_types=1);
$lib=__DIR__.'/../src/AppGuard.php';
if (!is_file($lib)) { fwrite(STDERR,"FAIL: strict PHP SDK API is not implemented\n"); exit(1); }
require $lib;
require __DIR__.'/../src/Policy.php';
require __DIR__.'/../src/HttpAdapter.php';
use AppGuard\{RequestInput,SignatureParameters,KeyRecord,Canonical,Wire,Verifier,InMemoryReplayStore,ReplayStore,VerificationError,Policy,PolicyContext,PolicyEngine,PolicyDecision,PolicyError,Audit,JsonAuditSink,HttpAdapter,HttpEvidence,HttpFailure};
$count=0;
function check(bool $ok,string $message):void { global $count; $count++; if(!$ok) throw new RuntimeException($message); }
function eq(mixed $got,mixed $want,string $label):void { check($got===$want,$label.': got '.json_encode($got).' want '.json_encode($want)); }
function code(callable $run):string { try{$r=$run();return is_object($r)&&isset($r->code)?$r->code:'OK';}catch(VerificationError|PolicyError $e){check($e->getMessage()===$e->reason&&$e->getPrevious()===null,'fixed redacted error');return $e->reason;} }
function request(array $v):RequestInput{return new RequestInput($v['method'],$v['target'],$v['headers'],base64_decode($v['body_b64'],true));}
function params(array $v):SignatureParameters{return new SignatureParameters(...$v);}
function keyRecord(array $v):KeyRecord{return new KeyRecord(...$v);}
function vectors(string $name):array{return json_decode(file_get_contents(__DIR__.'/../../../conformance/v0/'.$name.'.json'),true,512,JSON_THROW_ON_ERROR);}
$rows=vectors('requests');eq(count($rows),40,'request corpus count');
foreach($rows as $v){
 $store=new InMemoryReplayStore($v['replay_store']==='full'?1:10000);
 if($v['replay_store']==='full')$store->claim(['other-app','other-key','AAAAAAAAAAAAAAAAAAAAAA'],1700000120,1700000000);
 if($v['replay_store']==='unavailable')$store=new class implements ReplayStore{public function claim(array $scope,mixed $expires,mixed $now):mixed{throw new RuntimeException('SECRET');}};
 foreach($v['expected_codes'] as $expected){$actual=code(fn()=>Verifier::verify(request($v['request']),params($v['parameters']),base64_decode($v['signature_b64']),...array_merge($v['context'],['key'=>keyRecord($v['key']),'replay'=>$store])));eq($actual,$expected,'request '.$v['id']);}
 if($v['expected_signature_base']!==null)eq(Canonical::signatureBase(request($v['request']),params($v['parameters']),$v['context']['origin']),$v['expected_signature_base'],'base '.$v['id']);
}
$rows=vectors('http');eq(count($rows),43,'wire corpus count');
foreach($rows as $v){$parsed=null;$actual=code(function()use($v,&$parsed){$parsed=Wire::parse($v['headers']);return (object)['code'=>'PARSED'];});eq($actual,$v['expected_code'],'wire '.$v['id']);if($actual==='PARSED'){eq(get_object_vars($parsed->parameters),$v['expected']['parameters'],'wire params');eq(base64_encode($parsed->signature),$v['expected']['signature_b64'],'wire signature');}}
$rows=vectors('policy');eq(count($rows),42,'policy corpus count');
$localRisk=vectors('local-risk-policy');eq(count($localRisk),24,'local risk policy corpus count');
foreach(array_merge($rows,$localRisk) as $v){eq(get_object_vars(PolicyEngine::evaluate(new Policy(...$v['policy']),new PolicyContext(...$v['context']),$v['now'])),$v['expected'],'policy '.$v['id']);}
require __DIR__.'/security.php';
$count+=require __DIR__.'/error_status.php';
echo "PASS: 40 request, 43 HTTP, 42 baseline+24 local-risk policy vectors; $count assertions\n";
