<?php
/** Test-only public-fixture consumer. No private keys, accounts or network I/O. */
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use AppGuard\{Canonical,RequestInput,SignatureParameters,KeyRecord,Wire,Verifier,InMemoryReplayStore,VerificationError};
function requireTrue(bool $ok):void{if(!$ok)throw new RuntimeException('PUBLIC_FIXTURE_FAILED');}
function verifyPublic(array $v):void{
 $r=$v['request'];$context=$v['context'];$body=base64_decode($r['body_b64'],true);$signature=base64_decode($v['signature_b64'],true);requireTrue(is_string($body)&&is_string($signature));
 $request=new RequestInput($r['method'],$r['target'],$r['headers'],$body);$parameters=new SignatureParameters(...$v['parameters']);$key=new KeyRecord(...$v['key']);
 $parsed=Wire::parse($request->headers);requireTrue(get_object_vars($parsed->parameters)===get_object_vars($parameters)&&$parsed->signature===$signature);
 $run=fn($input,$store)=>Verifier::verify($input,$parsed->parameters,$parsed->signature,$context['origin'],$context['app_id'],$context['subject'],$context['now'],$key,$store);
 $replay=new InMemoryReplayStore();requireTrue($run($request,$replay)->code==='VERIFIED');
 try{$run($request,$replay);throw new RuntimeException('REPLAY_ACCEPTED');}catch(VerificationError $e){requireTrue($e->reason==='REPLAY_DETECTED');}
 $headers=[];foreach($request->headers as [$name,$value])$headers[]=[$name,strtolower($name)==='authorization'?'Bearer OTHER_TOKEN':$value];
 $variants=[new RequestInput($request->method,$request->target,$request->headers,$request->body.'!'),new RequestInput($request->method,'/different-target',$request->headers,$request->body),new RequestInput($request->method,$request->target,$headers,$request->body)];
 foreach($variants as $i=>$variant){try{$run($variant,new InMemoryReplayStore());throw new RuntimeException('MUTATION_ACCEPTED');}catch(VerificationError $e){requireTrue($e->reason===($i===0?'DIGEST_MISMATCH':'INVALID_SIGNATURE'));}}
 echo "PHP_NATIVE_CLIENT_VERIFIED_REPLAY_AND_MUTATIONS_REJECTED\n";
}
try{
 $raw=stream_get_contents(STDIN,2097153);requireTrue(is_string($raw)&&strlen($raw)<=2097152);$values=json_decode($raw,true,512,JSON_THROW_ON_ERROR);requireTrue(is_array($values));if(!array_is_list($values))$values=[$values];requireTrue(count($values)>=1&&count($values)<=100);
 foreach($values as $value){requireTrue(is_array($value));verifyPublic($value);}
}catch(Throwable){fwrite(STDERR,"PUBLIC_FIXTURE_FAILED\n");exit(1);}
