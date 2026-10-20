<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use AppGuard\{HttpAdapter,HttpEvidence,RequestInput,KeyRecord,InMemoryReplayStore,HttpFailure};
$v=json_decode(file_get_contents(__DIR__.'/../../../conformance/v0/requests.json'),true)[0];
$server=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);if(!$server)exit(2);
echo stream_socket_get_name($server,false),"\n";flush();
$adapter=new HttpAdapter('https://api.example.test','test-app',fn($native,$request)=>$native->authenticatedSubject,fn()=>new KeyRecord(...$v['key']),new InMemoryReplayStore(),fn()=>1700000000,allowInsecure:true);
for($i=0;$i<5;$i++){
 $socket=stream_socket_accept($server,15);if(!$socket)exit(3);stream_set_timeout($socket,5);
 $line=fgets($socket,8200);$parts=explode(' ',rtrim($line,"\r\n"));$headers=[];$length=0;
 while(($line=fgets($socket,17000))!==false&&$line!=="\r\n"){$colon=strpos($line,':');if($colon===false)exit(4);$name=substr($line,0,$colon);$value=rtrim(substr($line,$colon+1),"\r\n");if(str_starts_with($value,' '))$value=substr($value,1);$headers[]=[$name,$value];if(strtolower($name)==='content-length')$length=(int)$value;}
 $body='';while(strlen($body)<$length){$chunk=fread($socket,$length-strlen($body));if($chunk===false||$chunk==='')exit(5);$body.=$chunk;}
 // This harness is the actual trusted ingress; it captured lines before normalization.
 // Only this local fixture substitutes an authenticated identity for an upstream auth layer.
 $native=(object)['authenticatedSubject'=>'test-user','existing'=>'preserved'];
 $capture=fn()=>$parts[1]==='/missing-evidence'?null:new HttpEvidence(new RequestInput($parts[0],$parts[1],$headers,$body),false);
 $response=$adapter->handle($native,$capture,fn($original,$verified)=>json_encode(['body_b64'=>base64_encode($verified->request->body),'existing'=>$original->existing,'verified'=>$verified->result->code],JSON_THROW_ON_ERROR));
 $status=$response instanceof HttpFailure?$response->status:200;$out=$response instanceof HttpFailure?$response->body:$response;
 fwrite($socket,"HTTP/1.1 $status Test\r\nContent-Type: application/json\r\nContent-Length: ".strlen($out)."\r\nConnection: close\r\n\r\n".$out);fclose($socket);
}
fclose($server);
