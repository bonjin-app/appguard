<?php
use AppGuard\{RequestInput,SignatureParameters,KeyRecord,Canonical,Wire,Verifier,InMemoryReplayStore,ReplayStore,VerificationError,Policy,PolicyContext,PolicyEngine,PolicyDecision,PolicyError,Audit,JsonAuditSink,HttpAdapter,HttpEvidence,HttpFailure};
$private=openssl_pkey_new(['config'=>__DIR__.'/fixtures/openssl.cnf','private_key_type'=>OPENSSL_KEYTYPE_EC,'curve_name'=>'prime256v1']);$details=openssl_pkey_get_details($private);$generatedKey=new KeyRecord('test-app','test-key','test-user',$details['key'],Canonical::ALGORITHM,false);
openssl_sign(Canonical::signatureBase($r,$p,'https://api.example.test'),$der,$private,OPENSSL_ALGO_SHA256);$raw=AppGuard\P256::derToRaw($der);eq(strlen($raw),64,'OpenSSL DER raw width');eq($verify(signature:$raw,key:$generatedKey)->code,'VERIFIED','independent generated signature');eq(AppGuard\P256::rawToDer($raw),$der,'canonical DER round trip');
foreach(["",$der."\0","\x30\x81".substr($der,1),"\x30\x06\x02\x01\0\x02\x01\1", "\x30\x07\x02\x02\0\1\x02\x01\1"] as $bad)eq(code(fn()=>AppGuard\P256::derToRaw($bad)),'INVALID_SIGNATURE','strict DER');
foreach([str_repeat("\0",64),hex2bin('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551').str_repeat("\1",32)] as $bad)eq(code(fn()=>AppGuard\P256::rawToDer($bad)),'INVALID_SIGNATURE','scalar range');
foreach(['secp384r1','secp256k1'] as $curve){$pk=openssl_pkey_new(['config'=>__DIR__.'/fixtures/openssl.cnf','private_key_type'=>OPENSSL_KEYTYPE_EC,'curve_name'=>$curve]);$badKey=new KeyRecord('test-app','test-key','test-user',openssl_pkey_get_details($pk)['key'],Canonical::ALGORITHM,false);eq(code(fn()=>$verify(key:$badKey)),'KEY_REJECTED','wrong curve');}
$revoked=new KeyRecord('test-app','test-key','test-user',$details['key'],Canonical::ALGORITHM,true);eq(code(fn()=>$verify(key:$revoked)),'KEY_REJECTED','revocation');
// Named-curve compressed SEC1 points are also valid SPKI P-256 public keys.
$pointX=str_pad($details['ec']['x'],32,"\0",STR_PAD_LEFT);$pointY=$details['ec']['y'];$point=chr(2+(ord(substr($pointY,-1))&1)).$pointX;
$compressedDer=hex2bin('3039301306072a8648ce3d020106082a8648ce3d030107032200').$point;
$compressedPem="-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($compressedDer),64,"\n")."-----END PUBLIC KEY-----\n";
$compressedKey=new KeyRecord('test-app','test-key','test-user',$compressedPem,Canonical::ALGORITHM,false);eq($verify(signature:$raw,key:$compressedKey)->code,'VERIFIED','compressed P256 SPKI');
$binary="\0\xff{}\r\n";$binaryHeaders=$r->headers;$binaryHeaders[1]=['Content-Digest','sha-256=:'.base64_encode(hash('sha256',$binary,true)).':'];$binaryRequest=new RequestInput('POST','/binary?',$binaryHeaders,$binary);
openssl_sign(Canonical::signatureBase($binaryRequest,$p,'https://api.example.test'),$binaryDer,$private,OPENSSL_ALGO_SHA256);$binaryRaw=AppGuard\P256::derToRaw($binaryDer);
eq($verify(request:$binaryRequest,signature:$binaryRaw,key:$generatedKey)->code,'VERIFIED','binary body and empty query exact bytes');eq(code(fn()=>$verify(request:new RequestInput('POST','/binary',$binaryHeaders,$binary),signature:$binaryRaw,key:$generatedKey)),'INVALID_SIGNATURE','lost empty query rejects');
