<?php
declare(strict_types=1);
namespace AppGuard;

/** Fixed public reasons. Never retain a dependency exception as a previous exception. */
class VerificationError extends \RuntimeException {
    public readonly string $reason;
    public readonly int $status;
    private const CODES = ['INVALID_REQUEST','UNSUPPORTED_PROFILE','INVALID_TIME','KEY_REJECTED','DIGEST_MISMATCH','INVALID_SIGNATURE','REPLAY_DETECTED','REPLAY_STORE_UNAVAILABLE','AUTHENTICATION_REQUIRED','IDENTITY_UNAVAILABLE','KEY_RESOLVER_UNAVAILABLE','VERIFICATION_UNAVAILABLE'];
    public function __construct(string $reason='INVALID_REQUEST', ?int $status=null) {
        $this->reason=in_array($reason,self::CODES,true)?$reason:'INVALID_REQUEST';
        $this->status=$status??match($this->reason){'INVALID_REQUEST'=>400,'AUTHENTICATION_REQUIRED'=>401,'IDENTITY_UNAVAILABLE','KEY_RESOLVER_UNAVAILABLE','VERIFICATION_UNAVAILABLE','REPLAY_STORE_UNAVAILABLE'=>503,default=>403};
        parent::__construct($this->reason);
    }
}

final readonly class RequestInput {
    public string $method; public string $target; public array $headers; public string $body;
    public function __construct(mixed $method,mixed $target,mixed $headers,mixed $body) {
        if(!is_string($method)||!is_string($target)||!is_string($body))throw new VerificationError();
        Canonical::headers($headers); // Validate before making an immutable, reference-free copy.
        $pairs=[];foreach($headers as $pair)$pairs[]=[$pair[0],$pair[1]];
        $this->method=$method;$this->target=$target;$this->headers=$pairs;$this->body=$body;
    }
}
final readonly class SignatureParameters {
    public function __construct(public mixed $created,public mixed $expires,public mixed $nonce,public mixed $key_id,public mixed $algorithm=Canonical::ALGORITHM,public mixed $tag=Canonical::TAG) {}
}
final readonly class KeyRecord {
    public function __construct(public mixed $app_id,public mixed $key_id,public mixed $subject,public mixed $public_key_pem,public mixed $algorithm,public mixed $revoked,public mixed $expires_at=null) {}
    public function validContract():bool {
        return Canonical::identifier($this->app_id)&&Canonical::identifier($this->key_id)&&Canonical::identifier($this->subject)&&is_string($this->public_key_pem)&&is_string($this->algorithm)&&is_bool($this->revoked)&&($this->expires_at===null||Canonical::validTime($this->expires_at));
    }
}
final readonly class VerificationResult {
    public string $code;
    public function __construct(public string $app_id,public string $key_id,public int $expires){$this->code='VERIFIED';}
}
final readonly class ParsedSignature {
    public function __construct(public SignatureParameters $parameters,public string $signature){}
}

final class Canonical {
    public const ALGORITHM='ecdsa-p256-sha256';public const TAG='appguard-request-v0';
    public const COMPONENTS=['@method','@target-uri','content-type','content-digest','authorization','appguard-app-id'];
    public const COVERED='"@method" "@target-uri" "content-type" "content-digest" "authorization" "appguard-app-id"';
    private const TOKEN='/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+\z/';
    public static function validTime(mixed $value):bool{return is_int($value)&&$value>=0&&$value<=999999999999999;}
    public static function identifier(mixed $value):bool{return is_string($value)&&strlen($value)<=128&&preg_match('/\A[A-Za-z0-9._:-]{1,128}\z/',$value)===1;}
    public static function nonce(mixed $value):void{
        if(!is_string($value)||preg_match('/\A[A-Za-z0-9_-]{22}\z/',$value)!==1)throw new VerificationError();
        $bytes=base64_decode(strtr($value,'-_','+/').'==',true);
        if($bytes===false||strlen($bytes)!==16||rtrim(strtr(base64_encode($bytes),'+/','-_'),'=')!==$value)throw new VerificationError();
    }
    public static function origin(mixed $origin):void{
        if(!is_string($origin)||strlen($origin)>512||preg_match('/\Ahttps:\/\/([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?\z/',$origin,$m)!==1||strlen($m[1])>253)throw new VerificationError();
        foreach(explode('.',$m[1]) as $label)if(preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/',$label)!==1)throw new VerificationError();
        if(isset($m[2])&&((int)$m[2]>65535||(int)$m[2]===443))throw new VerificationError();
    }
    public static function target(mixed $target):void{
        if(!is_string($target)||strlen($target)>8192||str_starts_with($target,'//')||preg_match("/\A\/[A-Za-z0-9._~!$&'()*+,;=:@\/?%\\-]*\z/",$target)!==1||preg_match('/%(?![0-9A-Fa-f]{2})/',$target))throw new VerificationError();
        $decoded=rawurldecode($target);
        if(preg_match('/[\x00-\x1f\x7f\\\\]/',$decoded))throw new VerificationError();
        foreach(explode('/',rawurldecode(explode('?',$target,2)[0])) as $segment)if($segment==='.'||$segment==='..')throw new VerificationError();
    }
    public static function headers(mixed $headers,bool $wire=false):array{
        if(!is_array($headers)||!array_is_list($headers)||count($headers)>64)throw new VerificationError();
        $singletons=['content-type','content-digest','authorization','appguard-app-id','content-encoding'];
        if($wire)$singletons=[...$singletons,'signature-input','signature','content-length','transfer-encoding','host'];
        $map=[];$size=0;
        foreach($headers as $pair){
            if(!is_array($pair)||!array_is_list($pair)||count($pair)!==2||!is_string($pair[0])||!is_string($pair[1]))throw new VerificationError();
            [$name,$value]=$pair;$size+=strlen($name)+strlen($value);
            if($size>16384||preg_match(self::TOKEN,$name)!==1||preg_match('/\A[\x20-\x7e]*\z/',$value)!==1||str_starts_with($value,' ')||str_ends_with($value,' '))throw new VerificationError();
            $lower=strtolower($name);if(in_array($lower,$singletons,true)&&array_key_exists($lower,$map))throw new VerificationError();
            $map[$lower]=$value;
        }
        return $map;
    }
    public static function digest(mixed $field):string{
        if(!is_string($field)||preg_match('/\Asha-256=:([A-Za-z0-9+\/]{43}=):\z/',$field,$m)!==1)throw new VerificationError();
        $bytes=base64_decode($m[1],true);if($bytes===false||strlen($bytes)!==32||base64_encode($bytes)!==$m[1])throw new VerificationError();return $bytes;
    }
    public static function request(RequestInput $request):array{
        if(strlen($request->body)>1048576||strlen($request->method)>32||$request->method!==strtoupper($request->method)||preg_match(self::TOKEN,$request->method)!==1)throw new VerificationError();
        self::target($request->target);$headers=self::headers($request->headers);
        foreach(array_slice(self::COMPONENTS,2) as $name)if(!isset($headers[$name]))throw new VerificationError();
        if($headers['content-type']===''||isset($headers['content-encoding'])&&$headers['content-encoding']!=='identity'||preg_match('/\ABearer [A-Za-z0-9._~+\/-]+=*\z/i',$headers['authorization'])!==1||!self::identifier($headers['appguard-app-id']))throw new VerificationError();
        self::digest($headers['content-digest']);return $headers;
    }
    public static function parameters(SignatureParameters $p):void{
        if($p->algorithm!==self::ALGORITHM||$p->tag!==self::TAG)throw new VerificationError('UNSUPPORTED_PROFILE');
        if(!self::identifier($p->key_id))throw new VerificationError();self::nonce($p->nonce);
        if(!self::validTime($p->created)||!self::validTime($p->expires))throw new VerificationError('INVALID_TIME');
    }
    public static function serialize(SignatureParameters $p):string{
        return '('.self::COVERED.');created='.$p->created.';expires='.$p->expires.';nonce="'.$p->nonce.'";keyid="'.$p->key_id.'";alg="'.$p->algorithm.'";tag="'.$p->tag.'"';
    }
    public static function signatureBase(RequestInput $request,SignatureParameters $p,mixed $origin):string{
        $headers=self::request($request);self::origin($origin);self::parameters($p);
        $values=[$request->method,$origin.$request->target];foreach(array_slice(self::COMPONENTS,2) as $n)$values[]=$headers[$n];
        $lines=[];foreach(self::COMPONENTS as $i=>$n)$lines[]='"'.$n.'": '.$values[$i];$lines[]='"@signature-params": '.self::serialize($p);return implode("\n",$lines);
    }
}

final class Wire {
    public static function framing(mixed $headers,?int $bodyLength=null):array{
        $map=Canonical::headers($headers,true);$length=$map['content-length']??null;$encoding=$map['transfer-encoding']??null;
        if($length!==null&&$encoding!==null||$encoding!==null&&$encoding!=='chunked'||isset($map['content-encoding'])&&$map['content-encoding']!=='identity')throw new VerificationError();
        if($length!==null){
            if(preg_match('/\A(?:0|[1-9][0-9]*)\z/',$length)!==1)throw new VerificationError();
            if(strlen($length)>7||(int)$length>1048576)throw new VerificationError('INVALID_REQUEST',413);
            if($bodyLength!==null&&(int)$length!==$bodyLength)throw new VerificationError();
        }
        return $map;
    }
    public static function parse(mixed $headers):ParsedSignature{
        $map=self::framing($headers);$integer='(0|-?[1-9][0-9]{0,14})';
        $pattern='/\Aappguard=\('.preg_quote(Canonical::COVERED,'/').'\);created='.$integer.';expires='.$integer.';nonce="([A-Za-z0-9_-]{22})";keyid="([A-Za-z0-9._:-]{1,128})";alg="([A-Za-z0-9._:-]{1,64})";tag="([A-Za-z0-9._:-]{1,64})"\z/';
        if(preg_match($pattern,$map['signature-input']??'',$m)!==1||preg_match('/\Aappguard=:([A-Za-z0-9+\/]{86}==):\z/',$map['signature']??'',$s)!==1)throw new VerificationError();
        Canonical::nonce($m[3]);$signature=base64_decode($s[1],true);
        if($signature===false||strlen($signature)!==64||base64_encode($signature)!==$s[1])throw new VerificationError();
        $p=new SignatureParameters((int)$m[1],(int)$m[2],$m[3],$m[4],$m[5],$m[6]);
        if($p->algorithm!==Canonical::ALGORITHM||$p->tag!==Canonical::TAG)throw new VerificationError('UNSUPPORTED_PROFILE');
        return new ParsedSignature($p,$signature);
    }
}

/** Strict minimal DER at the OpenSSL boundary; v0 wire is always unsigned raw64. */
final class P256 {
    private const ORDER='ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';
    private static function scalar(string $bytes):void{
        if(strlen($bytes)!==32||$bytes===str_repeat("\0",32)||strcmp($bytes,hex2bin(self::ORDER))>=0)throw new VerificationError('INVALID_SIGNATURE');
    }
    public static function rawToDer(mixed $raw):string{
        if(!is_string($raw)||strlen($raw)!==64)throw new VerificationError('INVALID_SIGNATURE');$out='';
        foreach([substr($raw,0,32),substr($raw,32,32)] as $scalar){self::scalar($scalar);$value=ltrim($scalar,"\0");if(ord($value[0])>=128)$value="\0".$value;$out.="\x02".chr(strlen($value)).$value;}
        return "\x30".chr(strlen($out)).$out;
    }
    public static function derToRaw(mixed $der):string{
        if(!is_string($der)||strlen($der)<8||strlen($der)>72||$der[0]!=="\x30"||ord($der[1])!==strlen($der)-2)throw new VerificationError('INVALID_SIGNATURE');
        $offset=2;$raw='';for($i=0;$i<2;$i++){
            if($offset+2>strlen($der)||$der[$offset++]!=="\x02")throw new VerificationError('INVALID_SIGNATURE');$length=ord($der[$offset++]);
            if($length<1||$length>33||$offset+$length>strlen($der))throw new VerificationError('INVALID_SIGNATURE');$value=substr($der,$offset,$length);$offset+=$length;
            if(ord($value[0])>=128||strlen($value)>1&&$value[0]==="\0"&&ord($value[1])<128)throw new VerificationError('INVALID_SIGNATURE');
            if(strlen($value)===33){if($value[0]!=="\0")throw new VerificationError('INVALID_SIGNATURE');$value=substr($value,1);}
            $value=str_pad($value,32,"\0",STR_PAD_LEFT);self::scalar($value);$raw.=$value;
        }
        if($offset!==strlen($der)||self::rawToDer($raw)!==$der)throw new VerificationError('INVALID_SIGNATURE');return $raw;
    }
    public static function publicKey(mixed $pem):\OpenSSLAsymmetricKey{
        if(!is_string($pem)||strlen($pem)>4096||preg_match('/\A-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+\/=\r\n]+)-----END PUBLIC KEY-----\r?\n?\z/',$pem,$m)!==1)throw new VerificationError('KEY_REJECTED');
        // Require exactly the named-curve P-256 SubjectPublicKeyInfo, with a compressed or uncompressed point.
        // This rejects private/certificate PEMs, explicit curve parameters, appended keys and trailing DER.
        $encoded=str_replace(["\r","\n"],'',$m[1]);$der=base64_decode($encoded,true);
        $prefix=hex2bin('3059301306072a8648ce3d020106082a8648ce3d03010703420004');
        $compressedPrefix=hex2bin('3039301306072a8648ce3d020106082a8648ce3d030107032200');
        $validEncoding=is_string($der)&&((strlen($der)===91&&substr($der,0,27)===$prefix)||(strlen($der)===59&&substr($der,0,26)===$compressedPrefix&&in_array(ord($der[26]),[2,3],true)));
        if(!$validEncoding||base64_encode($der)!==$encoded)throw new VerificationError('KEY_REJECTED');
        try{$key=@openssl_pkey_get_public($pem);$details=$key===false?false:openssl_pkey_get_details($key);}catch(\Throwable){$key=false;$details=false;}
        if($key===false||$details===false||($details['type']??null)!==OPENSSL_KEYTYPE_EC||($details['bits']??null)!==256||($details['ec']['curve_name']??null)!=='prime256v1'||($details['ec']['curve_oid']??null)!=='1.2.840.10045.3.1.7')throw new VerificationError('KEY_REJECTED');
        return $key;
    }
}

interface ReplayStore { public function claim(array $scope,mixed $expires,mixed $now):mixed; }

final class ReplayValidation {
    public static function check(array $scope,mixed $expires,mixed $now):void{
        try{
            if(!array_is_list($scope)||count($scope)!==3||!Canonical::identifier($scope[0])||!Canonical::identifier($scope[1])||!Canonical::validTime($now)||!Canonical::validTime($expires)||$now>=$expires||$expires-$now>150)throw new VerificationError();Canonical::nonce($scope[2]);
        }catch(\Throwable){throw new VerificationError('REPLAY_STORE_UNAVAILABLE');}
    }
}

/** Volatile, bounded, synchronous process-local development state only. */
final class InMemoryReplayStore implements ReplayStore {
    private array $claims=[];private int $capacity;
    public function __construct(mixed $capacity=10000){if(!is_int($capacity)||$capacity<1)throw new VerificationError('REPLAY_STORE_UNAVAILABLE');$this->capacity=$capacity;}
    public function claim(array $scope,mixed $expires,mixed $now):mixed{
        ReplayValidation::check($scope,$expires,$now);
        foreach($this->claims as $key=>$deadline)if($deadline<=$now)unset($this->claims[$key]);
        $key=json_encode($scope,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);if(isset($this->claims[$key]))return false;
        if(count($this->claims)>=$this->capacity)throw new VerificationError('REPLAY_STORE_UNAVAILABLE');
        // No callbacks, waits or Fiber suspension points between lookup and insertion.
        $this->claims[$key]=$expires;return true;
    }
}

/** Inject an existing atomic backend callback; the SDK provides no distributed guarantees. */
final class CallbackReplayStore implements ReplayStore {
    private \Closure $claim;
    public function __construct(callable $claim){$this->claim=\Closure::fromCallable($claim);}
    public function claim(array $scope,mixed $expires,mixed $now):mixed{
        ReplayValidation::check($scope,$expires,$now);
        try{$result=($this->claim)($scope,$expires,$now);}catch(\Throwable){throw new VerificationError('REPLAY_STORE_UNAVAILABLE');}
        if(!is_bool($result))throw new VerificationError('REPLAY_STORE_UNAVAILABLE');return $result;
    }
}

final class Verifier {
    public static function verify(RequestInput $request,SignatureParameters $parameters,mixed $signature,mixed $origin,mixed $app_id,mixed $subject,mixed $now,?KeyRecord $key,ReplayStore $replay):VerificationResult{
        if(!Canonical::identifier($app_id)||!Canonical::identifier($subject))throw new VerificationError();
        $base=Canonical::signatureBase($request,$parameters,$origin);
        if(!Canonical::validTime($now)||$parameters->created>=$parameters->expires||$parameters->expires-$parameters->created>120||$parameters->created>$now+30||$now>=$parameters->expires)throw new VerificationError('INVALID_TIME');
        $headers=Canonical::request($request);
        if($key===null||!$key->validContract()||$key->revoked!==false||$key->app_id!==$app_id||$headers['appguard-app-id']!==$app_id||$key->subject!==$subject||$key->key_id!==$parameters->key_id||$key->algorithm!==Canonical::ALGORITHM||$key->expires_at!==null&&$now>=$key->expires_at)throw new VerificationError('KEY_REJECTED');
        $public=P256::publicKey($key->public_key_pem);
        if(!hash_equals(Canonical::digest($headers['content-digest']),hash('sha256',$request->body,true)))throw new VerificationError('DIGEST_MISMATCH');
        $der=P256::rawToDer($signature);try{$valid=@openssl_verify($base,$der,$public,OPENSSL_ALGO_SHA256)===1;}catch(\Throwable){$valid=false;}
        if(!$valid)throw new VerificationError('INVALID_SIGNATURE');
        try{$claimed=$replay->claim([$app_id,$key->key_id,$parameters->nonce],$parameters->expires,$now);}catch(\Throwable){throw new VerificationError('REPLAY_STORE_UNAVAILABLE');}
        if($claimed===false)throw new VerificationError('REPLAY_DETECTED');if($claimed!==true)throw new VerificationError('REPLAY_STORE_UNAVAILABLE');
        return new VerificationResult($app_id,$key->key_id,$parameters->expires);
    }
}
