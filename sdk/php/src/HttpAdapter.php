<?php
declare(strict_types=1);
namespace AppGuard;

/** Caller attests these inputs were captured at the trusted server ingress before normalization. */
final readonly class HttpEvidence {
    public RequestInput $request; public bool $secure;
    public function __construct(mixed $request,mixed $secure){if(!$request instanceof RequestInput||!is_bool($secure))throw new VerificationError();$this->request=$request;$this->secure=$secure;}
    public static function fromStream(mixed $method,mixed $target,mixed $headers,mixed $stream,mixed $secure):self{
        if(!is_resource($stream)||get_resource_type($stream)!=='stream'||!is_bool($secure))throw new VerificationError();
        // Validate target and all raw header evidence before reading a potentially large stream.
        Canonical::target($target);Wire::framing($headers);
        $metadata=stream_get_meta_data($stream);if(($metadata['blocked']??true)!==true)throw new VerificationError();
        try{$body=stream_get_contents($stream,1048577);$metadata=stream_get_meta_data($stream);$complete=is_string($body)&&!($metadata['timed_out']??false)&&feof($stream);}catch(\Throwable){$body=false;$complete=false;}
        if(is_string($body)&&strlen($body)>1048576)throw new VerificationError('INVALID_REQUEST',413);
        if(!$complete)throw new VerificationError();
        Wire::framing($headers,strlen($body));return new self(new RequestInput($method,$target,$headers,$body),$secure);
    }
}
final readonly class VerifiedRequest {
    public function __construct(public RequestInput $request,public VerificationResult $result){}
}
final readonly class HttpFailure {
    public string $body;
    public function __construct(public int $status,string $reason){$this->body=json_encode(['code'=>$reason],JSON_THROW_ON_ERROR);}
}

/** Framework-neutral native adapter: raw evidence and trusted identity dependencies are mandatory. */
final class HttpAdapter {
    private string $origin;private string $app_id;private \Closure $authenticate;private \Closure $resolveKey;private \Closure $clock;private ReplayStore $replay;private bool $allowInsecure;
    public function __construct(mixed $origin,mixed $app_id,callable $authenticate,callable $resolveKey,ReplayStore $replay,callable $clock,mixed $allowInsecure=false){
        Canonical::origin($origin);if(!Canonical::identifier($app_id)||!is_bool($allowInsecure))throw new VerificationError();
        $this->origin=$origin;$this->app_id=$app_id;$this->authenticate=\Closure::fromCallable($authenticate);$this->resolveKey=\Closure::fromCallable($resolveKey);$this->replay=$replay;$this->clock=\Closure::fromCallable($clock);$this->allowInsecure=$allowInsecure;
    }
    public function handle(mixed $nativeRequest,callable $capture,callable $next):mixed{
        try{
            try{$evidence=$capture($nativeRequest);}catch(VerificationError $error){throw $error;}catch(\Throwable){throw new VerificationError();}
            if(!$evidence instanceof HttpEvidence||!$evidence->secure&&!$this->allowInsecure)throw new VerificationError();
            $request=$evidence->request;if(strlen($request->body)>1048576)throw new VerificationError('INVALID_REQUEST',413);
            Wire::framing($request->headers,strlen($request->body));$parsed=Wire::parse($request->headers);
            Canonical::signatureBase($request,$parsed->parameters,$this->origin);
            try{$subject=($this->authenticate)($nativeRequest,$request);}catch(\Throwable){throw new VerificationError('IDENTITY_UNAVAILABLE');}
            if($subject===null)throw new VerificationError('AUTHENTICATION_REQUIRED');
            if(!Canonical::identifier($subject))throw new VerificationError('IDENTITY_UNAVAILABLE');
            try{$key=($this->resolveKey)($subject,$parsed->parameters->key_id,$this->app_id);}catch(\Throwable){throw new VerificationError('KEY_RESOLVER_UNAVAILABLE');}
            if($key!==null&&(!$key instanceof KeyRecord||!$key->validContract()))throw new VerificationError('KEY_RESOLVER_UNAVAILABLE');
            try{$now=($this->clock)();}catch(\Throwable){throw new VerificationError('VERIFICATION_UNAVAILABLE');}
            $result=Verifier::verify($request,$parsed->parameters,$parsed->signature,$this->origin,$this->app_id,$subject,$now,$key,$this->replay);
        }catch(VerificationError $error){
            // A subclass can omit parent construction or initialize its own fields.
            // Normalize again at publication, without trusting exception metadata.
            $failure=new VerificationError($error->reason??'INVALID_REQUEST',$error->status??null);
            return new HttpFailure($failure->status,$failure->reason);
        }catch(\Throwable){return new HttpFailure(503,'VERIFICATION_UNAVAILABLE');}
        // Deliberately outside the verification error handler: downstream behavior belongs to the app.
        return $next($nativeRequest,new VerifiedRequest($request,$result));
    }
}
