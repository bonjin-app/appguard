<?php
declare(strict_types=1);
namespace AppGuard;

final class PolicyError extends \RuntimeException {
    public readonly string $reason;
    public function __construct(string $reason='INVALID_POLICY'){$this->reason=in_array($reason,['INVALID_POLICY','INVALID_POLICY_CONTEXT','INVALID_POLICY_DECISION','INVALID_AUDIT_EVENT','AUDIT_UNAVAILABLE'],true)?$reason:'INVALID_POLICY';parent::__construct($this->reason);}
}
final class PolicyValidation {
    public const PROFILES=['basic','balanced','strict'];
    public static function signals(mixed $signals,string $error):array{
        if(!is_array($signals)||!array_is_list($signals)||count($signals)>32)throw new PolicyError($error);$copy=[];
        foreach($signals as $value){if(!is_string($value)||strlen($value)>64||preg_match('/\A[a-z][a-z0-9_]{0,63}\z/',$value)!==1||in_array($value,$copy,true))throw new PolicyError($error);$copy[]=$value;}return $copy;
    }
    public static function policy(Policy $policy):Policy{
        try{return new Policy($policy->profile,$policy->require_signature,$policy->suspicious_signals);}catch(\Throwable){throw new PolicyError('INVALID_POLICY');}
    }
    public static function context(PolicyContext $context):PolicyContext{
        try{return new PolicyContext($context->authentication,$context->verification,$context->attestation,$context->attestation_expires,$context->risk_signals,$context->rate_limited);}catch(\Throwable){throw new PolicyError('INVALID_POLICY_CONTEXT');}
    }
    public static function decision(mixed $action,mixed $code,mixed $profile):bool{
        if(!is_string($profile)||!in_array($profile,self::PROFILES,true)||!is_string($action)||!is_string($code))return false;
        if(in_array($code,['AUTHENTICATION_REQUIRED','AUTHENTICATION_INVALID','REQUEST_REJECTED','VERIFICATION_UNAVAILABLE','SIGNATURE_REQUIRED','ATTESTATION_REJECTED','RATE_LIMITED'],true))return $action==='deny';
        if(in_array($code,['ATTESTATION_MISSING','ATTESTATION_UNSUPPORTED','ATTESTATION_UNAVAILABLE','ATTESTATION_EXPIRED','RISK_DETECTED'],true))return $action===['basic'=>'observe','balanced'=>'step_up','strict'=>'deny'][$profile];
        return $code==='ALLOWED'&&$action==='allow';
    }
}
final readonly class Policy {
    public string $profile; public bool $require_signature; public array $suspicious_signals;
    public function __construct(mixed $profile='basic',mixed $require_signature=true,mixed $suspicious_signals=['debugger','root','hook','tamper']){
        if(!is_string($profile)||!in_array($profile,PolicyValidation::PROFILES,true)||!is_bool($require_signature)||!$require_signature&&$profile!=='basic')throw new PolicyError();
        $this->profile=$profile;$this->require_signature=$require_signature;$this->suspicious_signals=PolicyValidation::signals($suspicious_signals,'INVALID_POLICY');
    }
}
final readonly class PolicyContext {
    public string $authentication;public string $verification;public string $attestation;public ?int $attestation_expires;public array $risk_signals;public bool $rate_limited;
    public function __construct(mixed $authentication='missing',mixed $verification='missing',mixed $attestation='missing',mixed $attestation_expires=null,mixed $risk_signals=[],mixed $rate_limited=false){
        if(!in_array($authentication,['authenticated','missing','invalid'],true)||!in_array($verification,['verified','missing','rejected','unavailable'],true)||!in_array($attestation,['verified','missing','unsupported','rejected','unavailable'],true)||$attestation_expires!==null&&!Canonical::validTime($attestation_expires)||!is_bool($rate_limited))throw new PolicyError('INVALID_POLICY_CONTEXT');
        $this->authentication=$authentication;$this->verification=$verification;$this->attestation=$attestation;$this->attestation_expires=$attestation_expires;$this->rate_limited=$rate_limited;$this->risk_signals=PolicyValidation::signals($risk_signals,'INVALID_POLICY_CONTEXT');
    }
}
final readonly class PolicyDecision {
    public string $action;public string $code;public string $profile;
    public function __construct(mixed $action,mixed $code,mixed $profile){if(!PolicyValidation::decision($action,$code,$profile))throw new PolicyError('INVALID_POLICY_DECISION');$this->action=$action;$this->code=$code;$this->profile=$profile;}
}
final class PolicyEngine {
    public static function evaluate(mixed $policy,mixed $context,mixed $now):PolicyDecision{
        if(is_string($policy))$policy=new Policy($policy);
        if(!$policy instanceof Policy)throw new PolicyError();
        if(!$context instanceof PolicyContext||!Canonical::validTime($now))throw new PolicyError('INVALID_POLICY_CONTEXT');
        $policy=PolicyValidation::policy($policy);$context=PolicyValidation::context($context);
        $deny=fn($code)=>new PolicyDecision('deny',$code,$policy->profile);
        $observe=fn($code)=>new PolicyDecision(['basic'=>'observe','balanced'=>'step_up','strict'=>'deny'][$policy->profile],$code,$policy->profile);
        if($context->authentication==='missing')return $deny('AUTHENTICATION_REQUIRED');
        if($context->authentication==='invalid')return $deny('AUTHENTICATION_INVALID');
        if($context->verification==='rejected')return $deny('REQUEST_REJECTED');
        if($context->verification==='unavailable')return $deny('VERIFICATION_UNAVAILABLE');
        if($context->attestation==='rejected')return $deny('ATTESTATION_REJECTED');
        if($context->verification==='missing'&&$policy->require_signature)return $deny('SIGNATURE_REQUIRED');
        if($context->rate_limited)return $deny('RATE_LIMITED');
        if($context->attestation!=='verified')return $observe(['missing'=>'ATTESTATION_MISSING','unsupported'=>'ATTESTATION_UNSUPPORTED','unavailable'=>'ATTESTATION_UNAVAILABLE'][$context->attestation]);
        if($context->attestation_expires===null||$now>=$context->attestation_expires)return $observe('ATTESTATION_EXPIRED');
        foreach($context->risk_signals as $hint)if(in_array($hint,$policy->suspicious_signals,true))return $observe('RISK_DETECTED');
        return new PolicyDecision('allow','ALLOWED',$policy->profile);
    }
}
final class Audit {
    /** Explicit allowlist, fresh array; caller IDs must themselves contain no credentials/PII. */
    public static function event(mixed $decision,mixed $event_id,mixed $app_id,mixed $now,mixed $context=null):array{
        if(!$decision instanceof PolicyDecision||!Canonical::identifier($event_id)||!Canonical::identifier($app_id)||!Canonical::validTime($now)||$context!==null&&!$context instanceof PolicyContext)throw new PolicyError('INVALID_AUDIT_EVENT');
        try{
            $decision=new PolicyDecision($decision->action,$decision->code,$decision->profile);
            if($context!==null)$context=PolicyValidation::context($context);
        }catch(\Throwable){throw new PolicyError('INVALID_AUDIT_EVENT');}
        $out=['schema_version'=>'appguard-audit-v0','event_id'=>$event_id,'app_id'=>$app_id,'at'=>$now,'action'=>$decision->action,'code'=>$decision->code,'profile'=>$decision->profile];
        if($context!==null){$out['risk_count']=count($context->risk_signals);$out['attestation_state']=$context->attestation;}return $out;
    }
}
final class JsonAuditSink {
    private \Closure $callback;
    public function __construct(mixed $callback){if(!is_callable($callback))throw new PolicyError('INVALID_AUDIT_EVENT');$this->callback=\Closure::fromCallable($callback);}
    public function emit(mixed $decision,mixed $event_id,mixed $app_id,mixed $now,mixed $context=null):void{
        $event=Audit::event($decision,$event_id,$app_id,$now,$context);try{($this->callback)(json_encode($event,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));}catch(\Throwable){throw new PolicyError('AUDIT_UNAVAILABLE');}
    }
}
