package io.appguard;
import java.util.*;
final class PolicyValidation {
    private PolicyValidation() {}
    static final List<String> DEFAULT_SIGNALS=List.of("debugger","root","hook","tamper");
    static boolean profile(String profile) { return profile!=null && List.of("basic","balanced","strict").contains(profile); }
    static boolean time(long value) { return value>=0 && value<=999999999999999L; }
    static boolean oneOf(String value,String... choices) { return value!=null && Arrays.asList(choices).contains(value); }
    static List<String> signals(List<String> input,String error) {
        try {
            if(input==null||input.size()>32)throw new IllegalArgumentException();
            List<String> copy=List.copyOf(input);
            if(copy.size()>32||new HashSet<>(copy).size()!=copy.size())throw new IllegalArgumentException();
            for(String code:copy)if(!code.matches("[a-z][a-z0-9_]{0,63}"))throw new IllegalArgumentException();
            return copy;
        }catch(RuntimeException ignored){throw new PolicyException(error);}
    }
    static String observation(String profile) { return switch(profile){case "basic"->"observe";case "balanced"->"step_up";default->"deny";}; }
    static boolean decision(String action,String code,String profile) {
        if(!profile(profile)||action==null||code==null)return false;
        if(List.of("AUTHENTICATION_REQUIRED","AUTHENTICATION_INVALID","REQUEST_REJECTED","VERIFICATION_UNAVAILABLE","SIGNATURE_REQUIRED","ATTESTATION_REJECTED","RATE_LIMITED").contains(code))return action.equals("deny");
        if(List.of("ATTESTATION_MISSING","ATTESTATION_UNSUPPORTED","ATTESTATION_UNAVAILABLE","ATTESTATION_EXPIRED","RISK_DETECTED").contains(code))return action.equals(observation(profile));
        return code.equals("ALLOWED")&&action.equals("allow");
    }
}
