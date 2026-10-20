package io.appguard.flutter;
import java.util.*;
import io.flutter.plugin.common.*;
public final class AdapterProbe {
  static int assertions;
  static Object invoke(String method,Object arguments,AppGuardPlugin.Invoker invoker) {
    Object[] answer = new Object[1];
    AppGuardPlugin.dispatch(new MethodCall(method,arguments),new MethodChannel.Result() {
      public void success(Object value) { answer[0]=value; }
      public void error(String code,String message,Object details) { throw new AssertionError("exception details exposed"); }
      public void notImplemented() { answer[0]="notImplemented"; }
    },invoker);
    return answer[0];
  }
  static void equal(Object actual,Object expected) {assertions++; if(!Objects.equals(actual,expected)) throw new AssertionError("adapter mismatch");}
  public static void main(String[] args) {
    String payload="{\"target\":\"/a%2Fb?\",\"bodyBase64\":\"AP+ADQpB\"}";
    Map<String,Object> valid=new HashMap<>(); valid.put("operation","prepare");valid.put("payload",payload);
    equal(invoke("invoke",valid,(operation,json)->{equal(operation,"prepare");equal(json,payload);return "native-response";}),"native-response");
    equal(invoke("other",valid,(o,p)->{throw new AssertionError();}),"notImplemented");
    for(Object invalid:Arrays.asList(null,"secret",Map.of("operation",42,"payload",payload),Map.of("operation","prepare","payload",42),Map.of("operation","prepare","payload",payload,"extra",true))) {
      equal(invoke("invoke",invalid,(o,p)->{throw new AssertionError("invalid reached facade");}),AppGuardPlugin.INVALID);
    }
    equal(invoke("invoke",valid,(o,p)->{throw new IllegalStateException("Bearer secret private-key");}),AppGuardPlugin.FAILED);
    equal(invoke("invoke",valid,null),"{\"ok\":false,\"error\":{\"code\":\"APPGUARD_NATIVE_UNAVAILABLE\"}}");
    System.out.println("AdapterProbe: "+assertions+" assertions passed");
  }
}
