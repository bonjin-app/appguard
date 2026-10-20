package io.appguard.flutter;
import java.util.*;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
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
  static final class Messenger implements BinaryMessenger {
    final boolean unsupported; final TaskQueue queue = new TaskQueue() {};
    BinaryMessageHandler handler; TaskQueue registered; int queues;
    Messenger(boolean unsupported) { this.unsupported=unsupported; }
    public TaskQueue makeBackgroundTaskQueue() { queues++; if(unsupported) throw new UnsupportedOperationException("PRIVATE"); return queue; }
    public void send(String c,ByteBuffer b) { throw new AssertionError(); }
    public void send(String c,ByteBuffer b,BinaryReply r) { throw new AssertionError(); }
    public void setMessageHandler(String c,BinaryMessageHandler h) { handler=h; registered=null; }
    public void setMessageHandler(String c,BinaryMessageHandler h,TaskQueue q) { handler=h; registered=q; }
  }
  static void queueLifecycle(boolean unsupported) {
    Messenger messenger = new Messenger(unsupported); AppGuardPlugin plugin = new AppGuardPlugin();
    Thread caller = Thread.currentThread(); AtomicReference<Thread> observed = new AtomicReference<>();
    plugin.attach(messenger,(o,p)->{ observed.set(Thread.currentThread()); return "{\"ok\":true}"; });
    equal(messenger.queues,1); equal(messenger.registered,unsupported ? null : messenger.queue);
    ByteBuffer request = StandardMethodCodec.INSTANCE.encodeMethodCall(new MethodCall("invoke",Map.of("operation","scanLocalRisk","payload","{}"))); request.flip();
    AtomicReference<Object> answer=new AtomicReference<>();
    Thread task = new Thread(()->messenger.handler.onMessage(request,b->{b.flip();answer.set(StandardMethodCodec.INSTANCE.decodeEnvelope(b));}));
    task.start(); try { task.join(); } catch(InterruptedException e) { throw new AssertionError(e); }
    equal(answer.get(),unsupported ? "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_NATIVE_UNAVAILABLE\"}}" : "{\"ok\":true}");
    equal(observed.get(),unsupported ? null : task);
    if(observed.get()==caller) throw new AssertionError("scanner ran on caller/UI thread");
    plugin.onDetachedFromEngine(null); equal(messenger.handler,null);
    Object[] detached=new Object[1];
    plugin.onMethodCall(new MethodCall("invoke",Map.of("operation","scanLocalRisk","payload","{}")),new MethodChannel.Result() {
      public void success(Object v) { detached[0]=v; } public void error(String c,String m,Object d) {throw new AssertionError();} public void notImplemented() {throw new AssertionError();}
    });
    equal(detached[0],"{\"ok\":false,\"error\":{\"code\":\"APPGUARD_NATIVE_UNAVAILABLE\"}}");
  }
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
    Map<String,Object> scan = Map.of("operation","scanLocalRisk","payload","x".repeat(8193));
    equal(invoke("invoke",scan,(o,p)->{throw new AssertionError("oversized scan reached facade");}),AppGuardPlugin.INVALID);
    equal(invoke("invoke",Map.of("operation","scanLocalRisk","payload","é".repeat(4097)),(o,p)->{throw new AssertionError();}),AppGuardPlugin.INVALID);
    equal(invoke("invoke",Map.of("operation","scanLocalRisk","payload","x".repeat(8192)),(o,p)->"x".repeat(4096)),"x".repeat(4096));
    equal(invoke("invoke",Map.of("operation","scanLocalRisk","payload","{}"),(o,p)->"é".repeat(2049)),AppGuardPlugin.FAILED);
    equal(invoke("invoke",valid,(o,p)->"x".repeat(9000)),"x".repeat(9000));
    queueLifecycle(false); queueLifecycle(true);
    System.out.println("AdapterProbe: "+assertions+" assertions passed");
  }
}
