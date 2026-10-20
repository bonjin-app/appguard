package io.appguard.flutter;

import java.util.Map;
import java.nio.charset.StandardCharsets;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.StandardMethodCodec;
import io.flutter.plugin.common.MethodChannel;
import io.appguard.android.NativeBridge;

/** A JSON-only adapter. Key handling and validation belong to the native SDK. */
public final class AppGuardPlugin implements FlutterPlugin, MethodChannel.MethodCallHandler {
    interface Invoker { String invoke(String operation, String payload); }
    private MethodChannel channel;
    private volatile Invoker invoker;
    static final String INVALID = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_INVALID_INPUT\"}}";
    static final String FAILED = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_OPERATION_FAILED\"}}";

    @Override public void onAttachedToEngine(FlutterPluginBinding binding) {
        NativeBridge bridge = new NativeBridge(binding.getApplicationContext());
        attach(binding.getBinaryMessenger(), bridge::invoke);
    }
    void attach(BinaryMessenger messenger, Invoker invoke) {
        // A missing task queue must never silently run scanner I/O on the UI thread.
        BinaryMessenger.TaskQueue queue;
        try { queue = messenger.makeBackgroundTaskQueue(); }
        catch (RuntimeException | LinkageError exception) { queue = null; }
        invoker = queue == null ? null : invoke;
        channel = queue == null ? new MethodChannel(messenger, "io.appguard/client")
                : new MethodChannel(messenger, "io.appguard/client", StandardMethodCodec.INSTANCE, queue);
        channel.setMethodCallHandler(this);
    }
    @Override public void onDetachedFromEngine(FlutterPluginBinding binding) {
        if (channel != null) channel.setMethodCallHandler(null);
        channel = null;
        invoker = null;
    }
    @Override public void onMethodCall(MethodCall call, MethodChannel.Result result) {
        dispatch(call, result, invoker);
    }
    static void dispatch(MethodCall call, MethodChannel.Result result, Invoker invoke) {
        if (!"invoke".equals(call.method)) { result.notImplemented(); return; }
        if (!(call.arguments instanceof Map)) { result.success(INVALID); return; }
        Map<?, ?> arguments = (Map<?, ?>) call.arguments;
        Object operation = arguments.get("operation"), payload = arguments.get("payload");
        if (arguments.size() != 2 || !(operation instanceof String) || !(payload instanceof String)
                || ((String) payload).getBytes(StandardCharsets.UTF_8).length >
                    ("scanLocalRisk".equals(operation) ? 8192 : 1500000)) {
            result.success(INVALID); return;
        }
        if (invoke == null) {
            result.success("{\"ok\":false,\"error\":{\"code\":\"APPGUARD_NATIVE_UNAVAILABLE\"}}"); return;
        }
        String response;
        try { response = invoke.invoke((String) operation, (String) payload); }
        catch (RuntimeException exception) { response = FAILED; }
        if ("scanLocalRisk".equals(operation) && (response == null
                || response.getBytes(StandardCharsets.UTF_8).length > 4096)) response = FAILED;
        result.success(response);
    }
}
