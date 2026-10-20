package io.appguard.flutter;

import java.util.Map;
import java.nio.charset.StandardCharsets;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.appguard.android.NativeBridge;

/** A JSON-only adapter. Key handling and validation belong to the native SDK. */
public final class AppGuardPlugin implements FlutterPlugin, MethodChannel.MethodCallHandler {
    interface Invoker { String invoke(String operation, String payload); }
    private MethodChannel channel;
    private Invoker invoker;
    static final String INVALID = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_INVALID_INPUT\"}}";
    static final String FAILED = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_OPERATION_FAILED\"}}";

    @Override public void onAttachedToEngine(FlutterPluginBinding binding) {
        NativeBridge bridge = new NativeBridge(binding.getApplicationContext());
        invoker = bridge::invoke;
        channel = new MethodChannel(binding.getBinaryMessenger(), "io.appguard/client");
        channel.setMethodCallHandler(this);
    }
    @Override public void onDetachedFromEngine(FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
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
                || ((String) payload).getBytes(StandardCharsets.UTF_8).length > 1500000) {
            result.success(INVALID); return;
        }
        if (invoke == null) {
            result.success("{\"ok\":false,\"error\":{\"code\":\"APPGUARD_NATIVE_UNAVAILABLE\"}}"); return;
        }
        String response;
        try { response = invoke.invoke((String) operation, (String) payload); }
        catch (RuntimeException exception) { response = FAILED; }
        result.success(response);
    }
}
