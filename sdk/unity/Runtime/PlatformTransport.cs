using System;
using System.Runtime.InteropServices;
using System.Text;
using UnityEngine;

namespace AppGuard {
internal sealed class PlatformTransport : INativeTransport {
#if UNITY_IOS && !UNITY_EDITOR
    [DllImport("__Internal", EntryPoint="AppGuardUnityInvoke")] static extern IntPtr InvokeNative(byte[] operation,byte[] payload);
    [DllImport("__Internal", EntryPoint="AppGuardUnityFree")] static extern void FreeNative(IntPtr response);
#endif
    internal string InvokeLocalRisk(string payload) {
#if UNITY_ANDROID && !UNITY_EDITOR
        // JNI is attached by ScanWorker on its owned thread before Java access.
        AndroidJavaObject bridge;
        try {
            using(var player=new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
            using(var activity=player.GetStatic<AndroidJavaObject>("currentActivity"))
            using(var context=activity.Call<AndroidJavaObject>("getApplicationContext"))
                bridge=new AndroidJavaObject("io.appguard.android.NativeBridge",context);
        } catch {throw new AppGuardException("APPGUARD_NATIVE_UNAVAILABLE");}
        using(bridge)return bridge.Call<string>("invoke","scanLocalRisk",payload);
#elif UNITY_IOS && !UNITY_EDITOR
        return NativeResponse.Consume(InvokeNative(Encoding.UTF8.GetBytes("scanLocalRisk\0"),Encoding.UTF8.GetBytes(payload+"\0")),FreeNative,LocalRiskDecoder.MaxBytes);
#else
        throw new AppGuardException("APPGUARD_UNSUPPORTED");
#endif
    }
    public string Invoke(string operation,string payload) {
#if UNITY_ANDROID && !UNITY_EDITOR
        using(var player=new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
        using(var activity=player.GetStatic<AndroidJavaObject>("currentActivity"))
        using(var context=activity.Call<AndroidJavaObject>("getApplicationContext"))
        using(var bridge=new AndroidJavaObject("io.appguard.android.NativeBridge",context))
            return bridge.Call<string>("invoke",operation,payload);
#elif UNITY_IOS && !UNITY_EDITOR
        return NativeResponse.Consume(InvokeNative(Encoding.UTF8.GetBytes(operation+"\0"),Encoding.UTF8.GetBytes(payload+"\0")),FreeNative);
#else
        throw new AppGuardException("APPGUARD_UNSUPPORTED");
#endif
    }
}
internal static class NativeResponse {
    internal const int MaxBytes=1500000;
    internal static string Consume(IntPtr pointer,Action<IntPtr> free,int maxBytes=MaxBytes) {
        if(pointer==IntPtr.Zero) throw new AppGuardException("APPGUARD_OPERATION_FAILED");
        try {
            int size=0; while(size<=maxBytes && Marshal.ReadByte(pointer,size)!=0) size++;
            if(size>maxBytes) throw new AppGuardException("APPGUARD_OPERATION_FAILED");
            var bytes=new byte[size];Marshal.Copy(pointer,bytes,0,size);return new UTF8Encoding(false,true).GetString(bytes);
        } catch {throw new AppGuardException("APPGUARD_OPERATION_FAILED");}
        finally {free(pointer);}
    }
}
}
