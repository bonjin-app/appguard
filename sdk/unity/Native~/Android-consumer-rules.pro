# Required when the host enables R8/minification: Unity calls the facade via JNI.
-keep class io.appguard.android.NativeBridge { public <init>(android.content.Context); public java.lang.String invoke(java.lang.String, java.lang.String); }
