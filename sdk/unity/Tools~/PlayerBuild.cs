using System;
using System.IO;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEditor.SceneManagement;
using UnityEngine;
using UnityEngine.Rendering;

public static class AppGuardPlayerBuild {
    public static void Build() {
        string mode=Environment.GetEnvironmentVariable("APPGUARD_PLAYER_TARGET"),output=Environment.GetEnvironmentVariable("APPGUARD_PLAYER_OUTPUT");
        if(string.IsNullOrEmpty(output))throw new Exception("Explicit player output required");
        bool android=mode=="android";
        if(!android && mode!="ios-simulator" && mode!="ios-device")throw new Exception("Unknown player target");
        var target=android?BuildTarget.Android:BuildTarget.iOS;
        var named=android?NamedBuildTarget.Android:NamedBuildTarget.iOS;
        PlayerSettings.companyName="AppGuardLocalTests";PlayerSettings.productName="AppGuard Player Smoke";
        PlayerSettings.SetApplicationIdentifier(named,"io.appguard.unity.playersmoke");
        PlayerSettings.bundleVersion="0.0.1";
        PlayerSettings.SetScriptingBackend(named,ScriptingImplementation.IL2CPP);
        PlayerSettings.SetManagedStrippingLevel(named,ManagedStrippingLevel.High);
        PlayerSettings.stripEngineCode=true;
        PlayerSettings.SetUseDefaultGraphicsAPIs(target,false);
        PlayerSettings.SetGraphicsAPIs(target,android?new[]{GraphicsDeviceType.OpenGLES3}:new[]{GraphicsDeviceType.Metal});
        if(android) {
            PlayerSettings.Android.targetArchitectures=AndroidArchitecture.ARM64;
            PlayerSettings.Android.minSdkVersion=AndroidSdkVersions.AndroidApiLevel26;
            PlayerSettings.Android.targetSdkVersion=AndroidSdkVersions.AndroidApiLevel36;
            PlayerSettings.Android.minifyRelease=true;
            string key=Environment.GetEnvironmentVariable("APPGUARD_PLAYER_KEYSTORE");
            if(string.IsNullOrEmpty(key) || !File.Exists(key))throw new Exception("Task-owned fixture keystore required");
            PlayerSettings.Android.useCustomKeystore=true;PlayerSettings.Android.keystoreName=key;
            PlayerSettings.Android.keystorePass="android";PlayerSettings.Android.keyaliasName="fixture";PlayerSettings.Android.keyaliasPass="android";
            EditorUserBuildSettings.buildAppBundle=false;
        } else {
            PlayerSettings.iOS.targetOSVersionString="15.0";
            PlayerSettings.iOS.sdkVersion=mode=="ios-simulator"?iOSSdkVersion.SimulatorSDK:iOSSdkVersion.DeviceSDK;
            PlayerSettings.iOS.simulatorSdkArchitecture=AppleMobileArchitectureSimulator.ARM64;
            PlayerSettings.iOS.appleEnableAutomaticSigning=false;
        }
        var scene=EditorSceneManager.NewScene(NewSceneSetup.EmptyScene,NewSceneMode.Single);
        EditorSceneManager.SaveScene(scene,"Assets/Smoke.unity");
        var report=BuildPipeline.BuildPlayer(new BuildPlayerOptions{scenes=new[]{"Assets/Smoke.unity"},locationPathName=output,target=target,options=BuildOptions.None});
        File.WriteAllText(output+".summary.json",JsonUtility.ToJson(new Summary{result=report.summary.result.ToString(),guid=report.summary.guid.ToString(),target=mode,backend=PlayerSettings.GetScriptingBackend(named).ToString(),stripping=PlayerSettings.GetManagedStrippingLevel(named).ToString(),errors=(int)report.summary.totalErrors},true));
        if(report.summary.result!=BuildResult.Succeeded)throw new Exception("Player build failed");
    }
    [Serializable] sealed class Summary {public string result,guid,target,backend,stripping;public int errors;}
}
