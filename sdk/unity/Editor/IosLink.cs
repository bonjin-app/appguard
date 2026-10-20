#if UNITY_IOS
using System.IO;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Callbacks;
using PackageInfo = UnityEditor.PackageManager.PackageInfo;
using UnityEditor.iOS.Xcode;
namespace AppGuard.Editor {
internal static class IosLink {
    [PostProcessBuild(100)]
    static void Configure(BuildTarget target,string path) {
        if(target!=BuildTarget.iOS) return;
        var package=PackageInfo.FindForAssembly(typeof(IosLink).Assembly);
        if(package==null) throw new BuildFailedException("Cannot resolve the AppGuard Unity package.");
        ConfigureExport(path,package.resolvedPath);
    }
    // Explicit package root keeps exported projects independent of the checkout layout.
    internal static void ConfigureExport(string path,string packageRoot) {
        string manifest=Path.Combine(packageRoot,"Native~/Dependencies/apple/Sources/AppGuardApple/Resources/PrivacyInfo.xcprivacy");
        if(!File.Exists(manifest)) throw new BuildFailedException("AppGuard privacy manifest is missing. Stage the native SDK sources before exporting iOS.");
        string projectPath=PBXProject.GetPBXProjectPath(path);
        var project=new PBXProject();project.ReadFromFile(projectPath);
        string framework=project.GetUnityFrameworkTargetGuid(),app=project.GetUnityMainTargetGuid();
        if(string.IsNullOrEmpty(framework)||string.IsNullOrEmpty(app))
            throw new BuildFailedException("AppGuard requires Unity app and UnityFramework targets in the iOS export.");
        const string bundle="Libraries/AppGuardPrivacy.bundle";
        string bundlePath=Path.Combine(path,bundle);
        Directory.CreateDirectory(bundlePath);
        File.Copy(manifest,Path.Combine(bundlePath,"PrivacyInfo.xcprivacy"),true);
        File.WriteAllText(Path.Combine(bundlePath,"Info.plist"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"+
            "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>io.appguard.privacy</string>"+
            "<key>CFBundleName</key><string>AppGuardPrivacy</string><key>CFBundlePackageType</key><string>BNDL</string>"+
            "<key>CFBundleVersion</key><string>1</string></dict></plist>\n");
        string resource=project.FindFileGuidByProjectPath(bundle);
        if(string.IsNullOrEmpty(resource)) resource=project.AddFolderReference(bundle,bundle,PBXSourceTree.Source);
        string resources=project.GetResourcesBuildPhaseByTarget(app);
        if(string.IsNullOrEmpty(resources)) resources=project.AddResourcesBuildPhase(app);
        project.RemoveFileFromBuild(app,resource);
        project.AddFileToBuildSection(app,resources,resource);
        project.SetBuildProperty(framework,"SWIFT_VERSION","5.0");
        project.SetBuildProperty(framework,"CLANG_ENABLE_MODULES","YES");
        project.SetBuildProperty(app,"ALWAYS_EMBED_SWIFT_STANDARD_LIBRARIES","YES");
        // A Swift source makes Xcode discover/link the static plugin's Swift runtime.
        const string source="Libraries/AppGuardUnityLink.swift";
        File.WriteAllText(Path.Combine(path,source),"import Foundation\n");
        string file=project.FindFileGuidByProjectPath(source);
        if(string.IsNullOrEmpty(file)) file=project.AddFile(source,source,PBXSourceTree.Source);
        project.AddFileToBuild(framework,file);
        project.WriteToFile(projectPath);
    }
}
}
#endif
