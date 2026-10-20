#if UNITY_IOS
using System.IO;
using UnityEditor;
using UnityEditor.Callbacks;
using UnityEditor.iOS.Xcode;
namespace AppGuard.Editor {
internal static class IosLink {
    [PostProcessBuild(100)]
    static void Configure(BuildTarget target,string path) {
        if(target!=BuildTarget.iOS) return;
        string projectPath=PBXProject.GetPBXProjectPath(path);
        var project=new PBXProject();project.ReadFromFile(projectPath);
        string framework=project.GetUnityFrameworkTargetGuid(),app=project.GetUnityMainTargetGuid();
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
