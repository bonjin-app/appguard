// Runs against the installed Unity PBX API, not mocked project methods.
using System;
using System.IO;
using System.Text.RegularExpressions;
using UnityEditor.iOS.Xcode;
using AppGuard.Editor;
class ExportProbe {
    static void Require(bool condition,string message) { if(!condition) throw new Exception(message); }
    public static void Main(string[] args) {
        string root=args[0],package=args[1]; Directory.CreateDirectory(root);
        string projectPath=PBXProject.GetPBXProjectPath(root);
        Directory.CreateDirectory(Path.GetDirectoryName(projectPath));
        var p=new PBXProject();
        p.ReadFromString(@"{ archiveVersion = 1; classes = {}; objectVersion = 50; objects = {
AAAAAAAAAAAAAAAAAAAAAAAA = {isa = PBXProject; mainGroup = BBBBBBBBBBBBBBBBBBBBBBBB; targets = (); buildConfigurationList = CCCCCCCCCCCCCCCCCCCCCCCC; };
BBBBBBBBBBBBBBBBBBBBBBBB = {isa = PBXGroup; children = (); sourceTree = ""<group>""; };
CCCCCCCCCCCCCCCCCCCCCCCC = {isa = XCConfigurationList; buildConfigurations = (); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; };
}; rootObject = AAAAAAAAAAAAAAAAAAAAAAAA; }");
        string app=p.AddTarget("Unity-iPhone","app","com.apple.product-type.application");
        string framework=p.AddTarget("UnityFramework","framework","com.apple.product-type.framework");
        p.AddResourcesBuildPhase(app);p.AddResourcesBuildPhase(framework);p.AddSourcesBuildPhase(framework);
        p.WriteToFile(projectPath);
        File.WriteAllText(Path.Combine(root,"PrivacyInfo.xcprivacy"),"host sentinel");
        Directory.CreateDirectory(Path.Combine(root,"UnityFramework"));
        File.WriteAllText(Path.Combine(root,"UnityFramework/PrivacyInfo.xcprivacy"),"framework sentinel");
        IosLink.ConfigureExport(root,package);
        IosLink.ConfigureExport(root,package); // Repeat export callback must not duplicate references.
        p.ReadFromFile(projectPath); string pbx=p.WriteToString();
        string bundle=p.FindFileGuidByProjectPath("Libraries/AppGuardPrivacy.bundle");
        Require(!string.IsNullOrEmpty(bundle),"bundle file reference missing");
        Require(Regex.IsMatch(pbx,bundle+@" /\*.*?\*/ = \{[^}]*lastKnownFileType = folder;",RegexOptions.Singleline),"bundle is not a PBX folder reference");
        var build=Regex.Match(pbx,@"([A-F0-9]{24}) /\* AppGuardPrivacy.bundle in Resources \*/ = \{isa = PBXBuildFile; fileRef = "+bundle);
        Require(build.Success,"bundle build file missing");
        string resources=p.GetResourcesBuildPhaseByTarget(app);
        string frameworkResources=p.GetResourcesBuildPhaseByTarget(framework);
        string appBlock=Regex.Match(pbx,resources+@" /\* Resources \*/ = \{.*?\};",RegexOptions.Singleline).Value;
        string frameworkBlock=Regex.Match(pbx,frameworkResources+@" /\* Resources \*/ = \{.*?\};",RegexOptions.Singleline).Value;
        Require(appBlock.Contains(build.Groups[1].Value),"app resources does not copy bundle");
        Require(!frameworkBlock.Contains(build.Groups[1].Value),"framework must not copy bundle");
        Require(Regex.Matches(pbx,@"isa = PBXBuildFile; fileRef = "+bundle).Count==1,"duplicate bundle build entries");
        Require(File.ReadAllText(Path.Combine(root,"PrivacyInfo.xcprivacy"))=="host sentinel","host manifest overwritten");
        Require(File.ReadAllText(Path.Combine(root,"UnityFramework/PrivacyInfo.xcprivacy"))=="framework sentinel","framework manifest overwritten");
        Require(File.ReadAllText(Path.Combine(root,"Libraries/AppGuardPrivacy.bundle/PrivacyInfo.xcprivacy"))==File.ReadAllText(Path.Combine(package,"Native~/Dependencies/apple/Sources/AppGuardApple/Resources/PrivacyInfo.xcprivacy")),"staged manifest differs");
        var info=new PlistDocument();info.ReadFromFile(Path.Combine(root,"Libraries/AppGuardPrivacy.bundle/Info.plist"));
        Require(info.root["CFBundlePackageType"].AsString()=="BNDL","invalid resource bundle plist");
        string before=File.ReadAllText(projectPath);bool failed=false;
        try { IosLink.ConfigureExport(root,Path.Combine(root,"missing-package")); } catch(UnityEditor.Build.BuildFailedException) { failed=true; }
        Require(failed && before==File.ReadAllText(projectPath),"missing input did not fail before PBX mutation");
        Console.WriteLine("PASS: real Unity PBX export resources, folder reference, repeat callback, host preservation, staged bytes and missing input");
    }
}
