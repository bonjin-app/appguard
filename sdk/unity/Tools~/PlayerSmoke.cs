using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AppGuard;
using UnityEngine;

// Copied only to a disposable consumer project's Assets. Never part of the SDK.
public sealed class AppGuardPlayerSmoke : MonoBehaviour {
    [Serializable] public sealed class Case { public string name, error; public bool passed; }
    [Serializable] public sealed class Receipt {
        public string schema="appguard-unity-player-smoke-v1", buildGuid, platform, identifier, backend;
        public bool development, complete;
        public int mainThread, frames, framesWhileScansPending;
        public Case[] cases;
        public string[] defaultChecks;
    }
    readonly List<Case> cases=new List<Case>();
    int frames, mainThread, framesWhilePending;
    [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
    static void Boot() {new GameObject("AppGuard player smoke").AddComponent<AppGuardPlayerSmoke>();}
    void Update() {frames++;}
    static void Require(bool value) {if(!value)throw new Exception("assertion");}
    async Task Check(string name,Func<Task> run) {
        try {await run();Require(Thread.CurrentThread.ManagedThreadId==mainThread);cases.Add(new Case{name=name,passed=true});}
        catch(Exception e) {cases.Add(new Case{name=name,passed=false,error=e is AppGuardException a?a.Code:e.GetType().Name});}
    }
    static string State(LocalRiskReport report,string code) => report.Checks.Single(c=>c.Code==code).State;
    async void Start() {
        mainThread=Thread.CurrentThread.ManagedThreadId;
        var receipt=new Receipt{buildGuid=Application.buildGUID,platform=Application.platform.ToString(),identifier=Application.identifier,mainThread=mainThread,development=Debug.isDebugBuild,
#if ENABLE_IL2CPP
            backend="IL2CPP"
#else
            backend="Mono"
#endif
        };
        try {
            var client=new Client();
            string platform=Application.platform==RuntimePlatform.Android?"android":"ios";
            string resource=platform=="android"?"appguard-fixture.txt":"Data/Raw/appguard-fixture.txt";
            string hash="FIXTURE_SHA256";
            await Check("defaults",async()=>{var r=await client.ScanLocalRiskAsync();Require(r.Platform==platform && r.Checks.Count==(platform=="android"?7:5));receipt.defaultChecks=r.Checks.Select(c=>c.Code+":"+c.State).ToArray();});
            await Check("identity-match",async()=>{Require(State(await client.ScanLocalRiskAsync(new LocalRiskOptions(expectedAppId:Application.identifier)),"app_identity_mismatch")=="not_observed");});
            await Check("identity-mismatch",async()=>{var r=await client.ScanLocalRiskAsync(new LocalRiskOptions(expectedAppId:"io.appguard.wrong"));Require(State(r,"app_identity_mismatch")=="detected" && r.RiskSignals.Contains("tamper"));});
            await Check("resource-match",async()=>{Require(State(await client.ScanLocalRiskAsync(new LocalRiskOptions(protectedResources:new Dictionary<string,string>{{resource,hash}})),"bundle_resource_mismatch")=="not_observed");});
            await Check("resource-mismatch",async()=>{Require(State(await client.ScanLocalRiskAsync(new LocalRiskOptions(protectedResources:new Dictionary<string,string>{{resource,new string('0',64)}})),"bundle_resource_mismatch")=="detected");});
            await Check("resource-missing",async()=>{Require(State(await client.ScanLocalRiskAsync(new LocalRiskOptions(protectedResources:new Dictionary<string,string>{{"appguard-does-not-exist.txt",hash}})),"bundle_resource_mismatch")=="detected");});
            await Check("signer-expectation",async()=>{
                try {var r=await client.ScanLocalRiskAsync(new LocalRiskOptions(androidSignerSha256:new[]{new string('0',64)}));Require(platform=="android" && State(r,"app_signer_mismatch")=="detected");}
                catch(AppGuardException e) {Require(platform=="ios" && e.Code=="APPGUARD_UNSUPPORTED" && e.Message==e.Code && e.InnerException==null);}
            });
            await Check("invalid-config",()=>{try {new LocalRiskOptions(expectedAppId:"../PRIVATE");throw new Exception("accepted");}catch(AppGuardException e){Require(e.Code=="APPGUARD_INVALID_INPUT" && e.Message==e.Code && e.InnerException==null);}return Task.CompletedTask;});
            await Check("concurrent-16",async()=>{
                int before=frames;var pending=Task.WhenAll(Enumerable.Range(0,16).Select(_=>client.ScanLocalRiskAsync(new LocalRiskOptions(protectedResources:new Dictionary<string,string>{{resource,hash}}))));
                while(!pending.IsCompleted){await Task.Yield();}
                var reports=await pending;framesWhilePending=frames-before;Require(reports.Length==16 && reports.All(r=>State(r,"bundle_resource_mismatch")=="not_observed"));
            });
            await Check("repeat-after-concurrency",async()=>{for(int i=0;i<8;i++)Require((await client.ScanLocalRiskAsync()).Platform==platform);});
            await Check("player-heartbeat",async()=>{int before=frames;await Task.Delay(150);Require(frames>before);});
        } catch(Exception e) {cases.Add(new Case{name="unhandled",error=e.GetType().Name});}
        receipt.frames=frames;receipt.framesWhileScansPending=framesWhilePending;receipt.cases=cases.ToArray();receipt.complete=true;
        string json=JsonUtility.ToJson(receipt,true);
        File.WriteAllText(Path.Combine(Application.persistentDataPath,"appguard-player-result.json"),json);
        Debug.Log("APPGUARD_PLAYER_RESULT "+(cases.Count==11 && cases.All(c=>c.passed)?"PASS":"FAIL")+" "+Application.buildGUID);
    }
}
