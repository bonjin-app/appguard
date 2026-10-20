package io.appguard.android;

import org.json.*;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

/** Actual scanner behind the JSON facade; no persistent keys or wall clock. */
public class LocalRiskBridgeTest {
    private NativeBridge bridge(LocalRiskScannerTest.OS os, AtomicInteger scans) {
        LocalRiskScanner scanner = new LocalRiskScanner(os);
        return new NativeBridge((alias, requirement) -> { throw new AssertionError("scan touched key storage"); },
            () -> { throw new AssertionError("scan touched clock"); }, config -> { scans.incrementAndGet(); return scanner.scan(config); });
    }
    private JSONObject success(NativeBridge bridge, String payload) throws Exception {
        String response = bridge.invoke("scanLocalRisk", payload);
        assertTrue(response.getBytes(StandardCharsets.UTF_8).length <= 4096);
        return NativeBridgeTest.success(response);
    }
    private List<String> strings(JSONArray array) throws Exception {
        List<String> result=new ArrayList<>();for(int i=0;i<array.length();i++)result.add(array.getString(i));return result;
    }
    private void invalid(NativeBridge bridge, String payload) throws Exception {
        String response = bridge.invoke("scanLocalRisk",payload);
        NativeBridgeTest.error("APPGUARD_INVALID_INPUT",response);
        assertFalse(response.contains("PRIVATE"));
    }
    @Test public void defaultsPreserveTypedReportWithoutKeysClockOrOptionalLookups() throws Exception {
        LocalRiskScannerTest.OS os = new LocalRiskScannerTest.OS() {
            public String appId() { throw new AssertionError("optional identity"); }
            public List<byte[]> currentSigners() { throw new AssertionError("optional signer"); }
            public java.io.InputStream asset(String path) { throw new AssertionError("optional asset"); }
        };
        AtomicInteger scans = new AtomicInteger();
        JSONObject report = success(bridge(os, scans), "{}");
        assertEquals("appguard-local-risk-v0",report.getString("schema"));
        assertEquals("android",report.getString("platform"));
        assertEquals(Set.of("schema","platform","checks","riskSignals"),NativeBridgeTest.keys(report));
        assertEquals(7,report.getJSONArray("checks").length());
        assertEquals("not_configured",report.getJSONArray("checks").getJSONObject(5).getString("state"));
        assertEquals(0,report.getJSONArray("riskSignals").length());assertEquals(1,scans.get());
    }
    @Test public void configuredInputsReachRealScannerAndOutputNeverEchoesConfiguration() throws Exception {
        LocalRiskScannerTest.OS os = new LocalRiskScannerTest.OS();
        os.resource = Files.createTempFile("appguard-risk-bridge", ".bin");
        try {
            Files.write(os.resource,"abc".getBytes(StandardCharsets.US_ASCII));
            String payload = new JSONObject().put("expectedAppId","io.example.app")
                .put("androidSignerSha256",new JSONArray().put(LocalRiskScannerTest.ABC))
                .put("protectedResources",new JSONObject().put("PRIVATE.bin",LocalRiskScannerTest.ABC)).toString();
            JSONObject report=success(bridge(os,new AtomicInteger()),payload);
            JSONArray checks=report.getJSONArray("checks");
            for(int i=4;i<7;i++)assertEquals("not_observed",checks.getJSONObject(i).getString("state"));
            String result=report.toString();assertFalse(result.contains("PRIVATE"));assertFalse(result.contains(LocalRiskScannerTest.ABC));assertFalse(result.contains("io.example.app"));
            report=success(bridge(os,new AtomicInteger()),payload.replace("io.example.app","io.other.app"));
            assertEquals(List.of("tamper"),strings(report.getJSONArray("riskSignals")));
        } finally {Files.deleteIfExists(os.resource);}
    }
    @Test public void malformedConfigurationRejectsBeforeAnyScan() throws Exception {
        LocalRiskScannerTest.OS os = new LocalRiskScannerTest.OS();AtomicInteger scans=new AtomicInteger();NativeBridge bridge=bridge(os,scans);
        for(String payload:List.of("", "[]", "null", "{", "{}x", "{\"alias\":\"PRIVATE\"}",
            "{\"expectedAppId\":null}","{\"expectedAppId\":1}","{\"expectedAppId\":\"\"}",
            "{\"expectedAppId\":\"a b\"}","{\"expectedAppId\":\"é\"}",
            "{\"expectedAppId\":\"a\",\"expectedAppId\":\"b\"}",
            "{\"expectedAppId\":\"a\",\"\\u0065xpectedAppId\":\"b\"}",
            "{\"androidSignerSha256\":null}","{\"androidSignerSha256\":{}}", "{\"androidSignerSha256\":[1]}",
            "{\"androidSignerSha256\":[[]]}","{\"androidSignerSha256\":[{}]}","{\"androidSignerSha256\":[true]}",
            "{\"protectedResources\":null}","{\"protectedResources\":[]}","{\"protectedResources\":{\"a\":null}}")) invalid(bridge,payload);
        invalid(bridge,new JSONObject().put("expectedAppId","a".repeat(256)).toString());
        for(String path:List.of("../PRIVATE","/PRIVATE","a//b","a/..","a\\b","a/", "a".repeat(129)))
            invalid(bridge,new JSONObject().put("protectedResources",new JSONObject().put(path,LocalRiskScannerTest.ABC)).toString());
        invalid(bridge,"{\"protectedResources\":{\"a\":\""+LocalRiskScannerTest.ABC+"\",\"a\":\""+LocalRiskScannerTest.ABC+"\"}}");
        assertEquals(0,scans.get());assertEquals(0,os.probes);
    }
    @Test public void signerListsAreBoundedDistinctAndCanonical() throws Exception {
        AtomicInteger scans=new AtomicInteger();NativeBridge bridge=bridge(new LocalRiskScannerTest.OS(),scans);
        for(JSONArray pins:List.of(new JSONArray().put(LocalRiskScannerTest.ABC).put(LocalRiskScannerTest.ABC),
                new JSONArray().put(LocalRiskScannerTest.ABC.toUpperCase()),new JSONArray().put("PRIVATE")))
            invalid(bridge,new JSONObject().put("androidSignerSha256",pins).toString());
        JSONArray pins=new JSONArray();for(int i=0;i<8;i++)pins.put(String.format("%064x",i));
        assertEquals(List.of("tamper"),strings(success(bridge,new JSONObject().put("androidSignerSha256",pins).toString()).getJSONArray("riskSignals")));
        pins.put(String.format("%064x",8));invalid(bridge,new JSONObject().put("androidSignerSha256",pins).toString());
        success(bridge,"{\"androidSignerSha256\":[],\"protectedResources\":{}}");assertEquals(2,scans.get());
    }
    @Test public void exactUtf8InputLimitAndResourceCountRejectBeforeScan() throws Exception {
        AtomicInteger scans=new AtomicInteger();NativeBridge bridge=bridge(new LocalRiskScannerTest.OS(),scans);
        success(bridge,"{}"+" ".repeat(8190));invalid(bridge,"{}"+" ".repeat(8191));
        invalid(bridge,new JSONObject().put("expectedAppId","é".repeat(4096)).toString());
        JSONObject resources=new JSONObject();for(int i=0;i<9;i++)resources.put("a"+i,LocalRiskScannerTest.ABC);
        invalid(bridge,new JSONObject().put("protectedResources",resources).toString());assertEquals(1,scans.get());
    }
    @Test public void unavailableHealthAndDetectedPrecedenceSurviveEnvelope() throws Exception {
        LocalRiskScannerTest.OS os=new LocalRiskScannerTest.OS();os.denied=true;os.debug=true;os.status="TracerPid: 7\n".getBytes();os.maps="\n".getBytes();
        JSONObject report=success(bridge(os,new AtomicInteger()),"{}");
        assertEquals("detected",report.getJSONArray("checks").getJSONObject(0).getString("state"));
        assertEquals("unavailable",report.getJSONArray("checks").getJSONObject(3).getString("state"));
        assertEquals(List.of("debugger","local_checks_unavailable"),strings(report.getJSONArray("riskSignals")));
    }
    @Test public void facadeFailureUsesFixedCodeWithoutNativeText() throws Exception {
        NativeBridge bridge=new NativeBridge((a,r)->{throw new AssertionError();},()->{throw new AssertionError();},config->{throw new java.io.IOException("PRIVATE");});
        NativeBridgeTest.error("APPGUARD_OPERATION_FAILED",bridge.invoke("scanLocalRisk","{}"));
        NativeBridgeTest.error("APPGUARD_INVALID_INPUT",bridge.invoke("scanLocalRisk","{\"clock\":1}"));
    }
}
