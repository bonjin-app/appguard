package io.appguard.android;

import org.junit.Test;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.Assert.*;
import static io.appguard.android.LocalRiskScanner.State.*;

public class LocalRiskScannerTest {
    static final String EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    static final String ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    static class OS implements LocalRiskScanner.Observations {
        boolean debug, build, root; boolean denied; byte[] status="Name:\tapp\nTracerPid:\t0\n".getBytes();
        byte[] maps="123-456 r-xp 0 00:00 0 /system/lib64/libc.so\n".getBytes();
        List<byte[]> signers = List.of("abc".getBytes()); Path resource; int probes;
        public boolean debugger() throws Exception { probes++; if(denied) throw new IOException("PRIVATE"); return debug; }
        public InputStream status() { probes++; return new ByteArrayInputStream(status); }
        public boolean debugBuild() throws Exception { probes++; if(denied) throw new SecurityException("PRIVATE"); return build; }
        public boolean rootArtifact(String p) throws Exception { probes++; if(denied) throw new IOException("PRIVATE"); return root; }
        public InputStream maps() { probes++; return new ByteArrayInputStream(maps); }
        public String appId() { probes++; return "io.example.app"; }
        public List<byte[]> currentSigners() { probes++; return signers; }
        public InputStream asset(String p) throws Exception { probes++; if(resource==null) throw new FileNotFoundException(p); return Files.newInputStream(resource); }
    }
    LocalRiskScanner.Report scan(OS os) { return new LocalRiskScanner(os).scan(new LocalRiskScanner.Config()); }
    static Set<String> keys(org.json.JSONObject j) { Set<String> s=new HashSet<>(); j.keys().forEachRemaining(s::add); return s; }
    @Test public void defaultChecksAreOrderedAndOptionalChecksNotConfigured() {
        LocalRiskScanner.Report r=scan(new OS());
        assertEquals(List.of("debugger_attached","debug_build","root_artifact","hook_artifact","app_identity_mismatch","app_signer_mismatch","bundle_resource_mismatch"),new ArrayList<>(r.checks().keySet()));
        assertEquals(not_configured,r.checks().get("app_signer_mismatch")); assertEquals(List.of(),r.riskSignals());
    }
    @Test public void tracerPositiveWinsOverDeniedDebugApi() {
        OS os=new OS(); os.denied=true; os.status="TracerPid:\t19\n".getBytes();
        LocalRiskScanner.Report r=scan(os); assertEquals(detected,r.checks().get("debugger_attached"));
        assertEquals(List.of("debugger","local_checks_unavailable"),r.riskSignals());
    }
    @Test public void malformedAndOversizeProcAreUnavailable() {
        for(byte[] bytes:List.of("TracerPid: garbage\n".getBytes(),"TracerPid: 99999999999999999999\n".getBytes(),"Name: x\n".getBytes(),new byte[65537])) {
            OS os=new OS();os.status=bytes; assertEquals(unavailable,scan(os).checks().get("debugger_attached"));
        }
        OS os=new OS(); os.maps=new byte[524289];assertEquals(unavailable,scan(os).checks().get("hook_artifact"));
    }
    @Test public void hookUsesKnownBasenamesRatherThanDirectorySubstrings() {
        OS os=new OS();os.maps="a-b r-xp 0 00:00 0 /frida/libc.so\n".getBytes();assertEquals(not_observed,scan(os).checks().get("hook_artifact"));
        os.maps="a-b r-xp 0 00:00 0 /data/libfrida-gadget.so\n".getBytes();assertEquals(detected,scan(os).checks().get("hook_artifact"));
        os.maps="unparseable secret\n".getBytes();assertEquals(unavailable,scan(os).checks().get("hook_artifact"));
    }
    @Test public void allCurrentSignersMustBeAllowed() {
        OS os=new OS(); LocalRiskScanner scanner=new LocalRiskScanner(os);
        LocalRiskScanner.Config c=new LocalRiskScanner.Config("io.other",Set.of(ABC),Map.of());
        assertEquals(not_observed,scanner.scan(c).checks().get("app_signer_mismatch"));
        os.signers=List.of("abc".getBytes(),"other-current-signer".getBytes());
        assertEquals(detected,scanner.scan(c).checks().get("app_signer_mismatch"));
        os.signers=List.of();assertEquals(unavailable,scanner.scan(c).checks().get("app_signer_mismatch"));
    }
    @Test public void resourceHashMissingAndBoundAreDistinct() throws Exception {
        OS os=new OS(); LocalRiskScanner scanner=new LocalRiskScanner(os);
        LocalRiskScanner.Config c=new LocalRiskScanner.Config(null,Set.of(),Map.of("pin.bin",ABC));
        assertEquals(detected,scanner.scan(c).checks().get("bundle_resource_mismatch"));
        os.resource=Files.createTempFile("appguard-resource", ".bin");
        try {
            Files.write(os.resource,"abc".getBytes());assertEquals(not_observed,scanner.scan(c).checks().get("bundle_resource_mismatch"));
            Files.write(os.resource,new byte[1048577]);assertEquals(unavailable,scanner.scan(c).checks().get("bundle_resource_mismatch"));
        } finally { Files.deleteIfExists(os.resource); }
    }
    @Test public void invalidConfigurationFailsBeforeProbesAndNeverEchoesInput() {
        OS os=new OS();
        for(String path:List.of("../PRIVATE","/PRIVATE","a//b","a\\b","a/..","a/")) {
            try { new LocalRiskScanner(os).scan(new LocalRiskScanner.Config(null,Set.of(),Map.of(path,ABC)));fail(); }
            catch(IllegalArgumentException e) { assertEquals("Invalid local risk configuration",e.getMessage());assertNull(e.getCause()); }
        }
        assertEquals(0,os.probes);
    }
    @Test public void invalidPinsIdentityAndCountsAreRejected() {
        for(String id:List.of("", "a b", "é", "a".repeat(256))) {
            try { new LocalRiskScanner.Config(id,Set.of(),Map.of());fail(); } catch(IllegalArgumentException expected) { }
        }
        try { new LocalRiskScanner.Config(null,Set.of(ABC.toUpperCase()),Map.of());fail(); } catch(IllegalArgumentException expected) { }
        Map<String,String> resources=new HashMap<>();for(int i=0;i<9;i++) resources.put("a"+i,ABC);
        try { new LocalRiskScanner.Config(null,Set.of(),resources);fail(); } catch(IllegalArgumentException expected) { }
    }
    @Test public void configAndReportsDefensivelyCopyAndJsonContainsOnlyFixedFields() throws Exception {
        OS os=new OS(); Set<String> pins=new HashSet<>(Set.of(ABC));Map<String,String> resources=new HashMap<>();
        LocalRiskScanner.Config c=new LocalRiskScanner.Config("io.other",pins,resources);pins.clear();resources.put("PRIVATE",EMPTY);
        LocalRiskScanner.Report r=new LocalRiskScanner(os).scan(c);
        assertEquals(not_observed,r.checks().get("app_signer_mismatch"));assertEquals(not_configured,r.checks().get("bundle_resource_mismatch"));
        try {r.checks().clear();fail();}catch(UnsupportedOperationException expected){}
        try {r.riskSignals().clear();fail();}catch(UnsupportedOperationException expected){}
        org.json.JSONObject json=new org.json.JSONObject(r.toJson());
        assertEquals(Set.of("schema","platform","checks","riskSignals"),keys(json));assertEquals("appguard-local-risk-v0",json.getString("schema"));
        assertFalse(r.toString().contains("io.other"));assertFalse(r.toJson().contains(ABC));
        assertEquals(Set.of("code","state"),keys(json.getJSONArray("checks").getJSONObject(0)));
    }
    @Test public void positiveRootWinsOverDeniedSibling() {
        OS os=new OS() { public boolean rootArtifact(String p) throws Exception {
            if(p.equals("/system/bin/su")) return true; throw new IOException();
        }};
        assertEquals(detected,scan(os).checks().get("root_artifact"));
    }
    @Test public void deniedAssetsAndReadFailuresAreUnavailable() {
        OS os=new OS() { public InputStream asset(String p) throws Exception {throw new SecurityException("PRIVATE");} };
        assertEquals(unavailable,new LocalRiskScanner(os).scan(new LocalRiskScanner.Config(null,Set.of(),Map.of("a",EMPTY))).checks().get("bundle_resource_mismatch"));
        OS broken=new OS() {public InputStream status(){ return new InputStream(){public int read() throws IOException {throw new IOException("PRIVATE");}};}};
        assertEquals(unavailable,scan(broken).checks().get("debugger_attached"));
    }
    @Test public void missingResourceWinsOverUnavailableSibling() {
        OS os=new OS() {public InputStream asset(String p) throws Exception {
            if(p.equals("a"))throw new FileNotFoundException();throw new IOException();
        }};
        assertEquals(detected,new LocalRiskScanner(os).scan(new LocalRiskScanner.Config(null,Set.of(),Map.of("a",EMPTY,"b",EMPTY))).checks().get("bundle_resource_mismatch"));
    }
    @Test public void duplicateNegativeTracerFieldIsUnavailable() {
        OS os=new OS();os.status="TracerPid: 0\nTracerPid: 0\n".getBytes();assertEquals(unavailable,scan(os).checks().get("debugger_attached"));
    }
    @Test public void configuredIdentityAndSignalsAreDeduplicatedInPolicyOrder() {
        OS os=new OS();os.debug=true;os.build=true;os.root=true;
        os.maps="a-b r-xp 0 00:00 0 /data/libsubstrate.so\n".getBytes();
        LocalRiskScanner.Report r=new LocalRiskScanner(os).scan(new LocalRiskScanner.Config("io.other",Set.of(EMPTY),Map.of("a",EMPTY)));
        assertEquals(List.of("debugger","root","hook","tamper"),r.riskSignals());
    }

    @Test public void resourceReadFileNotFoundIsUnavailableRatherThanMissing() {
        OS os=new OS(){public InputStream asset(String p){return new InputStream(){public int read() throws IOException {throw new FileNotFoundException("PRIVATE");}};}};
        assertEquals(unavailable,new LocalRiskScanner(os).scan(new LocalRiskScanner.Config(null,Set.of(),Map.of("a",EMPTY))).checks().get("bundle_resource_mismatch"));
    }
    @Test public void unexpectedSignerWinsOverMalformedSiblingInEitherOrder() {
        OS os=new OS(); LocalRiskScanner scanner=new LocalRiskScanner(os);
        LocalRiskScanner.Config c=new LocalRiskScanner.Config(null,Set.of(ABC),Map.of());
        for(List<byte[]> signers:List.of(Arrays.asList(null,"other".getBytes()),Arrays.asList("other".getBytes(),null))) {
            os.signers=signers;assertEquals(detected,scanner.scan(c).checks().get("app_signer_mismatch"));
        }
        os.signers=Collections.singletonList(new byte[0]);assertEquals(unavailable,scanner.scan(c).checks().get("app_signer_mismatch"));
    }
    @Test public void exactResourceLimitIsHashed() throws Exception {
        OS os=new OS();os.resource=Files.createTempFile("appguard-resource", ".bin");
        try {
            byte[] content=new byte[1048576];Files.write(os.resource,content);
            // SHA256 of exactly 1 MiB of zero bytes, independently generated fixture.
            assertEquals(not_observed,new LocalRiskScanner(os).scan(new LocalRiskScanner.Config(null,Set.of(),Map.of("a",
                "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"))).checks().get("bundle_resource_mismatch"));
        }finally{Files.deleteIfExists(os.resource);}
    }

    @Test public void defaultDoesNotLookupIdentitySignersOrResources() {
        OS os=new OS(){
            public String appId(){throw new AssertionError("unconfigured probe");}
            public List<byte[]> currentSigners(){throw new AssertionError("unconfigured probe");}
            public InputStream asset(String p){throw new AssertionError("unconfigured probe");}
        };
        assertEquals(not_configured,scan(os).checks().get("app_identity_mismatch"));
    }
    @Test public void boundedReadsCloseInputsOnErrorAndSuccess() {
        final int[] closed={0};
        OS os=new OS(){public InputStream status(){return new ByteArrayInputStream(new byte[65537]){public void close(){closed[0]++;}};}
            public InputStream maps(){return new ByteArrayInputStream("a-b r-xp 0 00:00 0 /lib/libc.so\n".getBytes()){public void close(){closed[0]++;}};}};
        scan(os);assertEquals(2,closed[0]);
    }

}
