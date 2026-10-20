package io.appguard.android;

import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import java.util.Collections;
import java.util.Set;
import static org.junit.Assert.*;
import static io.appguard.android.LocalRiskScanner.State.*;

/** Real read-only adapter coverage on this test APK, not root/hook efficacy. */
public class LocalRiskScannerInstrumentedTest {
    @Test public void actualIdentityCurrentSignerAndAssetAreObserved() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getContext();
        String expectedSigner = InstrumentationRegistry.getArguments().getString("expectedSignerSha256");
        assertNotNull("Pass APK certificate digest as expectedSignerSha256", expectedSigner);
        assertTrue(expectedSigner.matches("[0-9a-f]{64}"));
        Set<String> pins = Collections.singleton(expectedSigner);
        LocalRiskScanner scanner = new LocalRiskScanner(context);
        LocalRiskScanner.Report report = scanner.scan(new LocalRiskScanner.Config(context.getPackageName(), pins,
                Collections.singletonMap("local-risk-fixture.bin", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
        assertEquals(not_observed, report.checks().get("app_identity_mismatch"));
        assertEquals(not_observed, report.checks().get("app_signer_mismatch"));
        assertEquals(not_observed, report.checks().get("bundle_resource_mismatch"));
        LocalRiskScanner.Report mismatch = scanner.scan(new LocalRiskScanner.Config("io.appguard.wrong",
                Collections.singleton("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                Collections.singletonMap("missing-local-risk.bin", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
        assertEquals(detected, mismatch.checks().get("app_identity_mismatch"));
        assertEquals(detected, mismatch.checks().get("app_signer_mismatch"));
        assertEquals(detected, mismatch.checks().get("bundle_resource_mismatch"));
        assertFalse(report.toJson().contains(context.getPackageName()));
        assertEquals(7, report.checks().size());
    }
    @Test public void actualProcAndDebugApisProduceFiniteChecks() {
        Context context = InstrumentationRegistry.getInstrumentation().getContext();
        LocalRiskScanner.Report report = new LocalRiskScanner(context).scan(new LocalRiskScanner.Config());
        assertTrue(report.checks().get("debugger_attached") != not_configured);
        assertTrue(report.checks().get("debug_build") != not_configured);
        assertEquals(not_configured, report.checks().get("app_signer_mismatch"));
        // Root/hook status may be unavailable under the OS sandbox; never require a clean result.
        assertTrue(report.checks().get("root_artifact") != not_configured);
        assertTrue(report.checks().get("hook_artifact") != not_configured);
    }
    @Test public void jsonBridgeUsesActualIdentitySignerAndAssetsWithoutKeyOptions() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getContext();
        String signer = InstrumentationRegistry.getArguments().getString("expectedSignerSha256");
        assertNotNull(signer);
        org.json.JSONObject input = new org.json.JSONObject().put("expectedAppId",context.getPackageName())
            .put("androidSignerSha256",new org.json.JSONArray().put(signer))
            .put("protectedResources",new org.json.JSONObject().put("local-risk-fixture.bin",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        String response = new NativeBridge(context).invoke("scanLocalRisk",input.toString());
        assertTrue(response.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=4096);
        org.json.JSONObject envelope = new org.json.JSONObject(response);
        assertTrue(envelope.getBoolean("ok"));
        org.json.JSONObject report=envelope.getJSONObject("result");
        assertEquals("android",report.getString("platform"));
        assertEquals("appguard-local-risk-v0",report.getString("schema"));
        org.json.JSONArray checks=report.getJSONArray("checks");assertEquals(7,checks.length());
        for(int i=4;i<7;i++)assertEquals("not_observed",checks.getJSONObject(i).getString("state"));
        assertFalse(response.contains(context.getPackageName()));assertFalse(response.contains(signer));
        assertFalse(response.contains("local-risk-fixture.bin"));
        android.os.Bundle receipt=new android.os.Bundle();receipt.putString("appguardRiskBridgeReport",response);
        InstrumentationRegistry.getInstrumentation().sendStatus(2,receipt);
    }
}
