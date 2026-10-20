package io.appguard.android;

import android.os.Build;
import android.security.keystore.*;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import org.junit.After;
import static org.junit.Assert.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/** Uses only fresh per-test aliases inside this test APK's own UID. */
public class InstallationKeyTest {
    private final List<String> aliases=new ArrayList<>();
    private String alias() {String a="appguard-test-"+UUID.randomUUID();aliases.add(a);return a;}
    private KeyStore store() throws Exception {KeyStore s=KeyStore.getInstance("AndroidKeyStore");s.load(null);return s;}
    @After public void tearDown() throws Exception {for(String a:aliases)store().deleteEntry(a);}
    @Test public void testGenerateReuseSignAndReportActualBacking() throws Exception {
        String a=alias();AndroidInstallationKey key=AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE);
        AndroidInstallationKey reused=AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE);
        assertEquals(key.publicKeyPem(),reused.publicKeyPem());
        KeyStore s=store();PrivateKey privateKey=(PrivateKey)s.getKey(a,null);assertNull(privateKey.getEncoded());
        KeyInfo info=KeyFactory.getInstance("EC","AndroidKeyStore").getKeySpec(privateKey,KeyInfo.class);
        assertEquals(info.isInsideSecureHardware(),key.backing()!=AndroidInstallationKey.Backing.SOFTWARE && key.backing()!=AndroidInstallationKey.Backing.UNKNOWN);
        android.util.Log.i("AppGuardTests","local-key-backing="+key.backing());
        RequestSigner.Input in=new RequestSigner.Input("POST","/x?a=1&a=2",new byte[]{0,1,2},"application/octet-stream","Bearer test","app","enrolled-key","https://api.example.test",1700000000,1700000120,"AAECAwQFBgcICQoLDA0ODw");
        final byte[][] base={null},der={null};new RequestSigner().prepare(in,b->{base[0]=b.clone();der[0]=key.signDer(b);return der[0];});
        Signature verify=Signature.getInstance("SHA256withECDSA");verify.initVerify(s.getCertificate(a).getPublicKey());verify.update(base[0]);assertTrue(verify.verify(der[0]));
        assertEquals(64,EcdsaP256.derToRaw(der[0]).length);
    }
    @Test public void testNativeEnrollmentProofUsesTheSameNonExportableKey() throws Exception {
        String a=alias();AndroidInstallationKey key=AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE);
        byte[] spki=key.publicKeySpki();assertTrue(Arrays.equals(store().getCertificate(a).getPublicKey().getEncoded(),spki));
        Arrays.fill(spki,(byte)0);assertTrue(Arrays.equals(store().getCertificate(a).getPublicKey().getEncoded(),key.publicKeySpki()));
        StringBuilder fp=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(key.publicKeySpki()))fp.append(String.format(Locale.ROOT,"%02x",b&255));
        String nonce="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        EnrollmentProof.Challenge challenge=new EnrollmentProof.Challenge("test-app","https://api.example.test","test-user","test-key",fp.toString(),nonce,1700000120);
        EnrollmentProof.Result proof=EnrollmentProof.create(challenge,"test-app","https://api.example.test","test-user","test-key",1700000000,key);
        String message="appguard-enrollment-v0\napp-id: test-app\norigin: https://api.example.test\nsubject: test-user\nkey-id: test-key\npublic-key-sha256: "+fp+"\nchallenge: "+nonce+"\nexpires: 1700000120";
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(message.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        assertTrue(Arrays.equals(digest,proof.clientDataHash()));assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(digest),proof.googleRequestHash());
        byte[] raw=proof.proof(),r=new java.math.BigInteger(1,Arrays.copyOfRange(raw,0,32)).toByteArray(),t=new java.math.BigInteger(1,Arrays.copyOfRange(raw,32,64)).toByteArray();
        byte[] der=new byte[r.length+t.length+6];der[0]=0x30;der[1]=(byte)(der.length-2);der[2]=2;der[3]=(byte)r.length;System.arraycopy(r,0,der,4,r.length);der[4+r.length]=2;der[5+r.length]=(byte)t.length;System.arraycopy(t,0,der,6+r.length,t.length);
        Signature verify=Signature.getInstance("SHA256withECDSA");verify.initVerify(store().getCertificate(a).getPublicKey());verify.update(message.getBytes(java.nio.charset.StandardCharsets.US_ASCII));assertTrue(verify.verify(der));
    }
    @Test public void testHardwareRequirementNeverAcceptsSoftwareOrReplacesAnExistingKey() throws Exception {
        String a=alias();AndroidInstallationKey key=AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE);
        if(key.backing()==AndroidInstallationKey.Backing.SOFTWARE || key.backing()==AndroidInstallationKey.Backing.UNKNOWN) {
            try {AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.HARDWARE_REQUIRED);fail("software cannot satisfy hardware");}catch(GeneralSecurityException expected) {}
            assertEquals(key.publicKeyPem(),AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE).publicKeyPem());
        }
    }
    @Test public void testExistingWrongKeyIsPreservedAndRejected() throws Exception {
        String a=alias();KeyPairGenerator g=KeyPairGenerator.getInstance("RSA","AndroidKeyStore");
        g.initialize(new KeyGenParameterSpec.Builder(a,KeyProperties.PURPOSE_SIGN).setKeySize(2048).setDigests(KeyProperties.DIGEST_SHA256).setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1).build());g.generateKeyPair();
        byte[] before=store().getCertificate(a).getEncoded();
        try {AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE);fail("must reject existing RSA");}catch(GeneralSecurityException expected) {}
        assertTrue(Arrays.equals(before,store().getCertificate(a).getEncoded()));
    }
    @Test public void testExistingRestrictedEcKeyIsPreservedAndRejected() throws Exception {
        String a=alias();KeyPairGenerator g=KeyPairGenerator.getInstance("EC","AndroidKeyStore");
        g.initialize(new KeyGenParameterSpec.Builder(a,KeyProperties.PURPOSE_SIGN).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA512).build());g.generateKeyPair();
        byte[] before=store().getCertificate(a).getEncoded();
        try {AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE);fail("must reject wrong digest");}catch(GeneralSecurityException expected) {}
        assertTrue(Arrays.equals(before,store().getCertificate(a).getEncoded()));
    }
    @Test public void testFiniteUsageKeyIsRejectedWithoutConsumingItsLastUse() throws Exception {
        if(Build.VERSION.SDK_INT<31)return;
        String a=alias();KeyPairGenerator g=KeyPairGenerator.getInstance("EC","AndroidKeyStore");
        g.initialize(new KeyGenParameterSpec.Builder(a,KeyProperties.PURPOSE_SIGN).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256).setMaxUsageCount(1).build());g.generateKeyPair();
        byte[] before=store().getCertificate(a).getEncoded();
        try {AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE);fail("finite-use key must reject before consuming its last use");}catch(GeneralSecurityException expected) {}
        assertNotNull(store().getCertificate(a));assertTrue(Arrays.equals(before,store().getCertificate(a).getEncoded()));
    }
    @Test public void testExplicitStrongBoxRequirementNeverDowngradesOrReplaces() throws Exception {
        String a=alias();AndroidInstallationKey initial=AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE);
        String before=initial.publicKeyPem();
        if(initial.backing()!=AndroidInstallationKey.Backing.STRONGBOX) {
            try {AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.STRONGBOX_REQUIRED);fail("must not downgrade");}catch(GeneralSecurityException expected) {}
            assertEquals(before,AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),a,AndroidInstallationKey.Requirement.ANY_KEYSTORE).publicKeyPem());
        }
        String fresh=alias();
        try {AndroidInstallationKey strong=AndroidInstallationKey.getOrCreate(InstrumentationRegistry.getInstrumentation().getTargetContext(),fresh,AndroidInstallationKey.Requirement.STRONGBOX_REQUIRED);
            assertEquals(AndroidInstallationKey.Backing.STRONGBOX,strong.backing());
        } catch(GeneralSecurityException expected) { /* Unsupported hardware is an explicit failure. */ }
    }
}
