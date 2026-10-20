// Test-only ephemeral JCA producer; no private material is exported or persisted.
import com.fasterxml.jackson.databind.ObjectMapper;
import io.appguard.android.EnrollmentProof;
import io.appguard.android.JcaSigningKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

public final class AndroidEnrollmentProbe {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        JcaSigningKey key=new JcaSigningKey(generator.generateKeyPair());
        String fingerprint=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.publicKeySpki()));
        String nonce="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        long now=1700000000L,expires=now+120;
        EnrollmentProof.Challenge challenge=new EnrollmentProof.Challenge("test-app","https://api.example.test","test-user","android-installation-key",fingerprint,nonce,expires);
        EnrollmentProof.Result proof=EnrollmentProof.create(challenge,"test-app","https://api.example.test","test-user","android-installation-key",now,key);
        Map<String,Object> fields=Map.of("app_id","test-app","origin","https://api.example.test","subject","test-user","key_id","android-installation-key","public_key_sha256",fingerprint,"nonce",nonce,"expires",expires);
        System.out.println(new ObjectMapper().writeValueAsString(Map.of("challenge",fields,"proof_b64",Base64.getEncoder().encodeToString(proof.proof()),"public_key_pem",key.publicKeyPem(),"context",Map.of("now",now))));
    }
}
