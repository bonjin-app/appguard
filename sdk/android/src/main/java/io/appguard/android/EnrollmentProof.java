package io.appguard.android;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** Validated, domain-separated enrollment operation. No provider verification is performed. */
public final class EnrollmentProof {
    private EnrollmentProof() {}
    public static final class Challenge {
        private final String appId, origin, subject, keyId, publicKeySha256, nonce;
        private final long expires;
        public Challenge(String appId, String origin, String subject, String keyId,
                         String publicKeySha256, String nonce, long expires) {
            this.appId = appId; this.origin = origin; this.subject = subject; this.keyId = keyId;
            this.publicKeySha256 = publicKeySha256; this.nonce = nonce; this.expires = expires;
        }
    }
    public static final class Result {
        private final byte[] proof, hash;
        private Result(byte[] proof, byte[] hash) { this.proof = proof.clone(); this.hash = hash.clone(); }
        public byte[] proof() { return proof.clone(); }
        /** Apple clientDataHash input; acquiring platform evidence still requires a real provider. */
        public byte[] clientDataHash() { return hash.clone(); }
        /** Google Standard requestHash input; this value is not a provider verdict or token. */
        public String googleRequestHash() { return Base64.getUrlEncoder().withoutPadding().encodeToString(hash); }
    }
    public static Result create(Challenge c, String expectedAppId, String expectedOrigin,
                                String expectedSubject, String expectedKeyId, long now,
                                RequestSigner.PublicSigningKey key) throws GeneralSecurityException {
        if (c == null || key == null) invalid();
        RequestSigner.validateIdentifier(expectedAppId); RequestSigner.validateIdentifier(expectedSubject);
        RequestSigner.validateIdentifier(expectedKeyId); RequestSigner.validateOrigin(expectedOrigin);
        RequestSigner.validateIdentifier(c.appId); RequestSigner.validateIdentifier(c.subject);
        RequestSigner.validateIdentifier(c.keyId); RequestSigner.validateOrigin(c.origin);
        if (!c.appId.equals(expectedAppId) || !c.origin.equals(expectedOrigin)
                || !c.subject.equals(expectedSubject) || !c.keyId.equals(expectedKeyId)) invalid();
        if (c.publicKeySha256 == null || !c.publicKeySha256.matches("[0-9a-f]{64}")
                || c.nonce == null || !c.nonce.matches("[A-Za-z0-9_-]{43}")) invalid();
        byte[] nonce = Base64.getUrlDecoder().decode(c.nonce);
        if (nonce.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(nonce).equals(c.nonce)) invalid();
        if (now < 0 || now > 999999999999999L || c.expires < 0 || c.expires > 999999999999999L
                || now >= c.expires || c.expires - now > 300) invalid();
        byte[] spki = key.publicKeySpki();
        if (spki == null || spki.length == 0 || spki.length > 4096) throw new GeneralSecurityException("KEY_REJECTED");
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
        EcdsaP256.requireP256(publicKey);
        if (!Arrays.equals(spki, publicKey.getEncoded())) throw new GeneralSecurityException("KEY_REJECTED");
        if (!hex(MessageDigest.getInstance("SHA-256").digest(spki)).equals(c.publicKeySha256)) invalid();
        byte[] message = ("appguard-enrollment-v0\napp-id: " + c.appId + "\norigin: " + c.origin
                + "\nsubject: " + c.subject + "\nkey-id: " + c.keyId + "\npublic-key-sha256: "
                + c.publicKeySha256 + "\nchallenge: " + c.nonce + "\nexpires: " + c.expires)
                .getBytes(StandardCharsets.US_ASCII);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(message);
        return new Result(EcdsaP256.derToRaw(key.signDer(message)), hash);
    }
    private static String hex(byte[] bytes) {
        char[] alphabet = "0123456789abcdef".toCharArray(), out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) { out[i * 2] = alphabet[(bytes[i] & 255) >>> 4]; out[i * 2 + 1] = alphabet[bytes[i] & 15]; }
        return new String(out);
    }
    private static void invalid() { throw new IllegalArgumentException("INVALID_ENROLLMENT_CHALLENGE"); }
}
