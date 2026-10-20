package io.appguard.android;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

/** JCA adapter for caller-owned P-256 keys. This class makes no hardware-storage claim. */
public final class JcaSigningKey implements RequestSigner.PublicSigningKey {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    public JcaSigningKey(KeyPair pair) throws GeneralSecurityException {
        if (pair == null) throw new GeneralSecurityException("KEY_REJECTED");
        EcdsaP256.requireP256(pair.getPrivate()); EcdsaP256.requireP256(pair.getPublic());
        privateKey = pair.getPrivate(); publicKey = pair.getPublic();
        provePair(this, publicKey);
    }
    @Override public byte[] publicKeySpki() { return publicKey.getEncoded().clone(); }
    public String publicKeyPem() throws GeneralSecurityException { return EcdsaP256.publicPem(publicKey); }
    @Override public byte[] signDer(byte[] base) throws GeneralSecurityException {
        if (base == null) throw new GeneralSecurityException("INVALID_SIGNING_INPUT");
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey); signature.update(base); return signature.sign();
    }
    static void provePair(RequestSigner.SigningKey signer, PublicKey publicKey) throws GeneralSecurityException {
        byte[] probe = new byte[32]; new SecureRandom().nextBytes(probe);
        byte[] signed = signer.signDer(probe); EcdsaP256.derToRaw(signed);
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey); verifier.update(probe);
        if (!verifier.verify(signed)) throw new GeneralSecurityException("KEY_REJECTED");
    }
}
