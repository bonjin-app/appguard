package io.appguard.android;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Base64;

final class EcdsaP256 {
    private static final BigInteger ORDER = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    private EcdsaP256() {}
    static void requireP256(Key key) throws GeneralSecurityException {
        if (!(key instanceof ECKey) || !"EC".equals(key.getAlgorithm())) reject();
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
        ECParameterSpec actual = ((ECKey) key).getParams();
        if (actual == null || !actual.getCurve().equals(expected.getCurve())
                || !actual.getGenerator().equals(expected.getGenerator()) || !actual.getOrder().equals(expected.getOrder())
                || actual.getCofactor() != expected.getCofactor()) reject();
        if (key instanceof ECPublicKey) {
            // Decode through the platform EC provider too, rejecting malformed public encodings.
            PublicKey parsed = java.security.KeyFactory.getInstance("EC").generatePublic(
                    new java.security.spec.X509EncodedKeySpec(key.getEncoded()));
            if (!(parsed instanceof ECPublicKey) || !((ECPublicKey) key).getW().equals(((ECPublicKey) parsed).getW())) reject();
        }
    }
    static String publicPem(PublicKey key) throws GeneralSecurityException {
        requireP256(key);
        String base64 = Base64.getEncoder().encodeToString(key.getEncoded());
        StringBuilder pem = new StringBuilder("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < base64.length(); i += 64) pem.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        return pem.append("-----END PUBLIC KEY-----\n").toString();
    }
    static byte[] derToRaw(byte[] der) throws GeneralSecurityException {
        if (der == null || der.length < 8 || der.length > 72 || der[0] != 0x30 || (der[1] & 255) != der.length - 2) reject();
        byte[] raw = new byte[64];
        int offset = integer(der, 2, raw, 0);
        offset = integer(der, offset, raw, 32);
        if (offset != der.length) reject();
        return raw;
    }
    private static int integer(byte[] der, int offset, byte[] raw, int dest) throws GeneralSecurityException {
        if (offset + 2 > der.length || der[offset] != 2) reject();
        int length = der[offset + 1] & 255, start = offset + 2;
        if (length < 1 || length > 33 || start + length > der.length || (der[start] & 128) != 0) reject();
        if (length > 1 && der[start] == 0 && (der[start + 1] & 128) == 0) reject();
        BigInteger scalar = new BigInteger(1, Arrays.copyOfRange(der, start, start + length));
        if (scalar.signum() <= 0 || scalar.compareTo(ORDER) >= 0) reject();
        int unsignedStart = der[start] == 0 ? start + 1 : start;
        int unsignedLength = start + length - unsignedStart;
        if (unsignedLength > 32) reject();
        System.arraycopy(der, unsignedStart, raw, dest + 32 - unsignedLength, unsignedLength);
        return start + length;
    }
    private static void reject() throws GeneralSecurityException { throw new GeneralSecurityException("KEY_OR_SIGNATURE_REJECTED"); }
}
