package io.appguard;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.regex.*;

/** Stateless pinned P-256/SHA-256 verification. A successful result is not authorization. */
public final class Verifier {
    private Verifier(){}
    static ECPublicKey loadKey(byte[] pem){
        Canonical.require(pem!=null && pem.length>0 && pem.length<=4096,"KEY_REJECTED");
        try{
            for(byte b:pem) if(b<0) throw new GeneralSecurityException();
            Matcher m=Pattern.compile("-----BEGIN PUBLIC KEY-----\\s+([A-Za-z0-9+/=\\r\\n]+)-----END PUBLIC KEY-----\\s*").matcher(new String(pem,StandardCharsets.US_ASCII));
            if(!m.matches()) throw new GeneralSecurityException();
            byte[] der=Base64.getDecoder().decode(m.group(1).replace("\r","").replace("\n",""));
            PublicKey key=KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
            if(!java.util.Arrays.equals(der,key.getEncoded())) throw new GeneralSecurityException();
            if(!(key instanceof ECPublicKey ec)) throw new GeneralSecurityException();
            AlgorithmParameters expected=AlgorithmParameters.getInstance("EC");expected.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec p=ec.getParams(), q=expected.getParameterSpec(ECParameterSpec.class);
            if(!p.getCurve().equals(q.getCurve()) || !p.getGenerator().equals(q.getGenerator()) || !p.getOrder().equals(q.getOrder()) || p.getCofactor()!=q.getCofactor()) throw new GeneralSecurityException();
            return ec;
        }catch(GeneralSecurityException | IllegalArgumentException e){throw Canonical.fail("KEY_REJECTED");}
    }
    public static VerificationResult verify(RequestInput request,SignatureParameters parameters,byte[] signature,String origin,String appId,String subject,KeyRecord key,long now,ReplayStore replay){
        Canonical.identifier(appId);Canonical.identifier(subject);byte[] base=Canonical.signatureBase(request,parameters,origin);
        Canonical.require(Canonical.validTime(now) && parameters.created()<parameters.expires() && parameters.expires()-parameters.created()<=120 && parameters.created()<=now+30 && now<parameters.expires(),"INVALID_TIME");
        String signedApp=Canonical.headers(request.headers(),false).get("appguard-app-id");
        Canonical.require(key!=null && !key.revoked() && appId.equals(key.appId()) && appId.equals(signedApp) && subject.equals(key.subject()) && parameters.keyId().equals(key.keyId()) && Canonical.ALGORITHM.equals(key.algorithm()),"KEY_REJECTED");
        ECPublicKey publicKey=loadKey(key.publicKeyPem());Canonical.contentDigest(request);
        Canonical.require(signature!=null && signature.length==64,"INVALID_SIGNATURE");
        try{
            Signature verifier=Signature.getInstance("SHA256withECDSAinP1363Format");verifier.initVerify(publicKey);verifier.update(base);
            Canonical.require(verifier.verify(signature),"INVALID_SIGNATURE");
        }catch(GeneralSecurityException e){throw Canonical.fail("INVALID_SIGNATURE");}
        Boolean claimed;
        try{claimed=replay.claim(new ReplayScope(appId,key.keyId(),parameters.nonce()),parameters.expires(),now);}
        catch(Exception e){throw Canonical.fail("REPLAY_STORE_UNAVAILABLE");}
        Canonical.require(claimed!=null,"REPLAY_STORE_UNAVAILABLE");Canonical.require(claimed,"REPLAY_DETECTED");
        return new VerificationResult(appId,key.keyId(),parameters.expires());
    }
}
