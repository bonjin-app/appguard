// Test-only interoperability consumer; not included in a server/client package.
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.appguard.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class VerifyClientVector {
    static void rejected(Runnable operation) {
        try { operation.run(); } catch (VerificationException expected) { return; }
        throw new AssertionError("Mutated native request accepted");
    }
    public static void main(String[] args) throws Exception {
        JsonNode v = new ObjectMapper().readTree(System.in);
        JsonNode r=v.get("request"),p=v.get("parameters"),k=v.get("key"),c=v.get("context");
        List<Header> headers=new ArrayList<>();
        r.get("headers").forEach(pair->headers.add(new Header(pair.get(0).asText(),pair.get(1).asText())));
        byte[] body=Base64.getDecoder().decode(r.get("body_b64").asText());
        RequestInput request=new RequestInput(r.get("method").asText(),r.get("target").asText(),headers,body);
        ParsedSignature parsed=Wire.parse(headers);
        SignatureParameters parameters=new SignatureParameters(p.get("created").asLong(),p.get("expires").asLong(),p.get("nonce").asText(),p.get("key_id").asText(),p.get("algorithm").asText(),p.get("tag").asText());
        byte[] signature=Base64.getDecoder().decode(v.get("signature_b64").asText());
        if(!parameters.equals(parsed.parameters())||!Arrays.equals(signature,parsed.signature()))throw new AssertionError("Wire differs from typed input");
        KeyRecord key=new KeyRecord(k.get("app_id").asText(),k.get("key_id").asText(),k.get("subject").asText(),k.get("public_key_pem").asText().getBytes(StandardCharsets.US_ASCII),k.get("algorithm").asText(),k.get("revoked").asBoolean());
        String origin=c.get("origin").asText(),app=c.get("app_id").asText(),subject=c.get("subject").asText();
        long now=c.get("now").asLong();
        ReplayStore replay=new LocalReplayStore();
        if(!Verifier.verify(request,parameters,signature,origin,app,subject,key,now,replay).code().equals("VERIFIED"))throw new AssertionError();
        try { Verifier.verify(request,parameters,signature,origin,app,subject,key,now,replay);throw new AssertionError("Replay accepted"); }
        catch(VerificationException error){if(!error.code().equals("REPLAY_DETECTED"))throw error;}
        byte[] changed=Arrays.copyOf(body,body.length+1);changed[body.length]='!';
        rejected(()->Verifier.verify(new RequestInput(request.method(),request.target(),headers,changed),parameters,signature,origin,app,subject,key,now,new LocalReplayStore()));
        rejected(()->Verifier.verify(new RequestInput(request.method(),"/different-target",headers,body),parameters,signature,origin,app,subject,key,now,new LocalReplayStore()));
        List<Header> substituted=headers.stream().map(h->h.name().equalsIgnoreCase("authorization")?new Header(h.name(),"Bearer OTHER_TOKEN"):h).toList();
        rejected(()->Verifier.verify(new RequestInput(request.method(),request.target(),substituted,body),parameters,signature,origin,app,subject,key,now,new LocalReplayStore()));
        System.out.println("JAVA_NATIVE_CLIENT_VERIFIED_REPLAY_AND_MUTATIONS_REJECTED");
    }
}
