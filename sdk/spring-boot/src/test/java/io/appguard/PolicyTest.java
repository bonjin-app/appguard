package io.appguard;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.*;
import org.junit.jupiter.api.*;
import static org.assertj.core.api.Assertions.*;
class PolicyTest {
    static List<String> strings(JsonNode node, List<String> fallback) { if(node==null)return fallback; List<String> out=new ArrayList<>();node.forEach(n->out.add(n.textValue()));return out; }
    @TestFactory Stream<DynamicTest> portableCases() throws Exception {
        JsonNode rows=new ObjectMapper().readTree(Path.of(System.getProperty("appguard.corpus"),"policy.json").toFile()); assertThat(rows.size()).isEqualTo(42);
        JsonNode localRisk=new ObjectMapper().readTree(Path.of(System.getProperty("appguard.corpus"),"local-risk-policy.json").toFile()); assertThat(localRisk.size()).isEqualTo(24);
        return Stream.concat(StreamSupport.stream(rows.spliterator(),false),StreamSupport.stream(localRisk.spliterator(),false)).map(row->DynamicTest.dynamicTest(row.get("id").asText(),()->{
            JsonNode p=row.get("policy"),c=row.get("context"),e=row.get("expected");
            Policy policy=new Policy(p.path("profile").asText("basic"),p.path("require_signature").asBoolean(true),strings(p.get("suspicious_signals"),List.of("debugger","root","hook","tamper")));
            PolicyContext context=new PolicyContext(c.path("authentication").asText("missing"),c.path("verification").asText("missing"),c.path("attestation").asText("missing"),c.hasNonNull("attestation_expires")?c.get("attestation_expires").longValue():null,strings(c.get("risk_signals"),List.of()),c.path("rate_limited").asBoolean(false));
            assertThat(PolicyEngine.evaluate(policy,context,row.get("now").longValue())).isEqualTo(new PolicyDecision(e.get("action").asText(),e.get("code").asText(),e.get("profile").asText()));
        }));
    }
    static PolicyContext fresh(List<String> risks) { return new PolicyContext("authenticated","verified","verified",101L,risks,false); }
    @Test void defaultsFailClosedAndOnlyBasicOptsOut() {
        for(String profile:List.of("basic","balanced","strict")) assertThat(PolicyEngine.evaluate(profile,new PolicyContext(),100).code()).isEqualTo("AUTHENTICATION_REQUIRED");
        assertThat(PolicyEngine.evaluate(new Policy("basic",false,List.of()),new PolicyContext(),100).action()).isEqualTo("deny");
        for(String profile:List.of("balanced","strict")) assertThatThrownBy(()->new Policy(profile,false,List.of())).isInstanceOf(PolicyException.class).hasMessage("INVALID_POLICY");
    }
    @Test void invalidInputsHaveFixedErrors() {
        assertThatThrownBy(()->new Policy("SECRET")).hasMessage("INVALID_POLICY");
        assertThatThrownBy(()->new Policy(null)).hasMessage("INVALID_POLICY");
        for(List<String> hints:List.of(List.of("root","root"),List.of("SECRET token"),List.of("x".repeat(65)),IntStream.range(0,33).mapToObj(i->"r"+i).toList())) assertThatThrownBy(()->new Policy("basic",true,hints)).hasMessage("INVALID_POLICY");
        assertThatThrownBy(()->new Policy("basic",true,null)).hasMessage("INVALID_POLICY");
        assertThatThrownBy(()->new PolicyContext("SECRET","missing","missing",null,List.of(),false)).hasMessage("INVALID_POLICY_CONTEXT");
        assertThatThrownBy(()->new PolicyContext("missing","SECRET","missing",null,List.of(),false)).hasMessage("INVALID_POLICY_CONTEXT");
        assertThatThrownBy(()->new PolicyContext("missing","missing","SECRET",null,List.of(),false)).hasMessage("INVALID_POLICY_CONTEXT");
        for(long time:new long[]{-1,1000000000000000L}) {
            assertThatThrownBy(()->new PolicyContext("missing","missing","missing",time,List.of(),false)).hasMessage("INVALID_POLICY_CONTEXT");
            assertThatThrownBy(()->PolicyEngine.evaluate("basic",new PolicyContext(),time)).hasMessage("INVALID_POLICY_CONTEXT");
        }
        assertThatThrownBy(()->new PolicyContext("missing","missing","missing",null,List.of("root","root"),false)).hasMessage("INVALID_POLICY_CONTEXT");
        assertThatThrownBy(()->PolicyEngine.evaluate((Policy)null,new PolicyContext(),100)).hasMessage("INVALID_POLICY");
        assertThatThrownBy(()->PolicyEngine.evaluate("basic",null,100)).hasMessage("INVALID_POLICY_CONTEXT");
        assertThatThrownBy(()->new PolicyDecision("allow","RATE_LIMITED","basic")).hasMessage("INVALID_POLICY_DECISION");
        assertThatThrownBy(()->new PolicyDecision("allow","SECRET","basic")).hasMessage("INVALID_POLICY_DECISION");
    }
    @Test void immutableCopiesAndRedactedStringRepresentation() {
        List<String> hints=new ArrayList<>(List.of("private_signal")); Policy p=new Policy("basic",true,hints); PolicyContext c=fresh(hints); hints.clear();
        assertThat(p.suspiciousSignals()).containsExactly("private_signal"); assertThat(c.riskSignals()).containsExactly("private_signal");
        assertThatThrownBy(()->c.riskSignals().add("root")).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(()->p.suspiciousSignals().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(p.toString()).doesNotContain("private_signal"); assertThat(c.toString()).doesNotContain("private_signal");
        assertThat(PolicyEngine.evaluate(p,c,100).code()).isEqualTo("RISK_DETECTED");
    }
    @Test void precedenceFreshnessAndUnknownHints() {
        assertThat(PolicyEngine.evaluate("strict",new PolicyContext("authenticated","rejected","rejected",101L,List.of("debugger"),true),100).code()).isEqualTo("REQUEST_REJECTED");
        assertThat(PolicyEngine.evaluate("basic",new PolicyContext("authenticated","missing","rejected",null,List.of(),false),100).code()).isEqualTo("ATTESTATION_REJECTED");
        assertThat(PolicyEngine.evaluate("basic",fresh(List.of()),101).code()).isEqualTo("ATTESTATION_EXPIRED");
        assertThat(PolicyEngine.evaluate("strict",fresh(List.of("verified")),100).action()).isEqualTo("allow");
    }
    @Test void auditAllowlistAndValidation() {
        PolicyDecision d=new PolicyDecision("allow","ALLOWED","basic");
        Map<String,Object> event=AuditEvent.create(d,"event-1","test-app",100,fresh(List.of("private_signal"))).toMap();
        assertThat(event).containsExactlyInAnyOrderEntriesOf(Map.of("schema_version","appguard-audit-v0","event_id","event-1","app_id","test-app","at",100L,"action","allow","code","ALLOWED","profile","basic","risk_count",1,"attestation_state","verified"));
        assertThat(event.toString()).doesNotContain("private_signal"); assertThatThrownBy(()->event.put("token","SECRET")).isInstanceOf(UnsupportedOperationException.class);
        assertThat(AuditEvent.create(d,"e","a",0).toMap()).hasSize(7);
        assertThatThrownBy(()->AuditEvent.create(null,"e","a",0)).hasMessage("INVALID_AUDIT_EVENT");
        assertThatThrownBy(()->AuditEvent.create(d,"SECRET token","a",0)).hasMessage("INVALID_AUDIT_EVENT");
        assertThatThrownBy(()->AuditEvent.create(d,"e","a".repeat(129),0)).hasMessage("INVALID_AUDIT_EVENT");
        assertThatThrownBy(()->AuditEvent.create(d,"e","a",-1)).hasMessage("INVALID_AUDIT_EVENT");
    }
    @Test void validatesCopiedListBoundsRatherThanTrustingCallerSize() {
        List<String> changing=new AbstractList<>() {
            @Override public String get(int index) { return "r"+index; }
            @Override public int size() { return 1; }
            @Override public Object[] toArray() { return IntStream.range(0,33).mapToObj(i->"r"+i).toArray(); }
        };
        assertThatThrownBy(()->new Policy("basic",true,changing)).hasMessage("INVALID_POLICY");
        assertThatThrownBy(()->fresh(changing)).hasMessage("INVALID_POLICY_CONTEXT");
    }
    @Test void completeSignalAndTimeBoundaries() {
        for(List<String> hints:List.of(List.of("root","root"),List.of("SECRET token"),List.of("x".repeat(65)),IntStream.range(0,33).mapToObj(i->"r"+i).toList(),Arrays.asList((String)null)))
            assertThatThrownBy(()->fresh(hints)).isInstanceOf(PolicyException.class).hasMessage("INVALID_POLICY_CONTEXT").hasNoCause();
        assertThatThrownBy(()->fresh(null)).hasMessage("INVALID_POLICY_CONTEXT");
        assertThat(PolicyEngine.evaluate("basic",new PolicyContext(),999999999999999L).code()).isEqualTo("AUTHENTICATION_REQUIRED");
        assertThat(AuditEvent.create(new PolicyDecision("allow","ALLOWED","basic"),"e","a",999999999999999L).toMap().get("at")).isEqualTo(999999999999999L);
        assertThatThrownBy(()->AuditEvent.create(new PolicyDecision("allow","ALLOWED","basic"),"e","a",1000000000000000L)).hasMessage("INVALID_AUDIT_EVENT");
    }
    @Test void checkedCallbackFailuresAndInterruptionAreRedacted() {
        PolicyDecision d=new PolicyDecision("allow","ALLOWED","basic");
        assertThatThrownBy(()->new JsonAuditSink(line->{throw new java.io.IOException("SECRET");}).emit(d,"e","a",0)).hasMessage("AUDIT_UNAVAILABLE").hasNoCause();
        try {
            assertThatThrownBy(()->new JsonAuditSink(line->{throw new InterruptedException("SECRET");}).emit(d,"e","a",0)).hasMessage("AUDIT_UNAVAILABLE").hasNoCause();
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally { Thread.interrupted(); }
    }
    @Test void sinkJsonAndRedactedFailures() throws Exception {
        PolicyDecision d=new PolicyDecision("deny","RATE_LIMITED","strict"); List<String> lines=new ArrayList<>();
        new JsonAuditSink(lines::add).emit(d,"e","a",100);
        assertThat(new ObjectMapper().readTree(lines.get(0)).get("code").asText()).isEqualTo("RATE_LIMITED");
        assertThat(lines.get(0)).doesNotContain(" ");
        assertThatThrownBy(()->new JsonAuditSink(line->{throw new IllegalStateException("SECRET token/body/key");}).emit(d,"e","a",100)).isInstanceOf(AuditUnavailableException.class).hasMessage("AUDIT_UNAVAILABLE").hasNoCause().satisfies(error->assertThat(error.getSuppressed()).isEmpty());
        assertThatThrownBy(()->new JsonAuditSink(null)).hasMessage("INVALID_AUDIT_EVENT");
    }
}
