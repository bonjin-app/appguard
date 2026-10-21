package io.appguard;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.time.*;
import java.util.Arrays;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import static org.assertj.core.api.Assertions.*;

/** Signed public-filter checks for one coherent Principal subject snapshot. */
class PrincipalBindingTest {
    static final byte[] BODY="{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    static final class Counts {int lookups,clocks,claims,dispatches;}

    MockHttpServletResponse invoke(Principal principal,KeyResolver keys,Counts counts)throws Exception {
        Clock clock=new Clock(){
            public ZoneId getZone(){return ZoneOffset.UTC;}
            public Clock withZone(ZoneId zone){return this;}
            public Instant instant(){counts.clocks++;return Instant.ofEpochSecond(SignedRequests.NOW);}
        };
        LocalReplayStore replay=new LocalReplayStore();
        AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,
            IdentityResolver.fromPrincipal((subject,keyId)->{counts.lookups++;return keys.resolve(subject,keyId);}),
            (scope,expires,now)->{counts.claims++;return replay.claim(scope,expires,now);},clock,false);
        MockHttpServletRequest request=SignedRequests.request(BODY,"/echo","application/json");
        request.setUserPrincipal(principal);
        MockHttpServletResponse response=new MockHttpServletResponse();
        filter.doFilter(request,response,(selected,output)->{
            counts.dispatches++;
            HttpServletRequest verified=(HttpServletRequest)selected;
            assertThat(verified.getUserPrincipal()).isSameAs(principal);
            assertThat(verified.getInputStream().readAllBytes()).isEqualTo(BODY);
            assertThat(((VerificationResult)verified.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE)).code()).isEqualTo("VERIFIED");
            output.getWriter().write("accepted");
        });
        return response;
    }

    static void failure(MockHttpServletResponse response,int status,String code)throws Exception {
        assertThat(response.getStatus()).isEqualTo(status);
        assertThat(response.getContentAsString()).isEqualTo("{\"code\":\""+code+"\"}");
    }

    @Test void principalWhoseSecondReadFailsStillVerifiesItsFirstSubject()throws Exception {
        AtomicInteger reads=new AtomicInteger();
        Principal principal=()->{
            if(reads.getAndIncrement()!=0)throw new IllegalStateException("PRIVATE_SECOND_PRINCIPAL_READ");
            return "test-user";
        };
        Counts counts=new Counts();
        MockHttpServletResponse response=invoke(principal,(subject,keyId)->{
            assertThat(subject).isEqualTo("test-user");assertThat(keyId).isEqualTo("test-key");return SignedRequests.key();
        },counts);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).isEqualTo("accepted");
        assertThat(reads).hasValue(1);
        assertThat(counts.lookups).isEqualTo(1);assertThat(counts.clocks).isEqualTo(1);
        assertThat(counts.claims).isEqualTo(1);assertThat(counts.dispatches).isEqualTo(1);
    }

    @Test void lookupMutationCannotReplaceTheSubjectUsedToSelectItsKey()throws Exception {
        AtomicReference<String> name=new AtomicReference<>("test-user");
        Principal principal=name::get;
        Counts counts=new Counts();
        MockHttpServletResponse response=invoke(principal,(subject,keyId)->{
            assertThat(subject).isEqualTo("test-user");name.set("changed-user");return SignedRequests.key();
        },counts);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).isEqualTo("accepted");
        assertThat(counts.claims).isEqualTo(1);assertThat(counts.dispatches).isEqualTo(1);
        // AppGuard preserves the host Principal object; other consumers own it.
        assertThat(name).hasValue("changed-user");
    }

    @Test void aChangedPrincipalCannotMakeAnotherSubjectsKeyMatch()throws Exception {
        AtomicReference<String> name=new AtomicReference<>("test-user");
        Counts counts=new Counts();
        MockHttpServletResponse response=invoke(name::get,(subject,keyId)->{
            assertThat(subject).isEqualTo("test-user");name.set("changed-user");
            KeyRecord original=SignedRequests.key();
            return new KeyRecord(original.appId(),original.keyId(),"changed-user",original.publicKeyPem(),original.algorithm(),false);
        },counts);
        failure(response,403,"KEY_REJECTED");
        assertThat(counts.lookups).isEqualTo(1);assertThat(counts.clocks).isEqualTo(1);
        assertThat(counts.claims).isZero();assertThat(counts.dispatches).isZero();
    }

    @Test void malformedPrincipalNamesNeverReachTheKeyRepository()throws Exception {
        for(String subject:Arrays.asList(null,"","bad subject","line\nbreak","é","a".repeat(129),"user@example.test")){
            Counts counts=new Counts();
            failure(invoke(()->subject,(ignored,keyId)->SignedRequests.key(),counts),503,"IDENTITY_UNAVAILABLE");
            assertThat(counts.lookups).isZero();assertThat(counts.clocks).isZero();
            assertThat(counts.claims).isZero();assertThat(counts.dispatches).isZero();
        }
    }

    @Test void missingPrincipalStillRejectsWithoutRepositoryOrClock()throws Exception {
        Counts counts=new Counts();
        failure(invoke(null,(subject,keyId)->SignedRequests.key(),counts),401,"AUTHENTICATION_REQUIRED");
        assertThat(counts.lookups).isZero();assertThat(counts.clocks).isZero();
        assertThat(counts.claims).isZero();assertThat(counts.dispatches).isZero();
    }

    @Test void principalGetterFailureRemainsPrivateAndDoesNotBecomeAKeyLookupFailure()throws Exception {
        Counts counts=new Counts();
        failure(invoke(()->{throw new IllegalStateException("PRIVATE_PRINCIPAL_SECRET");},
            (subject,keyId)->SignedRequests.key(),counts),503,"IDENTITY_UNAVAILABLE");
        assertThat(counts.lookups).isZero();assertThat(counts.clocks).isZero();
        assertThat(counts.claims).isZero();assertThat(counts.dispatches).isZero();
    }

    @Test void principalGetterCannotChooseTheKeyRepositoryFailureCode()throws Exception {
        Counts counts=new Counts();
        failure(invoke(()->{throw Canonical.fail("KEY_RESOLVER_UNAVAILABLE");},
            (subject,keyId)->SignedRequests.key(),counts),503,"IDENTITY_UNAVAILABLE");
        assertThat(counts.lookups).isZero();assertThat(counts.clocks).isZero();
        assertThat(counts.claims).isZero();assertThat(counts.dispatches).isZero();
    }

    @Test void directAdapterGetterFailureHasOnlyTheFixedIdentityReason()throws Exception {
        MockHttpServletRequest request=SignedRequests.request(BODY,"/echo","application/json");
        request.setUserPrincipal(()->{throw new IllegalStateException("PRIVATE_DIRECT_PRINCIPAL_SECRET");});
        AtomicInteger lookups=new AtomicInteger();
        IdentityResolver resolver=IdentityResolver.fromPrincipal((subject,keyId)->{
            lookups.incrementAndGet();return SignedRequests.key();
        });
        var parameters=Wire.parse(SignedRequests.signed("POST","/echo",BODY,"application/json")).parameters();
        Throwable failure=catchThrowable(()->resolver.resolve(request,parameters));
        assertThat(failure).isInstanceOf(VerificationException.class).hasMessage("IDENTITY_UNAVAILABLE").hasNoCause();
        assertThat(lookups).hasValue(0);
    }
}
