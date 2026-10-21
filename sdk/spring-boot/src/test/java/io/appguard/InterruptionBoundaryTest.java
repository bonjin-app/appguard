package io.appguard;

import java.security.Principal;
import java.time.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import static org.assertj.core.api.Assertions.*;

class InterruptionBoundaryTest {
    @FunctionalInterface interface Checked { void run() throws Exception; }
    static final class Gate {
        final CountDownLatch entered=new CountDownLatch(1);
        void await() throws InterruptedException {
            entered.countDown();
            try { new CountDownLatch(1).await(); }
            catch(InterruptedException e) {
                e.initCause(new Exception("PRIVATE DEPENDENCY DETAIL"));
                throw e;
            }
        }
    }
    void onWorker(Checked action,Gate gate,boolean expectedFlag) throws Exception {
        AtomicReference<Throwable> failure=new AtomicReference<>();
        AtomicBoolean interrupted=new AtomicBoolean();
        Thread worker=new Thread(()->{
            try { action.run(); } catch(Throwable e) { failure.set(e); }
            finally { interrupted.set(Thread.currentThread().isInterrupted()); }
        },"appguard-interruption-test");
        worker.setDaemon(true);worker.start();
        try {
            if(gate!=null) {
                assertThat(gate.entered.await(5,TimeUnit.SECONDS)).as("callback reached blocking operation").isTrue();
                worker.interrupt();
            }
            worker.join(5000);
            assertThat(worker.isAlive()).as("worker completed").isFalse();
            assertThat(failure.get()).as("worker assertion or unexpected failure").isNull();
            assertThat(interrupted.get()).as("interruption signal after SDK boundary").isEqualTo(expectedFlag);
        } finally {
            if(worker.isAlive()){worker.interrupt();worker.join(5000);}
        }
    }
    static void fixed(Checked operation,String code) {
        Throwable error=catchThrowable(operation::run);
        assertThat(error).isInstanceOf(VerificationException.class);
        assertThat(((VerificationException)error).code()).isEqualTo(code);
        assertThat(error.getMessage()).isEqualTo(code);
        assertThat(error.getCause()).isNull();assertThat(error.getSuppressed()).isEmpty();
    }
    void directReplay(ReplayStore replay) throws Exception {
        List<Header> headers=SignedRequests.signed("POST","/echo",new byte[0],"application/json");
        ParsedSignature parsed=Wire.parse(headers);
        Verifier.verify(new RequestInput("POST","/echo",headers,new byte[0]),parsed.parameters(),parsed.signature(),
            SignedRequests.ORIGIN,"test-app","test-user",SignedRequests.key(),SignedRequests.NOW,replay);
    }
    void filterFailure(IdentityResolver identity,ReplayStore replay,String code,int expectedClock) throws Exception {
        AtomicInteger clocks=new AtomicInteger(),dispatches=new AtomicInteger();
        Clock clock=new Clock(){
            public ZoneId getZone(){return ZoneOffset.UTC;}
            public Clock withZone(ZoneId zone){return this;}
            public Instant instant(){clocks.incrementAndGet();return Instant.ofEpochSecond(SignedRequests.NOW);}
        };
        AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,identity,replay,clock,false);
        MockHttpServletRequest request=SignedRequests.request(new byte[0],"/echo","application/json");
        MockHttpServletResponse response=new MockHttpServletResponse();
        filter.doFilter(request,response,(req,res)->dispatches.incrementAndGet());
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString()).isEqualTo("{\"code\":\""+code+"\"}");
        assertThat(request.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE)).isNull();
        assertThat(dispatches).hasValue(0);assertThat(clocks).hasValue(expectedClock);
    }
    @Test void interruptedKeyLookupRestoresSignalForDirectAdapterCaller() throws Exception {
        Gate gate=new Gate();
        onWorker(()->{
            IdentityResolver identity=IdentityResolver.fromPrincipal((s,k)->{gate.await();return SignedRequests.key();});
            fixed(()->identity.resolve(SignedRequests.request(new byte[0],"/echo","application/json"),parameters()),"KEY_RESOLVER_UNAVAILABLE");
        },gate,true);
    }
    @Test void interruptedKeyLookupFailsClosedBeforeClockNonceAndDispatch() throws Exception {
        Gate gate=new Gate();AtomicInteger claims=new AtomicInteger();
        onWorker(()->filterFailure(IdentityResolver.fromPrincipal((s,k)->{gate.await();return SignedRequests.key();}),
            (s,e,n)->{claims.incrementAndGet();return true;},"KEY_RESOLVER_UNAVAILABLE",0),gate,true);
        assertThat(claims).hasValue(0);
    }
    @Test void interruptedCustomIdentityRestoresSignalAndDoesNotClaimNonce() throws Exception {
        Gate gate=new Gate();AtomicInteger claims=new AtomicInteger();
        onWorker(()->filterFailure((r,p)->{gate.await();return new Identity("test-user",SignedRequests.key());},
            (s,e,n)->{claims.incrementAndGet();return true;},"IDENTITY_UNAVAILABLE",0),gate,true);
        assertThat(claims).hasValue(0);
    }
    @Test void interruptedReplayRestoresSignalForDirectVerifierCaller() throws Exception {
        Gate gate=new Gate();AtomicInteger claims=new AtomicInteger();
        onWorker(()->fixed(()->directReplay((s,e,n)->{claims.incrementAndGet();gate.await();return true;}),
            "REPLAY_STORE_UNAVAILABLE"),gate,true);
        assertThat(claims).hasValue(1);
    }
    @Test void interruptedReplayRemainsUnavailableWithoutDispatchOrRetry() throws Exception {
        Gate gate=new Gate();AtomicInteger claims=new AtomicInteger();
        onWorker(()->filterFailure((r,p)->new Identity("test-user",SignedRequests.key()),
            (s,e,n)->{claims.incrementAndGet();gate.await();return true;},"REPLAY_STORE_UNAVAILABLE",1),gate,true);
        assertThat(claims).hasValue(1);
    }
    @SuppressWarnings("unchecked") static <E extends Throwable> String rethrow(Throwable error) throws E {throw (E)error;}
    @Test void principalGetterInterruptionKeepsIdentityOriginAndSignal() throws Exception {
        Gate gate=new Gate();AtomicInteger lookups=new AtomicInteger();
        onWorker(()->{
            MockHttpServletRequest request=SignedRequests.request(new byte[0],"/echo","application/json");
            // Java's Principal API has no checked throws; exercise the existing broad catch boundary.
            Principal principal=()->{try{gate.await();return "test-user";}catch(InterruptedException e){return rethrow(e);}};
            request.setUserPrincipal(principal);
            IdentityResolver identity=IdentityResolver.fromPrincipal((s,k)->{lookups.incrementAndGet();return SignedRequests.key();});
            fixed(()->identity.resolve(request,parameters()),"IDENTITY_UNAVAILABLE");
        },gate,true);
        assertThat(lookups).hasValue(0);
    }
    SignatureParameters parameters() {
        return new SignatureParameters(SignedRequests.NOW,SignedRequests.NOW+120,"AAAAAAAAAAAAAAAAAAAAAA","test-key",Canonical.ALGORITHM,Canonical.TAG);
    }
    @Test void ordinaryFailuresDoNotInventAnInterruption() throws Exception {
        onWorker(()->{
            filterFailure((r,p)->{throw new Exception("PRIVATE IDENTITY");},new LocalReplayStore(),"IDENTITY_UNAVAILABLE",0);
            filterFailure(IdentityResolver.fromPrincipal((s,k)->{throw new Exception("PRIVATE KEY");}),new LocalReplayStore(),"KEY_RESOLVER_UNAVAILABLE",0);
            filterFailure((r,p)->new Identity("test-user",SignedRequests.key()),(s,e,n)->{throw new Exception("PRIVATE REPLAY");},"REPLAY_STORE_UNAVAILABLE",1);
        },null,false);
    }
    @Test void nestedInterruptedCauseDoesNotInventACurrentThreadSignal() throws Exception {
        onWorker(()->{
            fixed(()->IdentityResolver.fromPrincipal((s,k)->{throw new Exception("PRIVATE",new InterruptedException());})
                .resolve(SignedRequests.request(new byte[0],"/echo","application/json"),parameters()),"KEY_RESOLVER_UNAVAILABLE");
            filterFailure((r,p)->{throw new Exception("PRIVATE",new InterruptedException());},new LocalReplayStore(),"IDENTITY_UNAVAILABLE",0);
            fixed(()->directReplay((s,e,n)->{throw new Exception("PRIVATE",new InterruptedException());}),"REPLAY_STORE_UNAVAILABLE");
        },null,false);
    }
    @Test void ordinaryFailureDoesNotClearAnAlreadySetSignal() throws Exception {
        onWorker(()->{
            MockHttpServletRequest request=SignedRequests.request(new byte[0],"/echo","application/json");
            Thread.currentThread().interrupt();
            fixed(()->IdentityResolver.fromPrincipal((s,k)->{throw new IllegalStateException("PRIVATE");})
                .resolve(request,parameters()),"KEY_RESOLVER_UNAVAILABLE");
        },null,true);
    }
    @Test void healthySignedRequestStillDispatchesOnceWithoutInterruption() throws Exception {
        onWorker(()->{
            AtomicInteger dispatches=new AtomicInteger(),claims=new AtomicInteger();
            AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,IdentityResolver.fromPrincipal((s,k)->SignedRequests.key()),
                (s,e,n)->{claims.incrementAndGet();return true;},Clock.fixed(Instant.ofEpochSecond(SignedRequests.NOW),ZoneOffset.UTC),false);
            MockHttpServletResponse response=new MockHttpServletResponse();
            filter.doFilter(SignedRequests.request(new byte[0],"/echo","application/json"),response,(r,s)->dispatches.incrementAndGet());
            assertThat(response.getStatus()).isEqualTo(200);assertThat(dispatches).hasValue(1);assertThat(claims).hasValue(1);
        },null,false);
    }
}
