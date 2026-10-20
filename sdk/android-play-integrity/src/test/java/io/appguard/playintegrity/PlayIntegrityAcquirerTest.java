package io.appguard.playintegrity;

import static org.junit.Assert.*;
import android.app.Activity;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.play.core.integrity.StandardIntegrityManager;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.Test;

/** Official Task boundaries are synthetic: no Play service/device verdict proof. */
public class PlayIntegrityAcquirerTest {
    private static final String HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final String TOKEN = "OFFLINE_TEST_ONLY_OPAQUE_TOKEN";

    private static class Manager implements StandardIntegrityManager {
        int preparations, requests;
        PrepareIntegrityTokenRequest preparation;
        StandardIntegrityTokenRequest request;
        Exception prepareError, requestError;
        boolean throwPrepare, throwRequest, cancelPrepare, cancelRequest;
        TaskCompletionSource<StandardIntegrityToken> pendingRequest;
        String token = TOKEN;
        @Override public Task<StandardIntegrityTokenProvider> prepareIntegrityToken(PrepareIntegrityTokenRequest value) {
            preparations++;
            preparation = value;
            if (throwPrepare) throw new RuntimeException(TOKEN);
            if (cancelPrepare) return Tasks.forCanceled();
            if (prepareError != null) return Tasks.forException(prepareError);
            return Tasks.forResult(tokenRequest -> {
                requests++;
                request = tokenRequest;
                if (throwRequest) throw new RuntimeException(TOKEN);
                if (cancelRequest) return Tasks.forCanceled();
                if (pendingRequest != null) return pendingRequest.getTask();
                if (requestError != null) return Tasks.forException(requestError);
                return Tasks.forResult(new StandardIntegrityToken() {
                    @Override public String token() { return token; }
                    @Override public Task<Integer> showDialog(Activity activity, int code) { throw new AssertionError(); }
                });
            });
        }
        @Override public Task<Integer> showDialog(StandardIntegrityDialogRequest value) { throw new AssertionError(); }
    }

    private PlayIntegrityResult acquire(Manager manager, String hash) {
        Task<PlayIntegrityResult> task = new PlayIntegrityAcquirer(manager, 123456789L).acquire(hash);
        assertTrue(task.isComplete());
        assertTrue(task.isSuccessful());
        return task.getResult();
    }

    @Test public void sendsExactCanonicalHashAndExplicitProjectAndReturnsOnlyOpaqueEvidence() {
        Manager manager = new Manager();
        PlayIntegrityResult result = acquire(manager, HASH);
        assertEquals(1, manager.preparations);
        // 1.6.0's generated immutable prepare value exposes its project as b().
        assertEquals(123456789L, manager.preparation.b());
        assertEquals(HASH, manager.request.requestHash());
        assertEquals(1, manager.requests);
        assertEquals(PlayIntegrityResult.State.EVIDENCE_AVAILABLE, result.state());
        assertEquals("NONE", result.errorCode());
        assertEquals(HASH, result.requestHash());
        assertArrayEquals(TOKEN.getBytes(StandardCharsets.UTF_8), result.opaqueEvidence());
        assertFalse(result.toString().contains(TOKEN));
        byte[] copied = result.opaqueEvidence();
        copied[0] = 0;
        assertEquals('O', result.opaqueEvidence()[0]);
    }

    @Test public void invalidHashNeverInvokesPlayIntegrity() {
        for (String hash : new String[] {null, "", "A".repeat(42), HASH + "=", "A".repeat(42) + "B", "../token"}) {
            Manager manager = new Manager();
            PlayIntegrityResult result = acquire(manager, hash);
            assertEquals(0, manager.preparations);
            assertEquals(PlayIntegrityResult.State.UNAVAILABLE, result.state());
            assertEquals("INVALID_CHALLENGE_HASH", result.errorCode());
            assertNull(result.opaqueEvidence());
        }
    }

    @Test public void invalidCloudProjectFailsBeforeAnyProviderCall() {
        for (long project : new long[] {0, -1, Long.MIN_VALUE}) {
            Manager manager = new Manager();
            try {
                new PlayIntegrityAcquirer(manager, project);
                fail();
            } catch (IllegalArgumentException error) {
                assertEquals("INVALID_CLOUD_PROJECT_NUMBER", error.getMessage());
                assertNull(error.getCause());
            }
            assertEquals(0, manager.preparations);
        }
    }

    @Test public void providerPrepareAndRequestErrorsAreFixedWithoutRawException() {
        for (int failure = 0; failure < 4; failure++) {
            Manager manager = new Manager();
            manager.prepareError = failure == 0 ? new RuntimeException(TOKEN) : null;
            manager.requestError = failure == 1 ? new RuntimeException(TOKEN) : null;
            manager.throwPrepare = failure == 2;
            manager.throwRequest = failure == 3;
            PlayIntegrityResult result = acquire(manager, HASH);
            assertEquals(PlayIntegrityResult.State.UNAVAILABLE, result.state());
            assertEquals("PLAY_INTEGRITY_UNAVAILABLE", result.errorCode());
            assertNull(result.opaqueEvidence());
            assertFalse(result.toString().contains(TOKEN));
        }
    }

    @Test public void malformedOrOversizedProviderTokenNeverBecomesEvidence() {
        for (String token : Arrays.asList(null, "", "token\nsecret", "\uD800", "x".repeat(65537))) {
            Manager manager = new Manager();
            manager.token = token;
            PlayIntegrityResult result = acquire(manager, HASH);
            assertEquals("INVALID_PROVIDER_RESPONSE", result.errorCode());
            assertEquals(PlayIntegrityResult.State.UNAVAILABLE, result.state());
            assertNull(result.opaqueEvidence());
        }
    }

    @Test public void mapsKnownUnsupportedCodesWithoutCallingThemVerified() {
        assertEquals(PlayIntegrityResult.State.UNSUPPORTED, PlayIntegrityAcquirer.failureForCode(-1, HASH).state());
        assertEquals(PlayIntegrityResult.State.UNSUPPORTED, PlayIntegrityAcquirer.failureForCode(-2, HASH).state());
        assertEquals(PlayIntegrityResult.State.UNSUPPORTED, PlayIntegrityAcquirer.failureForCode(-6, HASH).state());
        assertEquals(PlayIntegrityResult.State.UNAVAILABLE, PlayIntegrityAcquirer.failureForCode(-3, HASH).state());
        assertEquals("INVALID_CLOUD_PROJECT_NUMBER", PlayIntegrityAcquirer.failureForCode(-16, HASH).errorCode());
        assertEquals(PlayIntegrityResult.State.UNAVAILABLE, PlayIntegrityAcquirer.failureForCode(-100, HASH).state());
    }
    @Test public void canceledOfficialTasksReturnUnavailableWithoutEvidence() {
        for (boolean preparation : new boolean[] {true, false}) {
            Manager manager = new Manager();
            manager.cancelPrepare = preparation;
            manager.cancelRequest = !preparation;
            PlayIntegrityResult result = acquire(manager, HASH);
            assertEquals(PlayIntegrityResult.State.UNAVAILABLE, result.state());
            assertEquals("PLAY_INTEGRITY_UNAVAILABLE", result.errorCode());
            assertNull(result.opaqueEvidence());
        }
    }

    @Test public void delayedOfficialTaskCompletionIsObservedAndRedacted() {
        Manager manager = new Manager();
        manager.pendingRequest = new TaskCompletionSource<>();
        Task<PlayIntegrityResult> result = new PlayIntegrityAcquirer(manager, 123L).acquire(HASH);
        assertFalse(result.isComplete());
        manager.pendingRequest.setException(new RuntimeException(TOKEN));
        assertTrue(result.isComplete());
        assertTrue(result.isSuccessful());
        assertEquals("PLAY_INTEGRITY_UNAVAILABLE", result.getResult().errorCode());
        assertNull(result.getResult().opaqueEvidence());
    }
}
