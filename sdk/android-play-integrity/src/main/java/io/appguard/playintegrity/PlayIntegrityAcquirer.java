package io.appguard.playintegrity;

import android.content.Context;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.tasks.Tasks;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.StandardIntegrityException;
import com.google.android.play.core.integrity.StandardIntegrityManager;
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest;
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest;
import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.Executor;

/** Optional official Standard token acquisition. Only a server verifies evidence. */
public final class PlayIntegrityAcquirer {
    private static final Executor DIRECT = Runnable::run;
    private final StandardIntegrityManager manager;
    private final long cloudProjectNumber;

    /** No provider preparation or token request occurs until acquire is called. */
    public static PlayIntegrityAcquirer create(Context context, long cloudProjectNumber) {
        validateProject(cloudProjectNumber);
        if (context == null) throw new IllegalArgumentException("INVALID_CONTEXT");
        StandardIntegrityManager manager = null;
        try {
            Context application = context.getApplicationContext();
            manager = IntegrityManagerFactory.createStandard(application == null ? context : application);
        } catch (RuntimeException ignored) {
            // Deliberately discard raw Play/context exception details.
        }
        if (manager == null) throw new IllegalStateException("PLAY_INTEGRITY_UNAVAILABLE");
        return new PlayIntegrityAcquirer(manager, cloudProjectNumber);
    }

    // Package-scoped injection uses the official API boundary in offline tests.
    PlayIntegrityAcquirer(StandardIntegrityManager manager, long cloudProjectNumber) {
        validateProject(cloudProjectNumber);
        if (manager == null) throw new IllegalArgumentException("INVALID_INTEGRITY_MANAGER");
        this.manager = manager;
        this.cloudProjectNumber = cloudProjectNumber;
    }

    private static void validateProject(long number) {
        if (number <= 0) throw new IllegalArgumentException("INVALID_CLOUD_PROJECT_NUMBER");
    }

    private static boolean canonicalHash(String hash) {
        if (hash == null || !hash.matches("[A-Za-z0-9_-]{43}")) return false;
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(hash);
            return decoded.length == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(hash);
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    /** Request hash is canonical base64url(SHA256(exact enrollment message)). */
    public Task<PlayIntegrityResult> acquire(String challengeHash) {
        if (!canonicalHash(challengeHash)) {
            return Tasks.forResult(failed("INVALID_CHALLENGE_HASH", null));
        }
        TaskCompletionSource<PlayIntegrityResult> completion = new TaskCompletionSource<>();
        try {
            manager.prepareIntegrityToken(PrepareIntegrityTokenRequest.builder()
                    .setCloudProjectNumber(cloudProjectNumber).build())
                .addOnCompleteListener(DIRECT, prepared -> {
                    if (!prepared.isSuccessful()) {
                        completion.trySetResult(failure(prepared.getException(), challengeHash));
                        return;
                    }
                    try {
                        prepared.getResult().request(StandardIntegrityTokenRequest.builder()
                                .setRequestHash(challengeHash).build())
                            .addOnCompleteListener(DIRECT, requested -> {
                                if (!requested.isSuccessful()) {
                                    completion.trySetResult(failure(requested.getException(), challengeHash));
                                    return;
                                }
                                try {
                                    String token = requested.getResult().token();
                                    completion.trySetResult(evidence(token, challengeHash));
                                } catch (RuntimeException ignored) {
                                    completion.trySetResult(failed("INVALID_PROVIDER_RESPONSE", challengeHash));
                                }
                            });
                    } catch (RuntimeException ignored) {
                        completion.trySetResult(failed("PLAY_INTEGRITY_UNAVAILABLE", challengeHash));
                    }
                });
        } catch (RuntimeException ignored) {
            completion.trySetResult(failed("PLAY_INTEGRITY_UNAVAILABLE", challengeHash));
        }
        return completion.getTask();
    }

    private static PlayIntegrityResult evidence(String token, String hash) {
        if (token == null || token.isEmpty() || token.length() > 65536
                || !StandardCharsets.UTF_8.newEncoder().canEncode(token)) {
            return failed("INVALID_PROVIDER_RESPONSE", hash);
        }
        for (int index = 0; index < token.length(); index++) {
            char value = token.charAt(index);
            if (value < 32 || value == 127) return failed("INVALID_PROVIDER_RESPONSE", hash);
        }
        byte[] bytes = token.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 65536) return failed("INVALID_PROVIDER_RESPONSE", hash);
        return new PlayIntegrityResult(PlayIntegrityResult.State.EVIDENCE_AVAILABLE, "NONE", hash, bytes);
    }

    private static PlayIntegrityResult failed(String error, String hash) {
        return new PlayIntegrityResult(PlayIntegrityResult.State.UNAVAILABLE, error, hash, null);
    }

    private static PlayIntegrityResult failure(Exception error, String hash) {
        if (error instanceof StandardIntegrityException) {
            return failureForCode(((StandardIntegrityException) error).getErrorCode(), hash);
        }
        return failed("PLAY_INTEGRITY_UNAVAILABLE", hash);
    }

    static PlayIntegrityResult failureForCode(int code, String hash) {
        switch (code) {
            case StandardIntegrityErrorCode.API_NOT_AVAILABLE:
            case StandardIntegrityErrorCode.PLAY_STORE_NOT_FOUND:
            case StandardIntegrityErrorCode.PLAY_SERVICES_NOT_FOUND:
            case StandardIntegrityErrorCode.PLAY_STORE_VERSION_OUTDATED:
            case StandardIntegrityErrorCode.PLAY_SERVICES_VERSION_OUTDATED:
                return new PlayIntegrityResult(PlayIntegrityResult.State.UNSUPPORTED, "PLAY_INTEGRITY_UNSUPPORTED", hash, null);
            case StandardIntegrityErrorCode.CLOUD_PROJECT_NUMBER_IS_INVALID:
                return failed("INVALID_CLOUD_PROJECT_NUMBER", hash);
            default:
                return failed("PLAY_INTEGRITY_UNAVAILABLE", hash);
        }
    }
}
