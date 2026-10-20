package io.appguard.playintegrity;

/** Opaque acquisition outcome; never a client attestation or hardware verdict. */
public final class PlayIntegrityResult {
    public enum State { EVIDENCE_AVAILABLE, UNSUPPORTED, UNAVAILABLE }
    private final State state;
    private final String errorCode;
    private final String requestHash;
    private final byte[] evidence;

    PlayIntegrityResult(State state, String errorCode, String requestHash, byte[] evidence) {
        this.state = state;
        this.errorCode = errorCode;
        this.requestHash = requestHash;
        this.evidence = evidence == null ? null : evidence.clone();
    }
    public State state() { return state; }
    public String errorCode() { return errorCode; }
    public String requestHash() { return requestHash; }
    public byte[] opaqueEvidence() { return evidence == null ? null : evidence.clone(); }
}
