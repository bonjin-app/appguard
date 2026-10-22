# AppGuard Apple assertion client data v0 (experimental)

The opt-in [Python assertion lifecycle](../docs/security/apple-lifecycle.md)
combines App Attest assertions with an authenticated server challenge and an exact
application operation. This does not modify `request-signing-v0` or
`enrollment-v0`, and does not authorize resource access.

The server emits exactly the following ASCII bytes, in this order, with LF
separators and **no trailing LF**:

```text
appguard-apple-assertion-v0
app-id: <AppGuard application identifier>
apple-app-id: <provisioned Apple App ID prefix plus bundle ID>
environment: <development or production>
subject: <authenticated server subject>
key-id: <canonical padded standard base64 App Attest key ID>
request-sha256: <lowercase hex SHA-256 of exact operation bytes>
challenge: <canonical unpadded base64url of 32 random bytes>
issued-at: <integer UTC Unix seconds>
expires: <integer UTC Unix seconds>
```

`app-id` and `subject` use the existing AppGuard identifier syntax. Apple App ID
is server configuration and may use an App ID prefix different from Team ID.
`key-id` decodes to exactly 32 bytes. Timestamps are decimal integers with no
leading zeroes except `0`. Lifetime is 1..300 seconds. The server stores this exact
context under its nonce before sending it, and reconstructs these bytes from
server state at verification; a client-supplied JSON object cannot replace it.

The host defines a deterministic, unambiguous operation serialization. Include
all security-relevant method, authority/origin, exact raw target, body digest and
application/business fields. Verify against bytes reconstructed from the actual
received operation. Do not hash only a client-provided claim, reserialize JSON
without a published canonicalization rule, omit meaningful delimiters, or use
lossy normalized paths. The lifecycle accepts operation bytes of length 1..1 MiB.

Native callers compute `clientDataHash = SHA256(client_data)` once and supply
those 32 bytes, along with the already encoded App Attest key ID, to
`DCAppAttestService.generateAssertion`. Send its raw CBOR object, the nonce and key
ID to the authenticated server. Transport framing/base64 is a host concern; the
Python verifier takes decoded raw CBOR, bounded to 8 KiB.

Following Apple's [assertion verification procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server),
verify the signature using the previously attested P-256 public key and the digest
`SHA256(authenticatorData || SHA256(client_data))` with ECDSA/SHA-256 **prehashed**
verification. Do not hash that digest a second time. Verify RP ID, current signed
extension policy, counter increase, all context bindings and unconsumed challenge
expiry. Persist counter update and one-use consumption in one atomic transaction;
recheck expiry, revocation and the current counter after acquiring its write lock.

An assertion has no independently authenticated environment field. Environment
is pinned by initial attestation, server key state and this signed client message.
The server rejects cross-scope key reuse and retains revoked associations.

Synthetic vectors establish this serialization and crypto behavior only. Genuine
current-device acquisition, provider validation and receipt/fraud-risk lifecycle
remain separate evidence gates.
