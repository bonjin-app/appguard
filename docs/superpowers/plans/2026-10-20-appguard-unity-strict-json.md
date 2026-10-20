# Unity strict risk JSON fix plan

Authorized bounded fix: remove the previously deferred nonstandard JSON syntax
acceptance from the Unity local-risk response decoder, regressions/security review,
then clean local main fast-forward. Base 36ac17cb219bcc1eb660f213ed6ddbf4a147d3d2.

Root cause: Newtonsoft JsonTextReader accepts extensions before finite report
validation. Keep its duplicate-key and semantic checks, prepend a small bounded
syntax validator; no dependency/platform/API change. Input remains 4096 UTF8 bytes;
max 16 container levels, one JSON value, only standard four whitespace characters,
double-quoted strings/keys, legal escapes, JSON numbers/literals, no comments,
constructors or trailing commas. Require well-formed Unicode scalar strings as
an explicit stricter interchange profile; escaped lone surrogates reject too.

Ownership: parent sdk/unity/** and docs/protocol references only. Reuse managed
worktree/cache/evidence; no device/account/global config or native SDK changes.

- [x] Add raw-response regression cases through public ScanLocalRiskAsync; observe
  RED for prior accepted extensions, with existing 71 tests preserved.
- [x] Add Runtime/StrictRiskJson.cs syntax-only bounded validation and call before
  JObject.Load; preserve fixed errors, native codes, duplicate/schema/state checks.
- [x] GREEN full Unity suite and actual Android/iOS/runtime/postprocessor compilation;
  current relocated managed/native C ABI smoke with existing tools; no full XCFramework or player build.
- [x] One fresh read-only whole-change security review; parent handles any Critical/
  Important with RED/GREEN/full affected suite, no re-review; record Minor/rulings.
- [x] Update prior deferred status/docs/verification; preserve checksummed evidence,
  archive owned scratch, clean local main fast-forward and source hash readback.

Review focus: legal escapes/comments inside strings; decoded duplicates; raw/escaped
surrogate pairing; numeric extensions inside ignored error detail; whitespace/BOM;
container depth and byte/character bounds; identical fixed redacted error behavior.
