# Unity strict local-risk JSON verification

Base 36ac17cb219bcc1eb660f213ed6ddbf4a147d3d2. This bounded follow-up resolves the
previously deferred Unity response-syntax finding. Public APIs, native SDKs,
thread/JNI ownership, report semantics, dependencies and privacy resources are unchanged.

## Fix and contract

StrictRiskJson validates the entire bounded response before JsonTextReader loads
it. This syntax-only pass accepts one JSON value with standard quotes, delimiters,
escapes, number spelling, literals and only space/tab/CR/LF whitespace. It rejects
comments, single quotes, unquoted keys, trailing commas, constructors, leading-zero/
hex/nonfinite numbers, raw controls and multiple values. It consumes at most 4096
UTF8 bytes with at most 16 container levels. Existing duplicate decoded-key,
finite report/state/order/signal checks and redacted fixed errors remain downstream.

The grammar follows [RFC8259](https://www.rfc-editor.org/rfc/rfc8259).
The AppGuard interchange profile additionally rejects unpaired literal or escaped
UTF16 surrogates. RFC8259's ABNF permits escaped lone surrogates and documents
interoperability problems; the stricter profile is deliberate, not an assertion
that those escape sequences violate its ABNF. Legal paired escapes/raw non-BMP
strings and ignored error details retain their existing fixed-code behavior.

## Fresh tests

- Added 67 raw-response cases through public Client.ScanLocalRiskAsync. Before the
  fix: 138 total, 102 pass, 36 fail. All 71 previous cases passed. Failures reproduce
  accepted legacy quote/key/comment/comma/whitespace/number/control/surrogate forms.
- After the validator: 138/138 actual Unity 6000.3.24f1 EditMode tests pass, zero
  failures/skips. Correct JSON, legal escapes/Unicode, comment-looking strings,
  whitespace, standard numbers/literals, decoded duplicates, 16-level boundary,
  extreme nesting and exact 4096 UTF8 limits are covered. Existing 32 shared report
  vectors and worker/JNI/error/ownership regressions remain green.
- Unity's actual compiler/references compile Android JNI, iOS PInvoke and iOS
  postprocessor branches with the new helper. These are compile checks, not mobile
  player/IL2CPP/device runtime or root/hook detection efficacy.

Reproduce from repository root:

```sh
python3 sdk/unity/Tools~/test-managed.py \
  --unity /Applications/Unity/Hub/Editor/6000.3.24f1/Unity.app/Contents/MacOS/Unity \
  --evidence-directory sdk/unity/.evidence/strict-json/green
```

RED/GREEN XML/logs and compiled branches are retained under package-owned
.evidence/strict-json/, with earlier evidence preserved. Parent stage evidence
retains exact source/artifact hashes, fresh review probes and local integration
readback under `.superpowers/evidence/2026-10-20-unity-strict-json/`. No device/account/key/configuration/publication operation is included.

## Independent review and package verification

A source-only relocated package includes the new helper. Fresh host checks built
the staged Swift SDK and Unity wrapper, ran **6 actual exported C ABI scans**,
and compiled the relocated managed sources with Unity's compiler/references for
**2 async managed/native scans with 2 matching buffer frees on the worker**.
The staged Swift SDK/wrapper also compiled to arm64 iOS 15 and arm64 Simulator
objects. Logs and artifacts are under `.evidence/strict-json/native/`.
These checks do not establish Unity mobile player, IL2CPP or physical-device behavior.

Independent probes compiled the actual current runtime sources with Unity's
compiler/references. Results: **172,240 syntax cases**, **5,616 finite Android/iOS
report-state combinations**, and **1,392 public async response cases**, all matching
the stated profile. Syntax probes use Python's strict JSON oracle plus explicit
byte/depth/Unicode-profile checks; they do not replace the Unity regression suite.
One malformed handwritten oracle fixture was corrected before the final run.
The single fresh whole-change review found **0 Critical, 0 Important, 0 Minor**;
22 additional public Unicode-byte/decoded-key boundary probes also passed.
No product fix pass or second review was needed. A stalled console-pipe probe
completed through regular-file I/O; the owned stalled process was stopped and its
diagnostic preserved. This was a harness issue, with no product changes.

Rulings and costs: retain the small syntax-only traversal ahead of JSON.NET to
preserve existing semantic/duplicate checks without new dependencies; the custom
grammar requires focused boundary verification. Reject unpaired surrogates as a
stricter interchange profile; opaque error extensions containing them now return
operation-failed. Preserve inherited JSON.NET numeric representation limits:
`1e9999` and a 3,000-digit integer are valid syntax but both base/current public
paths return the same redacted `APPGUARD_OPERATION_FAILED`. Expanding numeric
compatibility is outside this fix; the decoder does not promise every JSON numeric
magnitude. Current native reports contain no numeric fields. Host/player/IL2CPP
and physical-device evidence remain distinct.

Local integration uses a clean main fast-forward from the stated base; the final
stage receipt checks changed-file hashes against main and the compiled snapshot.
