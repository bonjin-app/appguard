# Unity strict local-risk JSON verification

Base36ac17cb219bcc1eb660f213ed6ddbf4a147d3d2. This bounded follow-up resolves the
previously deferred Unity response-syntax finding. Public APIs, native SDKs,
thread/JNI ownership, report semantics, dependencies and privacy resources are unchanged.

## Fix and contract

StrictRiskJson validates the entire bounded response before JsonTextReader loads
it. This syntax-only pass accepts one JSON value with standard quotes, delimiters,
escapes, number spelling, literals and only space/tab/CR/LF whitespace. It rejects
comments, single quotes, unquoted keys, trailing commas, constructors, leading-zero/
hex/nonfinite numbers, raw controls and multiple values. It consumes at most4096
UTF8 bytes with at most16 container levels. Existing duplicate decoded-key,
finite report/state/order/signal checks and redacted fixed errors remain downstream.

The grammar follows [RFC8259](https://www.rfc-editor.org/rfc/rfc8259).
The AppGuard interchange profile additionally rejects unpaired literal or escaped
UTF16 surrogates. RFC8259's ABNF permits escaped lone surrogates and documents
interoperability problems; the stricter profile is deliberate, not an assertion
that those escape sequences violate its ABNF. Legal paired escapes/raw non-BMP
strings and ignored error details retain their existing fixed-code behavior.

## Fresh tests

- Added67 raw-response cases through public Client.ScanLocalRiskAsync. Before the
  fix:138 total,102 pass,36 fail. All71 previous cases passed. Failures reproduce
  accepted legacy quote/key/comment/comma/whitespace/number/control/surrogate forms.
- After the validator:138/138 actual Unity6000.3.24f1 EditMode tests pass,zero
  failures/skips. Correct JSON, legal escapes/Unicode, comment-looking strings,
  whitespace, standard numbers/literals, decoded duplicates,16-level boundary,
  extreme nesting and exact4096UTF8 limits are covered. Existing32 shared report
  vectors and worker/JNI/error/ownership regressions remain green.
- Unity's actual compiler/references compile Android JNI,iOS PInvoke and iOS
  postprocessor branches with the new helper. These are compile checks,not mobile
  player/IL2CPP/device runtime or root/hook detection efficacy.

Reproduce from repository root:

```sh
python3 sdk/unity/Tools~/test-managed.py \
  --unity /Applications/Unity/Hub/Editor/6000.3.24f1/Unity.app/Contents/MacOS/Unity \
  --evidence-directory sdk/unity/.evidence/strict-json/green
```

RED/GREEN XML/logs and compiled branches are retained under package-owned
.evidence/strict-json/, with earlier evidence preserved. Parent stage evidence
will retain exact source/artifact hashes, fresh review probes and local integration
readback. No device/account/key/configuration/publication operation is included.

## Independent review and package verification

Fresh one-time whole-change security verification and relocated managed/native
checks are coordinated by the parent before local main integration.
