# Absolute request-body capture deadline

Continue the approved server SDK hardening in the existing isolated checkout.
The current ASP.NET Core body loop has a byte cap but can await an incomplete
body forever while the client remains connected. Default and configured absolute
time budgets must cover the whole capture and final snapshot, without resetting
on progress or extending into authentication/downstream processing.

- [x] Reproduce the missing .NET deadline, add immutable validated default 30s configuration and implement bounded body capture.
- [x] Verify cancellation, ignored async cancellation/late faults, byte bounds, final snapshots and timer cleanup through targeted unit tests.
- [x] Run actual Kestrel raw HTTP stalled/drip/healthy concurrent requests and verify no authentication/key/clock/nonce/controller work after capture failure.
- [x] Record the verified Servlet blocking-read limitation; do not simulate a deadline with between-read clocks, idle timeouts or request-owned background threads.
- [x] Run affected .NET/Java suites, retained-binary consumer compatibility and independent review; update four README languages.

After committing, merge the verified same commit into main and inspect its
SDK CI and release gate to completion. Keep those point-in-time observations
in the exact-commit receipt rather than rewriting the candidate source.

The Spring filter cannot install a portable absolute read deadline via Servlet
6.0/6.1. Safely changing that requires a separate async lifecycle design; hosting
must provide an independently verified absolute upload boundary in the meantime.
This phase does not claim the Spring limitation is fixed. Physical devices,
provider accounts, external audits and registry publication remain excluded.
Existing upstream HIGH advisories keep the release gate blocked.
