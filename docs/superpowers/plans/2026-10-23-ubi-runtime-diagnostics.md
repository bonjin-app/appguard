# UBI10 diagnostic implementation plan

Approved scope is the v1 proposal plus v2 feature-first/NIO amendment and the
explicit new-path HOME/CODEX_HOME preservation ruling. Frozen proposal bytes
remain immutable. Implement only on the isolated UBI branch; no recursive
delegation, commit, push, CI dispatch or production substitution by the worker.

1. Add strict RPM/stage/envelope parsers and meaningful RED fixtures for NEVRA,
   multi-version identity, environment injection, partial feature result2 and
   independent aggregate equations. Preserve default dpkg/schema1/2/3.
2. Extract the existing feature engine without changing default output/exit.
   Add standard-Java17 fixed modes, direct Java PID1, NIO tree/DB hashing and
   bounded owned queries. Test real owned files/processes under pinned JDK17.
3. Integrate the explicit profile into the existing owned lifecycle. Test
   feature-first retention without shell/rpm/ldd, raw metadata ownership,
   timeout/cancellation/identity changes, overflow and private-parent rollback.
4. Append a copy-only pinned UBI target; add a separate strict comparison binder
   and fixed-runner workflow (manual on main; the exact owned evaluation branch
   also runs on push to obtain premerge evidence). Retain partial originals and counts;
   never convert UBI zero or a Debian control into verified Red Hat coverage.
5. Run focused RED→GREEN, existing relevant contracts, full tooling with pinned
   disposable Redis and release tests with pinned Syft. Run pinned actionlint
   and actual shell syntax/owned workflow fixtures. Record every failure and
   final source/log hashes in the new private implementation proof directory.
6. Self-review immutable inputs, parent-FD policy, child/environment handling,
   resource deadlines, exact-image identity, aggregate equations and false
   approval boundaries. Freeze and hand to root for independent scoped review.
7. Only root may commit/push/dispatch after review. Later native amd64/arm64 CI
   must actually observe the two exact images and report ten features, JRE
   equality, RPM/DB/providers, unsuppressed findings and cleanup separately.
   Missing utilities/feed evidence remain explicit incomplete results. No new
   packages, timeouts, CPU-default change or feed relaxation to force success.

Implementation evidence is local/static/owned-fixture only until that actual
CI runs. No UBI runtime, vulnerability reduction or production adoption result
is implied by this plan or passing unit tests.

The bootstrap push trigger is restricted to `codex/ubi-runtime-evaluation`.
GitHub requires a workflow on the default branch before manual dispatch, so this
exception permits testing the first version before integrating it into main.
It adds no main/PR trigger, caller-selected runner or production action. Later
manual runs retain the same fixed matrix, permissions, resource bounds and gates.
