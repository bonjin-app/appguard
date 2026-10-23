# UBI8 copy-only JRE implementation plan

Implement the approved [diagnostic contract](../specs/2026-10-23-ubi8-copy-jre-diagnostic.md)
on isolated branch `codex/ubi8-copy-jre-evaluation`, baseline393a524. The reviewed
private design is an immutable input. Own exactly the four shared integration
files, one new workflow, two new test modules and this separate spec/plan.
Preserve Java helper/probe bytes, old UBI10/default tests/workflow, scanners/tool
pins/controls, production defaults and release gates.

1. Write meaningful RED profile/lifecycle/binder and workflow tests. Exercise
   exact8.10 dispatch, invalid options before Docker, late/partial feature and
   missing-tool observations, fixed CPU provenance and cross-profile/pin denial.
2. Add `rpm-ubi8-copy-jre-v1` as an explicit fixed policy. Keep all existing
   caps, process ownership, deadlines, private publication and false approval
   equations. Leave old profile/default output contracts intact.
3. Insert the fixed copy-only UBI8 target before the unchanged final UBI10
   section. Copy the entire vendor JRE and existing probe/license outputs;
   no RUN, ENV, package, locale, font, library or loader-cache change.
4. Extend the binder through explicit fixed profile/base/JRE pins. Validate
   observed OS/CPU, original records and full tree equality including class
   archive, legal/security and literal links. Retain partial binding while
   completeness/feed/approval remain false. Bind new source/workflow hashes.
5. Add the exact branch-push/manual workflow with two fixed native runners,
   private owned state, same-ID native/scan/bind handoffs, both-role collection,
   native1/2 and scan/bind failure retention, exact-owned cleanup, a fixed
   status whitelist and nine explicit artifact paths.
6. Run the two new modules plus unchanged RPM/inventory/UBI binder/workflow
   contracts using existing Python3.11+. Run reviewed actionlint with optional
   shellcheck/pyflakes disabled, actual Bash syntax and owned CLI-stub tests.
   No network, dependency installation or actual Docker/npm/crypto execution
   is authorized for this local stage. Record failed attempts and final hashes
   in new ignored private evidence; do not change frozen earlier proofs.
7. Freeze a reviewable nine-file diff and source/test report for independent
   review. The implementer must not commit, push, dispatch or merge. Root may
   later authorize exact branch CI after review. Require actual native amd64
   and arm64 outcomes before integration, preserving failure/partial originals.

Local fixtures are not an actual UBI8/APT/RPM/ABI/CVE result. The initial scan
cannot establish clean coverage: UBI8 zero remains feed-unverified; Debian13
calibration and reported positive counts do not close that gap. Do not add a
positive control, change packages/caps or repair the copy-only image during
this first measurement. Runtime/native-closure/CPU/kernel/legal/external and
production approvals remain unresolved and false.
