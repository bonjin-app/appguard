# Production qualification implementation plan

1. Implement the store-and-forward ingress with focused tests before code;
   preserve signed bytes and impose bounded TLS/backend lifecycle handling.
2. Implement a runnable Spring mTLS consumer using the packaged starter,
   explicit identity/key/Redis configuration and resource authorization.
3. Implement a separate redacted readiness assessment and adversarial evidence
   tests. Reuse the real publication validator; retain every external blocker.
4. Build an owned-process qualification runner with ephemeral certificates;
   exercise actual TLS sockets against Spring and record hashes and cleanup.
5. Export and scan the actual example runtime graph, including its container.
   Do not substitute the starter-only graph or suppress findings.
6. Document installation, trust boundaries, commands and evidence limits in
   deployment guidance and the English/Korean/Japanese/Chinese entry points.
7. Run relevant suites and independent security review, fix confirmed findings,
   commit and merge to local main, push, and inspect hosted CI at the exact head.

Workers own disjoint gateway, backend and assessment files. The main agent owns
the qualification runner, documentation, CI integration and final verification.
No recursive delegation, account changes, physical-device work or registry
publication is part of this plan.
