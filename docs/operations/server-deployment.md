# Server deployment verification

See the [server deployment guide](../../sdk/node/DEPLOYMENT.md) for dependency
deadlines, overload controls, replay failure/recovery, ingress verification and
remaining release gates. The same guide is included as `DEPLOYMENT.md` in the
Node npm package, so its README link also works after local package installation.

For Python's existing identity budget, resolver cancellation behavior and host
concurrency/shutdown requirements, see the [Python integration guide](../../sdk/python/README.md)
and [identity deadline verification](../security/python-identity-deadlines.md).
For the separate whole-body capture budget and host receive cancellation limits,
see [body deadline verification](../security/python-body-deadlines.md).

For the Spring Boot Principal adapter's subject snapshot, early validation and
identity/key failure boundary, see [principal binding verification](../security/spring-principal-binding.md).
For preservation of directly reported callback interruption and host lifecycle
limits, see [Spring interruption verification](../security/spring-interruption.md).

The guide separates local SDK behavior from deployed ingress/load/failover,
supported-release, hosted CI, external audit, provider and physical-device
verification. These external gates remain unverified by local SDK tests.
