# Server deployment verification

See the [server deployment guide](../../sdk/node/DEPLOYMENT.md) for dependency
deadlines, overload controls, replay failure/recovery, ingress verification and
remaining release gates. The same guide is included as `DEPLOYMENT.md` in the
Node npm package, so its README link also works after local package installation.

The guide separates local SDK behavior from deployed ingress/load/failover,
supported-release, hosted CI, external audit, provider and physical-device
verification. These external gates remain unverified by local SDK tests.
