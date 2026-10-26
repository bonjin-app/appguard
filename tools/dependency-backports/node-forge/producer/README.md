# Retained modern Forge compiler recipe

This is a readable, portable recipe for the nine retained distribution files.
Static retention is not a fresh installation or compilation result. The existing
Forge `provenance.json` and distribution record remain historical and false.
The recipe uses modern Webpack transforms and does not reproduce the publisher's
original build process. Legal, browser/mobile, consumer, scan, CI and release
approval remain separate.

`package.json` and the complete `package-lock.json` are unchanged historical bytes:
86 records (root plus 85 dependencies), Webpack 5.112.1 and Mocha 12.0.3. The lock
contains no installed braces, micromatch, node-forge or resolve-workspace-root
package. The compiled Forge source comes from the separately retained archive,
not a compiler-tool npm dependency. A future tool graph containing one of those
affected logical packages requires explicit consumer-root derivative policy and
review of a new lock; do not add artificial dependencies to this graph.

`tool-tree.json` retains the full historical available compiler closure: 4,021
regular file digests and nine internal command aliases, including both locks and
all 85 package metadata files. Its presence is historical evidence, not a fresh
install proof. A separately qualified new install must match this full tree before
compilation. Any drift, including hidden-lock metadata, fails; never regenerate
the expectations to make a new installation pass.

`source-reference.json` records the official Git source/config reference.
Preparation reads all 49 lib files from the existing hash/SRI-bound published
archive using the established bounded parser, applies the one retained rsa.js
replacement, and adds the unchanged official webpack.config.js, original
package.json and LICENSE. The original `node-forge` package identity preserves
the `webpack://node-forge/` map namespace. Fork metadata is a later packaging step.
No duplicate expanded publisher tree or private workspace path is required.

From the repository root, use an existing Python 3.11 or later:

```sh
python3 -I -S -B scripts/dependencies/build-forge.py --prepare /owned/new-run
python3 -I -S -B scripts/dependencies/build-forge.py --verify-prepared /owned/new-run
```

Preparation creates `/owned/new-run/source` (52 files) and
`/owned/new-run/producer` (the two exact package/lock files). The root must be new,
its parent owned and not writable by other users. Directories use `0700`, files
`0600`. These commands perform no npm, JavaScript, compiler or lifecycle execution.

A separately reviewed runtime plan must first qualify the exact Node 22.23.2/npm
10.9.8 installation, package cache origin and a complete fresh install in the new
`producer` directory. This recipe never installs anything. Do not use postinstall,
global configuration changes, an implicit compiler fallback or the legacy OpenSSL
provider. Preserve the actual HOME/CODEX_HOME presence and values in every child.
The following commands are for that later qualified runtime step:

```sh
python3 -I -S -B scripts/dependencies/build-forge.py --verify-tools /owned/new-run
python3 -I -S -B scripts/dependencies/build-forge.py --build /owned/new-run \
  --output /owned/new-independent-output --node /existing/node \
  --npm-package /existing/npm/package.json
```

Only the Python driver is the supported entrypoint. It validates the retained
recipe, complete inputs, source, installed tool tree and npm metadata before it
launches the explicitly supplied Node binary. The Node script checks the exact
runtime version, complete source/tool tree and actual tool resolution origins
before loading Webpack. NODE_OPTIONS/NODE_PATH injection is rejected, without
rewriting the caller's environment. No package distribution is executed.

The official six configurations are transformed explicitly to web/ES5, mocked
Node globals, disabled buffer/process/crypto fallbacks, window for UMD and self
for workers. Production uses full source maps and an explicit single-process
ES5 Terser minimizer. Every compiler closes even on failure. Verification parses
all six JS outputs as ES5 (including existing literal-eval strings), compares the
three exact recorded map inventories and generator file digests, checks expected
warning counts, and matches all six JS and three map hashes. These are normal
build checks and do not execute crypto behavior or establish security claims.

Compilation writes only a new independent output directory. Six compiler JSON
records and a separate successful compilation receipt accompany the nine outputs;
partial outputs remain for diagnosis after failure. A changed source, config,
package/lock, tool file, map entry or output fails closed. Expected distributions
and hashes are never overwritten. The receipt records only this independent
hash match and syntax/map checks; original publisher reproduction and all other
adoption/release gates remain false. No fresh build receipt exists from source
retention alone.

Every file in this directory is individually hash-bound through the Forge
manifest inputs and trusted builder. The Python driver is bound through the
recipe. The source catalog discovers this complete package-lock.json normally;
all 85 tool dependencies must remain in source/SBOM/scan coverage without
advisory exclusions or suppression. Future maintainers must monitor upstream,
repeat independent builds, preserve failed evidence and review removal or
replacement when a supported fixed release is verified.
