# CLI input preservation fix plan

**Goal:** Reject malformed project text before initialization can rewrite source
bytes or produce a lossy backup. Preserve valid Unicode/BOM/line endings.
**Scope:** `tools/cli/src/files.js`, focused project/CLI regressions, CLI guide and
verification record. Existing Apache-2.0 and Node22+ boundary remain unchanged.
**Base:** local main `b5e19b6b0cf57b63fd453e839e980d1602787c05` in a separate managed
worktree/branch; pending physical Unity changes remain on their existing branch.

1. Establish green CLI baseline. Reproduce lossy invalid-UTF8 initialization with
   real temporary project bytes and actual CLI errors. Confirm rejected input leaves
   source/config/backup/lock state intact. No production change before RED.
2. Read bounded raw bytes, reject invalid UTF8 explicitly, then decode without BOM,
   Unicode or newline normalization. Test valid multilingual/BOM/CRLF inputs and
   byte-identical original backups. Run the complete CLI suite and isolated packed
   package consumer; no live app build, SDK installation or provider action.
   If the documented package command fails, preserve the failure, repair the
   guide/CI command, and demonstrate the exact corrected command locally.
3. One fresh read-only scoped security review. Fix material findings with regressions,
   preserve evidence and integrate only the independent CLI fix into clean local main
   under the existing local-integration authorization. No push/publication. Physical
   Unity runtime and its integration remain pending; preserve that entire worktree.

Review focus: no malformed-byte fallback; valid Unicode U+FFFD/BOM remains valid;
zero application writes before input rejection; fixed CLI errors do not leak file
contents/paths; no new archive format or credential handling; isolated npm package
contains the same fix. This is a data-preservation repair, not encoding conversion.
