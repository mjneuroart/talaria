# Changelog

## 0.2.0 — 2026-11-10

Hardening pass driven by an adversarial review of 0.1.0. Every change below answers a
finding that was reproduced against the code, not a guess.

- **No compiled binary in the tree.** LZFSE and LZVN decoding is now a pure-Python port of
  Apple's reference decoder, verified byte-for-byte against it on five vectors (stored,
  LZVN, and LZFSE v2 blocks up to 123 KB of output). The vendored ELF is gone, so the plugin
  runs on any architecture and rule 17 holds by construction. Audit no longer calls
  `openssl`; certificate facts come from the in-tree DER reader.
- **The sandbox fails closed.** Without `bwrap` a build is refused instead of running the
  compiler on the host. The read-only root is now actually remounted read-only after the
  mounts are created, and `$HOME` is a throwaway tmpfs instead of a writable bind.
- **Signing asks a human.** A `pre_tool_call` hook escalates every consented signing call to
  Hermes's approval gate, keyed per artifact, so an unattended run cannot upload silently.
- **What was audited is what ships.** `talaria_sign` re-checks the stored artifact against
  its recorded sha256, re-runs the source filter, and compares the action list decoded from
  the signed container with the audited one. A mismatch is refused.
- **The source filter mirrors the compiler's grammar.** `#define` and `#include` accept any
  single separator character, so the old whitespace assumption was bypassable with one
  changed character. Every `#include` occurrence is now checked against the one allowed form,
  and unbalanced braces, parentheses or block comments are rejected before compiling.
- **Green is not proof.** Beyond "zero actions", a build now fails when the shortcut contains
  only no-op actions or leaves a control-flow block open — the shapes this compiler produces
  when a source is truncated.
- **No network by default.** `talaria_status` no longer opens a socket unless called with
  `probe_signer=true`; it also reports whether the compiler is a pinned build, and refuses to
  run an unaudited one unless `$TALARIA_ALLOW_UNPINNED=1` says so explicitly.
- **The audit fails closed.** An action with no rule is reported as `UNASSESSED_ACTION`
  instead of being counted as clean; the URL-scheme rule now watches the openers that exist
  (`openurl`, `openxcallbackurl`, `showwebpage`) instead of the passive `url` action;
  clipboard reads through a variable are detected; binary plists are read (the old check
  compared six bytes with an eight-byte magic); a forged AEA1 container is an anomaly.
- **Tests: 66, up from 33.** They run without the compiler (15 skip), and the decoder vectors
  ship as base64 in a JSON file so no binary payload is in the tree.

## 0.1.0 — 2026-11-10

Initial release.

- Six tools: `talaria_status`, `talaria_actions`, `talaria_build`, `talaria_sign`,
  `talaria_inspect`, `talaria_library`.
- Compilation inside a `bwrap` sandbox: no network, read-only root, fresh tmpfs `$HOME`,
  only the compiler and the job directory visible.
- Builds are verified by re-reading the produced plist; zero actions fails the build even
  when the compiler exits 0.
- `--skip-sign` is always passed; the only path that can reach the network is
  `talaria_sign`, and it refuses without `consent=true` in the same call.
- Signed-artifact support: AEA1 header parsing, certificate chain facts, LZFSE body
  decoding for inspection.
- Audit rules with severity: network writes, clipboard reads, writes outside the
  shortcut container, URL-scheme launches, `Run Shortcut` recursion, health/location/
  contacts reads.
- Bundled `shortcuts-authoring` skill: file shape, verified action signatures, house
  patterns, and the rules that keep a build from silently breaking.
- Artifact library under `$HERMES_HOME/talaria` (or `$TALARIA_HOME`), metadata mode 0600.
- Derived from `an earlier internal prototype` (MIT); lineage credited in `AUTHORS`
  and the README.
