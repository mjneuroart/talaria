# Add talaria: iOS Shortcuts from Hermes, compiled, signed and audited without a Mac

## What this adds

One catalog entry, `plugin-catalog/talaria.yaml`, for a Python plugin that gives Hermes the
iPhone Shortcuts surface.

Six tools:

- `talaria_status` — what actually works on this host: compiler path/version/sha256, whether
  `bwrap` can create a user namespace, whether the signer answers, library root.
- `talaria_actions` — verified Cherri signatures, the `#include` family each needs, and
  whether a parameter takes a literal or a variable.
- `talaria_build` — compiles inside a network-less `bwrap` sandbox, returns the unsigned
  `.shortcut`, the action inventory re-read from the produced plist, and its sha256.
- `talaria_sign` — Apple-signed artifact via RoutineHub HubSign, refusing without
  `consent=true` in the same call.
- `talaria_inspect` — decodes any `.shortcut` (signed AEA1 / LZFSE body, or plain plist) and
  reports actions plus severity-rated findings.
- `talaria_library` — list/get/save stored artifacts under `$HERMES_HOME/talaria`.

Plus a bundled `shortcuts-authoring` skill, because the model, not the tool, writes the
source.

## Why it belongs in the catalog

Nothing listed touches iOS Shortcuts, which is the largest automation surface on a phone.
Two properties are not available elsewhere in the ecosystem: signing an Apple container from
Linux, and auditing a shared `.shortcut` before it is installed. Builds are verified by
re-reading the plist, so `rc=0` is never treated as proof.

## Lineage (rule 16)

Not a fork. This is an independent implementation: no code, fixture or bundled resource is
shared with any other plugin or entry, so there is no origin to name and no duplicate lineage.
All work in this repository was written for Talaria.

## Disclosures (rule 13)

- **Subprocess:** runs `bwrap` and the Cherri compiler it discovers on the host. Both must be
  installed already; the plugin does not download or bundle either. No other subprocess exists:
  LZFSE/LZVN decoding and certificate parsing are pure Python, so there is no `lzfse` and no
  `openssl` call anywhere in the tree.
- **Network:** two explicit call sites, both inert by default. (1) `talaria_status` opens one TCP
  connection to the signing host only when called with `probe_signer=true`; the default opens
  none. (2) `talaria_sign` with `consent=true` POSTs the shortcut text (XML plist) and the
  shortcut name to `https://hubsign.routinehub.services/sign`. The refusal message names the
  destination and the payload before anything is sent.
- **Approval:** a `pre_tool_call` hook escalates every consented signing call to Hermes's approval
  gate, with a per-artifact `rule_key`. Unattended runs therefore fail closed (rule 12) instead of
  uploading with nobody present.
- **Local writes:** only under `$HERMES_HOME/talaria` (or `$TALARIA_HOME`), metadata mode 0600.
- **Not present:** no shell execution of model-written commands, no self-updater, no
  telemetry, no credentials, no API keys.

## Evidence

- `hermes plugins validate . --json` — exit 0, all 17 checks ok, warnings `[]`, security scan
  `safe`, isolation `verdict: host`, `ctx_methods: [register_hook, register_skill, register_tool]`.
- `hermes plugins doctor . --ci` — exit 0, `6 tool(s), 1 hook(s)`, declared set matches
  registrations (rule 6).
- `scripts/scan_plugin_payloads.py .` — exit 0: no compiled binary, no committed bytecode, no
  unreviewable archive. The LZFSE/LZVN decoder is a Python port, and the test vectors are base64
  in a JSON file, so nothing machine-readable is shipped.
- Test suite: 98 tests, `python3 -m unittest discover -s tests/python`. Without the compiler
  installed it still runs, skipping 15 build/sign tests instead of failing.
- Real tool calls on this machine: `talaria_status` reports compiler v2.4.0 and a working
  `bwrap`; `talaria_build` on the 16-action demo returns `artifact_id 65652a9668bde007`,
  9546 bytes, inventory of 16 actions; `talaria_inspect` decodes it (`magic: xml`, 16
  actions); `talaria_library action=list` lists it; `talaria_sign` without consent returns the
  refusal JSON and makes no request.
- No binaries and no bytecode in the tree: `__pycache__` is gitignored, and the compiler is
  host-provided (rule 17).

## Reviewer checklist (mapped to the README rules)

1. Human-merged gate — this PR.
2. Exact 40-hex SHA, no tag or branch (filled at release; see `docs/SUBMISSION.md`).
3. No self-updating code — no fetcher, no release download, no remote `plugin.js`.
4. SHA bumps are new PRs.
5. Submitted by the plugin's own author.
6. `capabilities.provides_tools` matches the six registrations, and `provides_hooks` declares the
   single `pre_tool_call` hook that guards signing. No middleware, no commands.
7. Scanner: `validate` reports `security scan: safe`.
8. Desktop surface: `desktop/plugin.js` registers a tool card and a library page through the
   plugin SDK only; `validate` reports `desktop surface: stays inside the plugin SDK surface`.
9. No core override: no `sys.modules` writes, no monkeypatching, no private Hermes imports.
10. No Python dependencies at all — nothing to resolve.
11. No credential reads: no `os.environ` secrets, no `.env`, no `auth.json`.
12. Approvals respected: a `pre_tool_call` hook routes every consented `talaria_sign` call to
    Hermes's approval gate, keyed per artifact. Under cron the gate resolves from the operator's
    `approvals.*_mode` policy instead of uploading silently.
13. Disclosed above and in `README.md`.
14. `requires_hermes: ">=0.23.1"` in the entry and in `plugin.yaml`; `version` matches.
15. No skin, no fork of a bundled plugin.
16. Fork named its origin in the entry description.
17. No bundled binaries or bytecode.
