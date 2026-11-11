# Talaria

iOS Shortcuts for Hermes: author them in plain language, compile them, sign them with an
Apple certificate, and audit them before they reach the phone — on Linux, with no Mac in the
loop.

Talaria is the winged sandals of Hermes. Delivery to the phone.

## What it does

iOS Shortcuts is the largest automation surface on an iPhone, and nothing in the Hermes
plugin ecosystem touches it. Without Talaria the agent can only tell you what to tap. With
Talaria it writes real Cherri source, compiles it to a `.shortcut`, has it signed by an
Apple-issued certificate, and gives you a risk report on the finished file — all as reviewable
artifacts on disk.

Four things it produces, in order:

1. **Source** — plain-text Cherri, readable and diffable before anything runs.
2. **Unsigned `.shortcut`** — compiled inside a network-less sandbox.
3. **Signed `.shortcut`** — an AEA1 container signed through RoutineHub HubSign, produced
   without Xcode and without a Mac. Only on explicit consent.
4. **An audit** — every action decoded, with severity-rated findings, before you install it.

The bundled `shortcuts-authoring` skill teaches the model to write Cherri that compiles: file
shape, verified action signatures, house patterns, and the traps that make a shortcut compile
cleanly and still be broken.

## Why it matters

- **No Mac.** Signing normally requires a Mac with Xcode. Talaria gets an Apple-signed file
  from Linux, because the signing service returns a genuinely signed container.
- **Evidence, not exit codes.** The Cherri compiler returns 0 on several malformed inputs.
  Talaria re-reads the plist it just produced and fails the build when there are zero actions,
  so a green compile is never mistaken for a working shortcut.
- **No silent data egress.** The compiler is always invoked with `--skip-sign`, because on
  Linux the default path uploads the shortcut to RoutineHub. Upload happens only when you call
  `talaria_sign` with consent.
- **Audit before install.** A shared `.shortcut` from the internet is an opaque binary. Talaria
  decodes it, including signed ones, and tells you what it reads, writes and sends.

## Install

From the repository:

```bash
hermes plugins install mjneuroart/talaria --enable
```

From the catalog, once the entry is merged (catalog key `hermes-shortcuts`):

```bash
hermes plugins install hermes-shortcuts --enable
```

From a checkout, for development (the plugin directory must be discoverable by Hermes):

```bash
ln -s "$PWD" ~/.hermes/plugins/hermes-shortcuts
hermes plugins validate ~/.hermes/plugins/hermes-shortcuts
hermes plugins doctor hermes-shortcuts --ci
```

Requirements: Hermes `>=0.23.1`, Python 3.10+, and for builds only two host tools: the Cherri
compiler v2.4.0 (on `PATH`, or point `$TALARIA_CHERRI` at it) and `bwrap`. Builds run on Linux,
and without `bwrap` they are refused rather than run on the host. Signing needs outbound HTTPS to
RoutineHub. There is nothing else to install: LZFSE and LZVN are decoded in pure Python, so no
`lzfse` command and no `openssl` are involved anywhere.

## The seven tools

| Tool | What it does |
|---|---|
| `talaria_status` | What works here: compiler, sandbox, signer, library, versions, hashes |
| `talaria_setup` | Download the pinned Cherri release, verify its sha256, install it under plugin data (needs `confirm: true`) |
| `talaria_actions` | Verified Cherri signatures, includes and parameter types |
| `talaria_build` | Compile to unsigned `.shortcut` + action inventory + sha256 |
| `talaria_sign` | Apple-sign an artifact, with consent in the same call |
| `talaria_inspect` | Decode and audit any `.shortcut`, signed or unsigned |
| `talaria_library` | List, read or re-save stored artifacts |

### `talaria_status`

```json
{"tool": "talaria_status", "arguments": {}}
```

Returns the compiler path, version and sha256, whether `bwrap` can create a user namespace,
whether the signer answers, and the library root. Call it first when a build fails.

### `talaria_setup`

```json
{"tool": "talaria_setup", "arguments": {"confirm": true}}
```

Downloads the pinned Cherri v2.4.0 release for this platform, checks the sha256 recorded in
`talaria/env.py` (`PINNED`), and installs it under the plugin data directory. Without
`confirm: true` it downloads nothing and returns what it would fetch. A `pre_tool_call` hook
turns `confirm: true` into an approval request, so the download never happens silently.

### `talaria_actions`

```json
{"tool": "talaria_actions", "arguments": {"query": "clipboard", "limit": 5}}
```

Returns exact signatures (`getClipboard()`, `setClipboard(variable value, bool ?local = false,
text ?expire)`), the `#include` family each action needs, and whether a parameter takes a
literal or a variable. The corpus is the compiled example set, not a guess.

### `talaria_build`

```json
{"tool": "talaria_build", "arguments": {
  "name": "meeting-note",
  "source": "#include 'actions/calendar'\n#include 'actions/documents'\nconst now = currentDate()\nconst stamp = formatDate(now, \"Custom\", \"yyyy-MM-dd HH:mm\")\nconst body = prompt(\"What was decided?\", \"Text\", \"\")\nif !body {\n  alert(\"Empty note discarded\", \"Talaria\")\n} else {\n  @line = \"{stamp} | {body}\"\n  saveFile(\"talaria/notes.txt\", @line, true)\n  show(@line)\n}\n"
}}
```

Returns `artifact_id`, `path`, `sha256`, `bytes`, `actions`, the full `inventory` and the
compiler `diagnostics` (argv, rc, stdout, isolation mode). Never signs, never uploads. A
`path` argument works too when the source is already on disk.

### `talaria_sign`

```json
{"tool": "talaria_sign", "arguments": {"artifact_id": "65652a9668bde007", "consent": true}}
```

Without `consent: true` it refuses and states exactly what would leave the machine. With
consent it uploads the shortcut text to RoutineHub HubSign and returns the signed file path,
the AEA header facts, the certificate issuer chain and the sha256.

### `talaria_inspect`

```json
{"tool": "talaria_inspect", "arguments": {"path": "/home/you/.hermes/talaria/artifacts/65652a9668bde007_unsigned.shortcut"}}
```

Returns the container facts (`xml`, `bplist00` or `AEA1` with issuers), every action with its
human name and a parameter summary, and findings with severity: network writes, clipboard
reads, file writes outside the shortcut's own container, URL-scheme launches, `Run Shortcut`
recursion, and reads of health, location or contacts.

### `talaria_library`

```json
{"tool": "talaria_library", "arguments": {"action": "list"}}
```

Returns stored artifacts newest first: id, name, timestamp, action count, sign state, sha256,
size, and the library root.

## Security model

- **Sandbox always.** Compilation runs under `bwrap`: no network namespace, a read-only root,
  a fresh tmpfs `$HOME`, and only the compiler binary and the job directory visible. If the
  sandbox cannot be established, the build fails rather than running unsandboxed.
- **No silent network.** The compiler is always invoked with `--skip-sign`; without that flag, a
  Linux-hosted Cherri compiler uploads the shortcut to RoutineHub. Two call sites exist and both
  are explicit: `talaria_status` opens one TCP connection only when called with
  `probe_signer=true` (the default opens none), and `talaria_sign` uploads only when `consent` is
  exactly `true`.
- **Consent for signing, in the same call.** `talaria_sign` refuses unless `consent` is exactly
  `true`, and the refusal names the destination and the payload: the shortcut text as an XML
  plist, POSTed over HTTPS to `hubsign.routinehub.services`. No files, no environment, no keys.
- **A human confirms the upload.** `consent=true` is the model's second factor, not the only one:
  a `pre_tool_call` hook escalates every consented signing call to Hermes's own approval gate,
  with a per-artifact `rule_key`, so an unattended run fails closed instead of uploading with
  nobody present.
- **Never sign a payload that carries a secret.** Signing posts the whole shortcut as an XML plist
  to RoutineHub, a third party that holds the Apple certificate. A shortcut that contains an API
  token, a password, a private URL or personal data is never signed: keep the secret out of the
  plist, or do not sign at all.
- **What you audited is what you install.** `talaria_sign` re-checks the stored artifact against
  its recorded sha256, re-runs the source filter, and after signing compares the action list
  decoded from the signed container with the one the user saw. A mismatch is refused, not shipped.
- **No shell exec.** Nothing in Talaria runs model-written shell.
- **Local state only.** Artifacts and metadata live under `$HERMES_HOME/talaria` (or
  `$TALARIA_HOME`), files mode `0600`. Nothing is written outside it.
- **Fail closed, never traceback.** Every tool returns JSON; a missing compiler or missing
  engine produces a message that says what is absent and what to do, not a stack trace.

What `build` and `sign` hand back: an unsigned `.shortcut` is a plain XML plist, which is why it
can be parsed with no decompression step. A signed `.shortcut` is an AEA1 container whose body is
compressed with LZFSE or LZVN — Apple's own formats, not ours. `talaria_inspect` decodes both in
pure Python, ported from Apple's reference decoder, so the plugin ships no compiled binary and
runs on any architecture.

## Limits

- **No agent runs on the phone.** Hermes compiles, signs and audits a `.shortcut` file. At run
  time the Shortcuts app executes it, within the actions it exposes and the permissions granted at
  import. Nothing of Talaria runs on iOS, so "Hermes calls your apps" always means "a shortcut you
  imported calls them, once you press play or a trigger fires".
- **The seal is verified by iOS, not by us.** `talaria_inspect` decodes the AEA1 header and the
  three-certificate chain, but `apple_issued` is a substring match on the issuer
  (`"apple" in issuer.lower()`), and `signature_verified` is hardcoded `false` in both
  `talaria/inspect.py` and `talaria/sign.py`: no ECDSA check over the body runs. A file that iOS
  would reject cannot be recognised here, only on a device.
- **The audit reads structure, not resolved values.** The signed body is decompressed and its
  action list is returned, so a signed shortcut stays auditable: the demo artifact decodes to 16
  actions, verdict `review`, one `medium` `SAVE_TO_FILES` finding on action 9. What the rules
  cannot do is resolve a URL or a path assembled at run time; those surface as
  `URL_OPEN_DYNAMIC`-class findings, never as values. The demo `meeting-note` also overwrites
  `talaria/notes.txt` on every run (`WFSaveFileOverwrite=true`), so it is a capability demo, not
  an accumulating log.
- **A signature is not reproducible, by construction.** Every signing call receives a fresh Apple
  leaf certificate, so the same source signs to different bytes: two runs minutes apart produced
  leaf `4ca80cea…` (issued 10:06:08Z) and leaf `76488dbc…` (issued 10:13:24Z), 23 491 and 23 486
  bytes, sha256 `ee192ced…` and `bb7e4e01…`. A sha256 identifies one artifact file, never a
  version of a shortcut; two signatures of the same source will always differ.
- **The seal carries a validity window.** The leaf is valid from its issue time and expires on
  2027-12-09 19:30:38 UTC (intermediate CA to 2032-02-18, root G3 to 2039-04-30). A device whose
  clock sits before the issue time, or after that expiry, refuses the import without saying why,
  so check the phone clock before blaming the file or the transfer path.

## Lineage and credit

Talaria is built on [`an earlier internal prototype`](an earlier internal prototype)
(MIT), by the earlier prototype's author. The original exposed three tools, one hardcoded alert template, and
produced unsigned sources only. Talaria keeps its product contract — source first, reviewable,
no shell exec — and replaces the rest: signed artifacts, a sandboxed compiler, an artifact
library, a decoder for signed containers, an audit pass, and an action corpus the model can
query. Original authorship is credited in `AUTHORS` and in the catalog entry.

It invokes [Cherri](https://github.com/electrikmilk/cherri), the Shortcuts compiler, as a
separate process pinned at v2.4.0 — no Cherri code is linked or redistributed here, and its
GPL-2.0 licence governs that binary, not this plugin.

## Licence

MIT. See `LICENSE` and `AUTHORS`.
