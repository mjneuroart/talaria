# Submitting Talaria to the Hermes plugin catalog

The catalog is a directory of YAML files in `NousResearch/hermes-agent`; an entry is admitted
only by a merged PR. This document is the fork/PR plan, with each admission rule quoted next
to how this plugin satisfies it.

## What goes where

```
plugin-catalog/talaria.yaml     <- repo/catalog-entry.yaml, sha replaced at release
```

Nothing else from this repository is copied into `hermes-agent`. CI clones and checks out the
pinned SHA itself.

## Steps

1. **Freeze the release.** In the plugin repository: confirm `plugin.yaml` says
   `version: "0.1.0"` and `requires_hermes: ">=0.23.1"`, then commit and tag `v0.1.0`.
2. **Pin the SHA.** `git rev-parse v0.1.0^{commit}` — a 40-character *commit* SHA, never the
   tag object, never a branch. Replace all 40 zeros in `catalog-entry.yaml`.
3. **Validate locally, on the pinned tree.**
   ```bash
   hermes plugins validate . --json     # exit 0, warnings []
   hermes plugins doctor . --ci         # exit 0, "6 tool(s), 1 hook(s)"
   ```
   Both are recorded in `build/lane-d/REPORT.md` with their real output.
4. **Check the payload scan by hand** (CI runs it, cheaper to pre-empt):
   `find . -name '*.pyc' -o -name '__pycache__'` must be empty in the committed tree;
   no ELF/Mach-O/PE/WASM file is committed. The Cherri compiler is *not* shipped: it is
   discovered on the host and reported by `talaria_status`.
5. **Fork `NousResearch/hermes-agent`**, add `plugin-catalog/talaria.yaml`, and run the local
   structural gate:
   ```bash
   python3 scripts/validate_plugin_catalog.py plugin-catalog/
   ```
6. **Open the PR** with `docs/PR-BODY.md` as the body. One entry, one commit, no other files.
7. **Expect `pinned-source-validate` to run** `hermes plugins validate --install-deps` against
   a fresh clone at the pin, with Hermes from *upstream main*. There are no Python
   dependencies, so `--install-deps` has nothing to resolve.
8. **After merge:** an update is a new PR that bumps `sha` and `version` together
   (rule 4). Users get it through `hermes plugins update talaria`.

## Rules, quoted, and how this entry satisfies them

**1. Human-merged gate.** "Entries are added *only* via a PR to the `hermes-agent` repository,
reviewed and merged by a maintainer." — This submission is that PR; no registry, no automation.

**2. Exact SHA pins.** "Every entry pins a full 40-character commit SHA. Branches, tags, and
short SHAs are rejected by the loader." — Step 2 pins `v0.1.0^{commit}`. The committed
placeholder is all zeros and is replaced before the PR is opened; a zero SHA is not a shipping
state.

**3. No self-updating code.** "A listed plugin must not fetch and replace its own files."
— There is no updater, no release downloader, no remote loader. `talaria_status` reads the
local compiler path only.

**4. SHA bumps are new PRs.** "Updating an entry's pin is a new PR whose diff (old SHA → new
SHA) is re-reviewed." — Step 8.

**5. Owner-or-major-contributor submissions.** "An entry may be submitted by the plugin
repository's owner or a major contributor." — Submitted by Mike-Jeason Leca, owner and sole
author of the release.

**6. Declared capabilities must match reality.** "The `capabilities:` block (tools, hooks,
middleware, env vars) must match what the plugin actually registers at the pinned commit."
— `validate` prints `declared tools: matches registrations` and `declared hooks: matches
registrations`; `doctor` prints `6 tool(s), 1 hook(s)`. `provides_hooks` declares the single
`pre_tool_call` hook that guards signing; `provides_middleware` and `requires_env` are empty
because nothing is registered there and no variable is read.

**7. The install scanner runs at admission.** "`dangerous` fails the entry; `caution` findings
appear as warnings." — `security scan: safe`, `warnings: []`.

**8. Desktop plugins stay inside the SDK surface.** — `desktop/plugin.js` registers a tool card
renderer and a library page, both through the plugin SDK only. `validate` reports `desktop
surface: stays inside the plugin SDK
surface`.

**9. No runtime overrides of Hermes core.** "A listed plugin extends Hermes only through
public surfaces." — No `sys.modules` writes, no monkeypatching, no private Hermes imports; the
package imports only the standard library plus its own modules. `no core override` check
passes.

**10. Dependency security policy is the plugin's.** "Reviewers read the dependency list at the
pinned SHA." — The dependency list is empty: standard library only, no `python_dependencies`,
no `pyproject.toml`, nothing to quarantine.

**11. Credentials come through Hermes, never from files.** — The plugin reads no credential:
no `os.environ` secret, no `.env`, no `auth.json`, no keychain. Signing is a third-party
service that takes no account and no key.

**12. Approvals and unattended runs are respected.** "Anything that waits for a person … fails
cleanly or times out under cron." — Nothing waits. Consent is an argument in the call; absent
or false, the tool returns a refusal JSON immediately. There is no prompt, no browser flow, no
auto-approve hook.

**13. Risky behaviour is disclosed.** "What a user would want to know before installing goes in
the PR description and the plugin's README: network calls to third-party services … shell
commands." — Disclosed in `README.md` ("Security model") and in the entry description:
subprocess use of `bwrap` and the catalog-installed Cherri binary, the two explicit egress paths to
`hubsign.routinehub.services`, and the local-only writes under `$HERMES_HOME/talaria`.

**14. Compatibility metadata is truthful.** "`requires_hermes` is a SemVer floor … never newer
than the current release. Declare the same floor in `plugin.yaml` as well." — `">=0.23.1"` in
both files. That floor is the release where every API this plugin uses was read in source
(`ctx.register_tool`, `ctx.register_skill`, `manifest_version: 2`) and where the plugin passed
`validate` and `doctor`. `version: "0.1.0"` matches `plugin.yaml`.

**15. No skins or forks of bundled plugins.** — Talaria is not a skin and does not fork a
bundled plugin; it targets a surface no bundled plugin covers.

**16. One listing per plugin lineage.** "A listed fork names its origin in its disclosure line
(`Derived from <entry>`)." — Talaria is not a fork: no code, fixture or bundled resource is
shared with any other plugin, so there is no origin to name and no duplicate lineage.

**17. No unscannable executable payloads.** "A plugin must not ship a compiled binary …,
committed Python bytecode (`.pyc`/`.pyo`), or an archive whose members are not themselves
reviewable source." — No binary, no bytecode, no archive. `.gitignore` excludes
`__pycache__/` and `*.py[cod]`; step 4 re-checks the committed tree. The Cherri compiler is a
host dependency the user installs, not a bundled payload.

**18. Password managers come from their vendor.** — Not applicable: no
`ctx.register_login_backend`.

## Reviewer-facing summary

- Shelf: `automation`. Tier: `community`.
- Surface: six tools + one bundled skill. One `pre_tool_call` hook (signing approval, keyed per artifact), no middleware, no commands, no env vars.
- Egress: two call sites, both inert by default (opt-in reachability probe with `probe_signer=true`, consent-gated upload), both named in the refusal text.
- Trust model: the SHA pin. Nothing self-updates.
