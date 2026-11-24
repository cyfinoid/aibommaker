# Detailed Changelog

The long-form companion to `CHANGELOG.md`. Where `CHANGELOG.md` says *what*
changed in one line, this file records *why* and *how* — enough for a future
reader to audit, reproduce, or roll back any change without re-deriving it.

Add a new entry (newest first) for every meaningful change. Use the template
below; drop sections that genuinely don't apply.

---

## 2026-11-24 — Fix CodeQL `js/incomplete-url-substring-sanitization` in `parseRepoInput`

**Summary:** CodeQL flagged two JS alerts; this entry covers the incomplete-URL-substring-sanitization finding in the repository-input parser. `js/github-api.js` matched `github.com/` as an unanchored substring of the raw input; now URL input is parsed with `new URL()` and the host is compared exactly, plus slug-charset validation on the extracted `owner`/`repo`.

**Why:** `parseRepoInput` is the app's entry point for untrusted input (the repo text field). The old regex `/github\.com\/([^\/]+)\/([^\/]+)/` matched the hostname anywhere — `https://evil.example/github.com/owner/repo`, `https://github.com.evil.example/owner/repo`, and `https://evil.example/?x=github.com/owner/repo` all parsed as GitHub repos. The extracted slugs are interpolated into `${GITHUB_API_BASE}/repos/${owner}/${repo}` API calls, `href` evidence links in the findings UI, and every generated BOM, so an attacker-crafted input string (e.g. pasted from a malicious page) could steer those outputs. Practical impact here is bounded (the API base is a constant, so no token exfiltration), but the check class is exactly the one CodeQL's `js/incomplete-url-substring-sanitization` query exists for, and the same bug class was already fixed once (`f1ae8b6`, 2025-11-14) in `detectEcosystemFromSPDX` (`pkgName.includes('github.com/')` → anchored regex) — this was the second occurrence nobody revisited.

**What changed:**
- `js/github-api.js`: `parseRepoInput` rewritten.
  - Bare-host paste forms that the old matcher happened to accept (`github.com/owner/repo`, `www.github.com/owner/repo`) are normalized by pinning the scheme; a single-slash scheme typo (`https:/github.com/…`) is repaired — both keep working through the URL path below.
  - URL-shaped input (`://`, protocol-relative `//`, `git@`) is normalized (`git@host:o/r` → `ssh://git@host/o/r`, `//host/o/r` → `https://host/o/r`), parsed with `new URL()`, and rejected unless `url.hostname` is exactly `github.com` or `www.github.com` (case-insensitive — `URL` lowercases the host). `owner`/`repo` come from the first two path segments (percent-encoded segments survive only if they fit the slug charset — `%` is rejected; dot segments resolve inside `new URL`, so `..` traversal cannot survive); `.git` suffix stripped.
  - Shorthand `owner/repo` (and `owner/repo/tree/main`) still accepted, now through the same validation.
  - New charset validation shared by all forms: owners `^[A-Za-z0-9][A-Za-z0-9-]*$`, repos `^[A-Za-z0-9._-]+$` (`.github` repo names still accepted), `.`/`..` rejected. Anything else throws the existing `Invalid repository format…` error; non-GitHub hosts throw `Only github.com repository URLs are supported.`
  - Behavior deltas (intentional): substring bypasses now fail fast; `git@github.com:o/r` and `//github.com/o/r` now parse (they previously produced garbage like `owner="git@github.com:owner"`); `https://gitlab.com/o/r` now errors clearly instead of silently scanning `gitlab.com/o` as if it were a GitHub owner.
- `tests.html`: new "parseRepoInput — host-validated GitHub URL parsing" section — 26 assertions: accepted forms (shorthand, https/www/scp/ssh/protocol-relative, extra path segments, query/fragment, case handling, whitespace, `.git` strip) and rejected forms (all three substring bypasses, attacker scp host, non-GitHub host, repo-less URL, whitespace/metacharacter slugs, empty, single segment).
- `scripts/tests/run-tests-html.js`: inject `URL` into the vm context (vm contexts don't inherit Node globals; `parseRepoInput` needs `new URL`).

**Commands / verification:**
- `node scripts/tests/run-tests-html.js` → `SUMMARY: 272 passed, 1 failed`; the 1 failure ("live line still captured") is pre-existing on the working tree (verified by stashing this change: `230 passed, 1 failed` before, same failure) and belongs to the in-progress `extractModelNameVersionInfo` work.
- `node scripts/tests/verify-e2e.js` → E2E PASSED. `node scripts/tests/verify-compliance.js` → ALL VERIFICATIONS PASSED.
- Direct edge-case matrix run in `node` (accepted/rejected table) — all 17 cases behave as specified, including `.github` repo names and all three bypass inputs.

**Notes:** The second CodeQL alert (`js/incomplete-multi-character-sanitization`) had no matching site in the current JS (verified against the query's trigger conditions: empty-replacement `replace()` calls whose regex can match `<!--`/`<script`/`<style`/`<iframe`/`../`/`on[a-z]+`-style prefixes). The only matching code in the workspace is a stale pre-fix snapshot under `projects/logme_files/` (untracked sample artifact; the same `includes('github.com/')` line fixed here in `f1ae8b6`). Root cause for "why we missed": (1) this repo has no CodeQL workflow for JavaScript — `.github/workflows/` only has Pages deploy + SBOM, so JS alerts only surface on ad-hoc scans; (2) the `f1ae8b6` URL-detection fix covered the SPDX ecosystem detector but not `parseRepoInput` — same pattern, second location; (3) no adversarial-URL test existed in `tests.html` (all fixtures were well-formed).

---

## 2026-11-21 (night) — Requirements gap-closing pass

**Summary:** Full audit of all remaining CERT-In/G7/OWASP gaps; implemented every non-structural fix: system producer/manufacturer, system version (package.json/pyproject.toml), system timestamp (repo last-push), SBOM version property, system application areas, security-controls property, model timestamps (release-date/last-modified), tokenizer identity (tokenizer_config.json), model licensing from bundled cards, dataset components (R5-lite: `type: data` + `ai_Dataset` + repo dependency edges), and the R6 vulnerability-posture honesty note. Scorecard: CERT-In 89.5/84.2, G7 69.0/64.0, OWASP 70.8/50.0 (§6 snapshot was 65.8/45.0/50.0 weighted).

**Remaining unmet rows are all structural (⛔)** — CVE/VEX feeds, SBOM signing, training-time observation, G7 KPIs, dataset hash/provenance/stats/sensitivity, flow typing, validity period. Remaining 🟡 partials are honest depth limits. Optional future: HF datasets API for dataset license/description (G7 #42/#34).

---

## 2026-11-21 (night) — HuggingFace models now always get a model card

**Summary:** User scanned a repo, HF models were detected but produced no model card. Root cause was three compounding gaps in the enrichment pipeline; fixed by broadening the HF API gate and synthesizing a structured card from verified API details when no card YAML parses. Follow-up in the same entry: compared `guidance/sample/Sweaterdog_Andy-3.6_aibom_1_7.json` (OWASP-AIBOM-Generator output for the same model our scan under-served) and adopted its best ideas — commit-pinned versions, proper 1.7 attribution, dataset hub URLs, richer HF references.

**Why:** (1) `shouldCheckHuggingFace` gated the API on `providersUsed.has('HuggingFace')` — HF models referenced by plain name (no HF-specific library import) never triggered a fetch. (2) When fetched, `modelCardData` was only set if the remote README YAML parsed non-empty (`parseModelCardYAML`). (3) The bundled-card fallback has no `modelcards/huggingface/` entries, so the local lookup 404s for every HF model. Net: HF models got at most a task/IO fragment in the BOM, and the UI panel showed no card at all.

**What changed:**
- `js/utils.js`: `extractModelNameVersionInfo(modelName)` — parses version/quantization/parameter-size declared in model identifiers (`meta-llama-v3-q4` → version 3 + q4; `llama-3.1-70b-instruct` → 3.1 + 70b; `qwen2.5-coder` → 2.5); conservative (bare attached integers like `qwen3` are not versions; `gpt-4o`/`yargs/helpers` → null). BOM generators emit it as `component.version` (`aibom:model:version-status: declared-in-identifier` — lowest precedence after card version and HF commit sha), `aibom:model:quantization` and `aibom:model:parameter-size` properties.
- `js/utils.js`: `buildModelCardDataFromHuggingFace(hfDetails, modelName)` — synthesizes a structured card from verified API details only: `modelType` (pipeline_tag), `capabilities` (tags with `license:`/`dataset:`/`arxiv:`/… metadata prefixes filtered), `architecture` (config architectures + context window), `access.license`, `origin: 'open-source-hub'`, `description` (card model_summary when present), `references.modelPage`. No intended-use/limitations fabrication. Returns null for unverified details. Also `buildDatasetEnrichmentFromHuggingFace` — datasets-API payload → license/description/last-modified/downloads (license-if-public tier).
- `js/github-api.js`: HF API result now carries `sha` + `lastModified`; new `fetchHuggingFaceDatasetInfo` (datasets API — license/description/last-modified/downloads via the pure `buildDatasetEnrichmentFromHuggingFace` mapper in `js/utils.js`).
- `js/detectors.js`: dataPipelineDetector enriches HF-sourced dataset names via the datasets API (capped 25, `hf` enrichment on `dataPipelineInfo.datasets`); gate broadened (`hasHuggingFaceModels` when any detected model is HF-sourced); synthesis applied when YAML parsing produced no card — single point so the UI panel, CycloneDX modelCard, and SPDX all benefit.
- `js/bom-generators.js`: `aibom:model-card-source` distinguishes `HuggingFace API — <model url>` from bundled card files; `aibom:origin` property emitted when a card carries origin classification; dataset components now carry API license (`licenses`), `description`, `aibom:dataset:last-modified`/`downloads` properties, and SPDX `ai_Dataset` elements get `licenseConcluded`.
- `js/ui.js`: `renderFindings` falls back to `fetchHuggingFaceModelInfo` + synthesis when a HuggingFace finding has no card after the bundled lookup (per-render cache) — covers scan-time fetch failures like rate limits or gated models; broadened to any HF-slug id (`org/repo`) regardless of provider attribution (DeepSeek-signature models with HF-slug names were skipped by the provider gate).
- `js/github-api.js`: HF API result now carries `sha` + `lastModified`.
- **OWASP-sample comparison uplift** (`guidance/sample/Sweaterdog_Andy-3.6_aibom_1_7.json`): HF models commit-pinned (`component.version` + purl `@sha` from the API `sha` field — immutable revision, closes CERT-In #2 and G7 #22), 1.7 attribution (`supplier`/`manufacturer`/`authors` = HF org; the platform name was wrong as `author`), training datasets as `modelParameters.datasets` with `contents.url` hub links, `distribution` (tree/main) + commit-specific `vcs` external references. Scorecard: CERT-In #2 and G7 #22 → met → CERT-In 78.9% weighted / 63.2% strict, G7 52.0% / 42.0%.
- `tests.html`: 13 new assertions (synthesis: tag filtering, architecture, license, provenance, no-fabrication, unverified→null).
- `scripts/tests/verify-e2e.js`: third fixture model (HF `bert-base-uncased` with API-synthesized card + commit sha + datasets); asserts commit-pinned version/purl, supplier/manufacturer/author, dataset hub URLs, commit/distribution references, provenance/origin/context-length properties, task from pipeline_tag, no speculative HF service; NTIA supplier tally updated (3/6).
- `README.md`, `CHANGELOG.md`, this file.

**How / commands run:**
```
node --check js/{utils,detectors,bom-generators}.js
node scripts/tests/verify-compliance.js   # PASS
node scripts/tests/verify-e2e.js          # PASS (HF synthesis + card assertions)
node scripts/tests/run-tests-html.js      # 215 passed / 1 pre-existing failure
aidc-scan                                 # clean
```

**Verification notes:**
- e2e validated behavior: HF model card present with `task: fill-mask` (pipeline_tag), origin + provenance properties, HF purl, license — and no speculative HuggingFace inference service (HF not in `AI_SERVICE_ENDPOINTS` since hub models are frequently run locally).
- NTIA supplier tally updated for the new fixture (3/6: 3 attributed models, libraries/frameworks unattributed).
- The user-reported scan predates this fix; re-scanning will now produce cards for HF models whose API data is reachable (404/rate-limited models stay card-less, honestly).

---

## 2026-11-21 (evening) — R1/R3/R4 implemented + BOM download UX

**Summary:** Revisited the three 2026-11-20-deferred recommendations and implemented all three, plus reworked the Generated AI BOM section for quick downloads (per-format Download-first buttons, collapsed JSON views, Download-all).

**Why:** User asked what the "R3 deferred" markers mean, then approved revisiting R1/R3/R4. R3 was the cheapest (metadata-only); R1 closes the biggest ❌ cluster (hashes — Git-LFS pointers are plain text readable via the existing Contents API); R4 records attestation presence honestly. The BOM section's always-expanded JSON walls were useless at a glance — downloads should be primary, content on demand.

**What changed:**
- `js/detectors.js`:
  - `modelsDetector` (+R1): model-file entries ≤512 bytes are fetched and parsed as Git-LFS pointers (`oid sha256:<64-hex>`, `size`); one machine-readable finding per hashed artifact with `artifactInfo {path, sha256, sizeBytes, source: 'git-lfs-pointer'}`; capped at 50 fetches
  - `attestationDetector` (+R4, new): filename patterns (`.sigstore`, `.sig`, `.att`, `.link`, `verification.key`, `SLSA_PROVENANCE*`, `provenance.json`) + capped content check of `.github/workflows/*.yml` for slsa/provenance/sigstore/gitsign/in-toto; single governance finding with `attestationInfo` when evidence exists
- `js/analyzer.js`: Attestations detector wired (needs tree + getFileContent); result carries `repository.scannedRef`
- `js/bom-generators.js`:
  - R1: `findArtifactForModel` (name-token ≥4 chars, best-score match; no match → no hash claim) attaches CycloneDX `hashes: [{alg: 'SHA-256', …}]` + `aibom:artifact:path` / `aibom:hash-source`; SPDX `checksum` + artifact comment; XML `<hashes>` in XSD position
  - R3: JSON `metadata.lifecycles: [{phase: 'post-build'}]` + five `aibom:*` metadata properties (scope with scanned ref, completeness, generation-context, authorship, graph-type); XML metadata `<lifecycles>` + properties in XSD order; SPDX document `comment`; extended AIBOM `source_scope`
  - R4: `getAttestationState` → `aibom:attestation` metadata property (JSON/XML) + SPDX repository element `comment`; detected types or explicit "none found in repository scan"
  - guards: `artifactInfo`/`attestationInfo` findings are state metadata — skipped in the CDX generic-component branch and SPDX package branch (they must not become components)
  - XML generator: metadata `<lifecycles>` + header properties in XSD order; `<hashes>` emission; guarded optional `<version>`/`<author>`
- `js/ui.js` + `index.html` + `styles.css`: per-tab Download-first actions, **Show content** toggle (`bom-preview.collapsed` default), **Download all** staggered batch; Analysis Notes section moved below Standards Compliance and reformatted as a compact gap table (Missing / What we searched / What it would add) with category chips, icons, count-in-heading and a clearer "gaps, not errors" caption; Analysis Results section collapsed by default with a single-click Expand/Collapse toggle (replaces click-for-items + double-click-for-section)
- Later (same session): user-requested default — **Analysis Results collapsed on load**
- `js/compliance.js`: scorecard rows for R1/R3/R4 flipped with dated notes; header headline updated
- scorecard notes later cleaned to factual where/why statements only (no dates/change commentary — user request); movement history stays in this changelog
- `tests.html`: 15 new assertions (artifact-to-model matching incl. generic-token/no-overlap cases, attestation state derivation, LFS pointer parsing end-to-end with stubbed fetch); scorecard expectations updated
- `scripts/tests/verify-e2e.js`: fixture gains an LFS artifact + sigstore finding; asserts hashes/checksum, header properties/lifecycles, attestation states, XML parity (lifecycles, services, hashes, no `undefined` version, single assembly)
- `README.md`, `CHANGELOG.md`, this file

**How / commands run:**
```
node --check js/{constants,detectors,analyzer,bom-generators,ui,compliance}.js && node --check scripts/tests/*.js
node scripts/tests/verify-compliance.js   # scorecard: PASS (73.7/50.0/68.8 weighted)
node scripts/tests/verify-e2e.js          # real generators: PASS (incl. R1/R3/R4 + XML parity assertions)
node scripts/tests/run-tests-html.js      # 202 passed / 1 pre-existing failure
aidc-scan                                 # clean after fixing 3 semgrep findings in the harnesses
```

**Verification notes:**
- e2e caught: stale `tasks: []` initializer, service refs unresolved in the validator, NTIA supplier tally drift (2/4 after new fixtures), G7 expected 26/50 vs actual 25/50 (recounted — tests corrected, not the rows), attestation finding leaking into the component list (guard added), and the download-all placeholder filter excluding the real XML (`startsWith('<')` matched `<?xml` — replaced with explicit `//`/`<!--` placeholder markers).
- Fresh-eyes review (round 3) findings, all fixed: hash matching required filename-hit-weighted score ≥2 with generic path tokens (`models`, `weights`, `checkpoints`…) excluded — a bare directory-token match can no longer attach another file's sha256 to a model; one-to-one greedy assignment so two similar models never share one hash claim; short ids (`gpt-4o`) match via 3-char tokens; artifact/attestation findings downgraded to `severity: low` (positive integrity facts, not risks); dead `attestationState` return removed; `aibom:attestation` now derives from ALL scan findings — deselecting the attestation finding can no longer flip the recorded state to a false "none found"; LFS candidates restricted to weight-artifact extensions (tokenizer/config JSONs excluded); stale tests.html comment corrected.
- Hash matching is deliberately conservative: unmatched artifacts stay hash-less (no invented integrity).
- R4 absence is explicit: "none found in repository scan" — never a silent clean bill (R6 principle).
- Scorecard movement all traceable: CERT-In 68.4→73.7 (+#19), G7 44.0→50.0 (+#8/#26/#27), OWASP 50.0→68.8 (+#1–3/#18, #19 partial).
- Semgrep `path-join-resolve-traversal` / `insecure-object-assign` findings on the committed harnesses fixed via literal whitelists + direct property assignment.
- Pre-existing tests.html failure still flagged (bare live-line constant capture).

**Files:** `js/detectors.js`, `js/analyzer.js`, `js/bom-generators.js`, `js/ui.js`, `js/compliance.js`, `index.html`, `styles.css`, `tests.html`, `scripts/tests/*.js`, `README.md`, `CHANGELOG.md`, `DETAILED_CHANGELOG.md`.

---


## 2026-11-21 (later) — Snyk-comparison uplift: identity/evidence/services + compliance section + PR #2 port

**Summary:** Compared our chatAssistant AIBOMs against Snyk's (`projects/snyk/glm-comparision.md`, independent of ChatGPT's `compare.md`), extracted the highest-value defects, and fixed them in the generators; moved the Standards Compliance panel to its own section; reviewed and ported cyfinoid/aibommaker PR #2 (Go/Java/Rust MCP SDK detection — our `js/constants.js` had the identical gap).

**Why:** Snyk comparison showed complementary recall (we 2/2 models but 3/5 libraries; Snyk 1/2 models but 4/5 — they detect undeclared imports, we missed `langchain-community`/`langchain-core`), a structured-identity defect (`"Dependency: langchain"` + `version: "detected"` with the real version only in prose), invented model versions (`latest`), and — verified field-by-field against `bom-1.7.schema.json` — ten emitted `modelCard` fields that violate `additionalProperties: false`. Snyk's strengths (native evidence structures, honest unknowns) and our strengths (model recall, card enrichment, identifier fidelity) were combined.

**What changed:**
- `js/bom-generators.js`:
  - `resolveLibraryIdentity` / `buildLibraryPurl` / `buildNativeEvidence` helpers; library components use clean name/version/purl (pypi/npm-with-%40-encoding/maven group:artifact/golang layouts), version omitted when unknown; model components drop invented `latest` (added `aibom:model:version-status` property; version only from real card data)
  - modelCard remapped to CycloneDX 1.7-valid fields: `modelParameters.task` (singular string), `considerations.useCases[]`, `considerations.technicalLimitations[]`, `considerations.ethicalConsiderations[]` risk objects; non-schema data → `modelCard.properties` as `aibom:capability`, `aibom:training-data`, `aibom:context-length`, `aibom:model-type`, `aibom:base-model`, `aibom:out-of-scope-use`, `aibom:lifecycle-status`, `aibom:model-card-source`, `aibom:additional-task`
  - native `evidence` on model + library components (identity technique manifest-analysis/source-code-analysis with confidence by provenance/severity; occurrences with `additionalContext` snippets); `structuredCardList` helper
  - CycloneDX `services`: `AI_SERVICE_ENDPOINTS`-matched providers emit external inference services (endpoint, provider, authenticated) + graph edges repo→service and model→service
  - SPDX: clean library names/versions, `packageVersion` omitted when unknown, purls as `externalIdentifier`, detection evidence as package `comment`, no invented AI package versions
  - CycloneDX XML generator: emits `services` (parity with JSON), guarded optional `version`, and now assembles once so dependency refs match the component list (previously it ran the assembly twice with different random bom-refs)
- `js/constants.js`: `AI_SERVICE_ENDPOINTS` (6 providers, public endpoints — HuggingFace deliberately excluded: local `transformers` use would make the "external API consumed" claim speculative); `AI_IMPORT_MODULE_MAP` (python + npm module→package); PR #2 port — `mcp_protocol` packages go/java/rust, Go code patterns (signature + protocol patterns), `generateExtendedDependencies` go/java wiring
- `js/detectors.js`: new `aiImportsDetector` (source-import analysis; scans aiFilesFound + tree source files capped at 120; dedupes against declared deps; skips comment lines and repo-local `langchain_*` modules; `source-import-analysis` provenance)
- `js/analyzer.js`: AI Imports detector wired after Code (needsAIFiles + needsAllFindings)
- `index.html`: compliance tab → standalone `#compliance-section` with collapse control
- `js/ui.js`: `renderComplianceSection()` + section show/hide (incl. hidden on re-scan) + collapse wiring
- `js/compliance.js`: scorecard rows updated honestly (CERT-In #2 → unmet, #16 → met; G7 #22 → unmet, #16 note); validator resolves service refs in dependency graph check
- `tests.html`: async-aware harness tail; bom-generators.js loaded; 27 new assertions (identity/purl layouts, npm %40 encoding, evidence techniques/confidences, import detector incl. the chatAssistant langchain-community/core scenario, scorecard post-uplift numbers)
- `scripts/tests/` (new): committed Node verification harnesses — `verify-compliance.js`, `verify-e2e.js` (real generators end-to-end), `run-tests-html.js` (headless tests.html runner) — reproducible without a browser
- `README.md`, `CHANGELOG.md`, `projects/snyk/glm-comparision.md` (new), this file

**How / commands run:**
```
node --check js/{constants,detectors,analyzer,bom-generators,ui,compliance}.js   # syntax OK
node scripts/tests/verify-compliance.js      # scorecard/validators: PASS (68.4/44.0/50.0 weighted)
node scripts/tests/verify-e2e.js             # 60 assertions on REAL generator output: PASS
node scripts/tests/run-tests-html.js         # tests.html headless: 187 passed / 1 pre-existing failure
curl -sL https://github.com/cyfinoid/aibommaker/pull/2.diff   # exact PR patch reviewed
curl -sL https://cyclonedx.org/schema/bom-1.7.schema.json     # schema used for field-level verification
```

**Verification notes:**
- e2e asserts against the real `generateCycloneDXJson`/`generateSPDX` with a finding set mirroring the chatAssistant scan (incl. an import finding): clean identities, no `Dependency:` names, no placeholder/invented versions, schema-valid modelCard (no `tasks`/`modelType`/`contextLength`/`baseModel` keys, `task` singular), services + unique dependency refs, SPDX comments/purls, NTIA honesty (version MISSING when unpinned; supplier 2/4 warn).
- Scorecard deltas documented: CERT-In 65.8→68.4 (version row unmet −0.5, out-of-scope row met +1.0; strict 47.4→52.6), G7 45.0→44.0 weighted (version row unmet). `guidance_details.md` §6 left untouched as the dated 2026-11-20 snapshot.
- PR #2 review verdict: applies cleanly to this repo (same gap in `AI_SIGNATURES.mcp_protocol`, same `generateExtendedDependencies`/protocol-pattern structure); ported with identical package lists (taken verbatim from the PR, not from memory); `rust` already had `mcp_protocol` wired in our tree, `go`/`java` did not; added `a2a_protocols?.go` spread per the PR (our a2a registry has no go packages yet — the spread is future-proof, not dead-verifiable).
- Fresh-eyes review findings, all fixed: HF `considerations.limitations` block re-read the same structured card object and emitted `["[object Object]"]` over the parsed `technicalLimitations` (string/number-array merge with Set dedupe now); HF `useCaseTags` overwrote card-derived `useCases` (merged with Set dedupe); npm scoped purls used `%2F` (now spec form `pkg:npm/%40langchain/community`); aiImportsDetector now also scans tree source files (capped 120) — smart-mode aiFilesFound only targets declared dependencies, which would have skipped undeclared-only files; out-of-scope extraction no longer mislabels flat-string intended uses; CERT-In #16 updated to met (out-of-scope extraction implemented this diff — scorecard/68.4% headline now matches code); duplicate `aibom:model-type` properties deduped (card wins over HF `transformer` default); empty `modelParameters: {}` dropped; XML generator emits services + guarded version + single assembly (its old double-assembly produced dependency refs pointing at different random bom-refs than the component list — pre-existing bug found and fixed); comment-line and repo-local `langchain_*` guards in the import detector; compliance section hidden on re-scan; constants formatting glitches; purl versions percent-encoded; "40+ assertions" corrected to 27; duplicate CHANGELOG compliance bullets merged; verification harnesses committed under `scripts/tests/`.
- HuggingFace removed from `AI_SERVICE_ENDPOINTS`: HF-hosted models are often run locally via `transformers`; emitting an "external API consumed by this application" service would have been speculative.
- Pre-existing tests.html failure still flagged: `extractContextualModelRefs` bare live-line constant case.

**Files:** `js/bom-generators.js`, `js/constants.js`, `js/detectors.js`, `js/analyzer.js`, `js/ui.js`, `js/compliance.js`, `index.html`, `tests.html`, `scripts/tests/{verify-compliance,verify-e2e,run-tests-html}.js` (new), `projects/snyk/glm-comparision.md` (new), `README.md`, `CHANGELOG.md`, `DETAILED_CHANGELOG.md`, `logs/2026-11-21-snyk-comparison-uplift.md`.

---


## 2026-11-21 — Fix `[object Object]` in model card display + add Standards Compliance tab

**Summary:** Two user-reported items from a KhanFaheed/chatAssistant scan: (1) the Model Card Information panel rendered `[object Object]` for Intended Use / Limitations, and (2) the previously produced standards-compliance scorecard (guidance §6) was not visible anywhere in the UI. Fixed the stringification bug via a shared `formatModelCardField` helper, and added a "Standards Compliance" tab to the BOM section backed by a new pure-logic module `js/compliance.js`.

**Why:** Local model card JSONs store `intendedUse`/`limitations` as structured objects (`{primaryUses, outOfScope}` / `{knownLimitations}` — see `modelcards/google/models-embedding-001.json`), but `js/ui.js:281-282` and `js/bom-generators.js:494/499` used the pattern `field.note || field`, assuming a flat string with an optional `note`. No card carries `note`, so the raw object fell through and stringified as `[object Object]`. The compliance scorecard from the 2026-11-20 guidance work existed only as Markdown.

**What changed:**
- `js/utils.js`: `formatModelCardField(value, labels)` — renders strings, arrays, `{note}`, `{primaryUses, outOfScope}`, `{knownLimitations}`, `{description}` shapes as human-readable text; labeled sub-objects (e.g. `Out of scope: …`) supported; empty string when nothing readable.
- `js/ui.js`: Model Card Information panel uses the helper for intendedUse/limitations/trainingData (escaped at the HTML sink, empty render suppressed); new `renderComplianceTab()` + report/scorecard HTML builders (native `<details>` sections, status pills), called from both `regenerateBOMs()` branches; the no-findings branch now writes placeholders into `generatedBOMs` so the compliance tab (and copy/download) can never validate stale documents from a previous selection.
- `js/bom-generators.js`: modelCard extension (`intendedUse`, `limitations`, `trainingData`) now embeds formatted strings instead of raw objects.
- `js/compliance.js` (new): pure validators `validateCycloneDXBom` (10 checks), `validateSpdxBom` (10 checks), `checkNtiaMinimumElements` (8 checks), `parseBomJson` defensive parse; static `AIBOM_SCORECARD` (CERT-In 19 + G7 50 + OWASP 24 rows transcribed from `guidance/guidance_details.md` §6.1–§6.3 with structural ⛔ markers) and `computeScorecardStats` (weighted ✅1.0/🟡0.5/❌0 + strict ✅-only; reproduces the documented headline 65.8/47.4, 45.0/34.0, 50.0/29.2). Node `module.exports` guard for test tooling.
- `index.html`: new tab button + `#compliance` tab content; `compliance.js` script include; cache-bust `?v=0.0.4-4` on scripts **and** `styles.css`.
- `styles.css`: `.compliance-*` report/table/cluster/headline styles, `.status-pill.pass|warn|fail` with light-theme variants.
- `tests.html`: `compliance.js` loaded; 38 new assertions (formatter regression incl. the embedding-001 shapes, validator pass/fail matrices, scorecard-vs-guidance headline equality).
- `README.md`: "Standards Compliance (report tab)" section under Output Formats. `CHANGELOG.md` + this file updated.

**How / commands run:**
```
sudo apt-get update && sudo apt-get install -y --no-install-recommends nodejs  # node v22.22.1 (none in container)
node --check js/{compliance,utils,ui,bom-generators}.js                        # syntax OK
# pure-function verification: 60 assertions over formatModelCardField,
# validateCycloneDXBom/checkNtiaMinimumElements/validateSpdxBom, scorecard math,
# buildComplianceReports  -> ALL VERIFICATIONS PASSED
# end-to-end: real generators loaded in a vm sandbox (fetch shimmed to modelcards/
# on disk, crypto.webcrypto provided), findings mirroring the chatAssistant scan
# (Google models/embedding-001 @ prepare_vectordb.py:52 + langchain dep):
#   generateCycloneDXJson + generateSPDX executed; modelCard.intendedUse in the
#   emitted BOM is readable text; both real documents pass all validator checks.
# tests.html harness executed headlessly (vm + DOM stubs): 159 passed / 1 failed;
#   the failure ("live line still captured") is pre-existing — reproduced on the
#   stashed original tree (121 passed / 1 failed there).
```

**Verification notes:**
- Scorecard math computed from transcribed rows equals the documented headline percentages exactly (single source of truth; guards future transcription drift).
- NTIA supplier check counts `supplier|author|publisher|group` — the real generated doc attributes models via CycloneDX `author`, which an earlier draft missed (showed 0/2); e2e run caught it.
- Fresh-eyes review findings, all fixed: `styles.css` cache-bust was missed (styles changed, scripts bumped); the no-findings branch validated stale `generatedBOMs` from a previous selection (placeholders now written before `renderComplianceTab`); formatted model-card text now escaped at the HTML sinks; `trainingData` routed through `formatModelCardField` in bom-generators too; NTIA identifier detail no longer conflates missing refs with duplicates; README honesty sentence corrected (partial attribution reports PARTIAL with tally, not MISSING); changelog check/assertion counts corrected (10 SPDX checks, 38 assertions); dead `.compliance-cluster-cont` class removed, `.compliance-headline` styled.
- Pre-existing failure flagged, not fixed (out of scope): `extractContextualModelRefs` does not capture bare string-constant live lines (`const y = "gemini-2.5-pro";`) — fails identically at git HEAD; needs a deliberate detector decision (bare constants risk false positives), tracked here for a follow-up.

**Files:** `js/utils.js`, `js/ui.js`, `js/bom-generators.js`, `js/compliance.js` (new), `index.html`, `styles.css`, `tests.html`, `README.md`, `CHANGELOG.md`, `DETAILED_CHANGELOG.md`.

---

## 2026-11-20 — Implement detection gap fixes from reference-project sync

**Summary:** Implemented the highest-priority gaps from `mdfiles/GAP_ANALYSIS.md` in pure HTML/JS/CSS: 27 new provider/agent/guardrail/observability signatures, generic model-kwargs/env-default extraction, Bedrock ARN + Ollama tag normalization, go/Java/Rust manifest fallback parsing, notebook support, A2A agent cards + Semantic Kernel activation, digest-pinned-image provenance, OWASP LLM Top-10 exposure assessment, and a tree-truncation warning. Shipped with `tests.html` (browser test suite). User removed the duplicate `owasp-aibom-generator` checkout and re-synced `xbom` (now at `2b092b7`) before implementation.

**Why:** The freshly synced reference projects (cisco `aibom` v1.10.1, `aibom-akumar0205`, `aibom-generator`) exposed detection scenarios our analyzer did not cater for (see `mdfiles/GAP_ANALYSIS.md`). User approved implementation.

**What changed:**
- `js/constants.js` (+710 lines): new `llm_providers` signatures (cohere/mistral/groq/xai/together/perplexity/fireworks/replicate/ai21/stability/alephalpha/azure.openai/bedrock.client/vertexai.client/openrouter.gateway/litellm.router — package names verified against in-repo `projects/ai-spotter/ai_detector/services.yaml` and cisco `KNOWN_AI_PACKAGES`); 11 new `ai_agents` signatures (langgraph/google.adk/openai.agents/pydanticai/smolagents/strands/deepagents/haystack/dspy/instructor/semantic-kernel) + AutoGen variants; new `guardrails` and `llm_observability` categories wired into `generatePackageRegistry` + `generateExtendedDependencies`; A2A `.well-known/agent.json` config file; `MODEL_FILE_PATTERNS` extensions (.ggml/.ckpt/.h5/.pb/.tflite/.msgpack/.onnx, risky ones pathMatch-guarded); SKILL.md dev-tool config; newer OpenAI/Anthropic/Google model patterns; digest-pinning + k8s model-env infrastructure patterns.
- `js/utils.js` (+264): `isPlausibleModelId` (deployment-literal/FP rejection, incl. akumar `misleading_config` baits), `normalizeBedrockModelId` (prefix/suffix/date stripping per cisco alias logic), `stripNotebookCells` (ipynb → source), `extractContextualModelRefs` (kwargs, module constants, env defaults with ctor-based provider attribution + ReDoS guard), `inferProviderFromLine`/`inferProviderFromName` helpers.
- `js/detectors.js` (+642): `detectEcosystem` + dispatch for go/rust/java; `findInGoMod`/`findInCargoToml`/`findInPomXml`/`findInGradle`; `.ipynb` in code fallback (strip + python-language mapping) and models detector; new literal model patterns (o1-pro/o3/o4-mini/gpt-4.1/4.5/5, bare Anthropic aliases with negative lookahead, gemini-2.5, llama4, qwen3, grok, nova/titan, Bedrock extract patterns); `extract-bedrock` normalization branch; contextual-extraction pass and Ollama-tag pass merged into the `modelsFound` map; `detectProvidersInUse` extended (Ollama/Groq/Bedrock/Vertex); configDetector framework configs; protocolDetector agent-card parsing (name/url/skills/capabilities) + SK config files + semantic-kernel code patterns (previously dead); smart-mode search queries for Ollama/Bedrock/agent frameworks; infra orchestration gate widened for digest/env platforms.
- `js/github-api.js`: `lastTreeFetchTruncated` + `wasLastTreeTruncated()`; `data.truncated` checked and logged.
- `js/analyzer.js`: result now carries `warnings[]` populated from truncation flag.
- `js/ui.js`: `renderAnalysisNotes` renders warnings section; empty-state no longer overwrites warnings.
- `js/extended-aibom-generator.js`: `assessOWASPLLMTop10(findings)` — deterministic OWASP LLM Top 10 (2025) exposure mapping (LLM01/02/03/04/06/08 surfaces + guardrail mitigation indicator), wired into `risk_assessment.owasp_llm_top10`.
- `index.html`: script cache-bust `?v=0.0.4-3`.
- `tests.html` (new): self-contained browser test suite asserting all new helpers/parsers/patterns/OWASP derivation with fixtures from the reference projects' adversarial cases.
- `README.md`: "What It Detects" updated. `CHANGELOG.md`/`DETAILED_CHANGELOG.md` updated. `projects/STATUS.md` + `mdfiles/GAP_ANALYSIS.md` marked as implemented.

**How / commands run:**
```
# syntax verification (no JS runtime in container; esprima is ES2017-era)
uv venv /tmp/opencode/jscheck && VIRTUAL_ENV=/tmp/opencode/jscheck uv pip install esprima
# parse all 8 JS files with ES2020->ES2017 token substitution; failures investigated:
#   - ui.js:444 + detectors.js `catch {` -> pre-existing ES2019 constructs, fail identically at git HEAD
#   - after substituting those two pre-existing constructs in-memory: ALL 8 FILES PARSE OK
# behavioral verification of every new pure function: executed via Code Mode JS runtime
#   - isPlausibleModelId / normalizeBedrockModelId / stripNotebookCells: 30+ assertions
#   - extractContextualModelRefs: 20+ assertions vs akumar adversarial fixtures
#     (fixed ternary env-default pattern `[^:]+:` during testing)
#   - manifest parsers: fixed Cargo simple-version form during testing (`= "0.27"`)
#   - assessOWASPLLMTop10 + infra patterns + detectEcosystem: 25+ assertions
```

**Errors encountered & resolution:**
- Ternary `process.env.X ? X : "default"` pattern initially required a quoted true-branch — fixed to `\?\s*[^:]+:`.
- Cargo parser missed simple `crate = "0.27"` version form (only inline-table) — added fallback regex.
- First `claude-3-sonnet|claude-3-haiku` combined pattern mapped both captures to one label — split into two patterns.
- go.mod fixture assertion expected line 9; parser was right (line 10) — test fixed.
- esprima flagged pre-existing ES2019 constructs; verified identical failures at `git HEAD` before accepting as tooling limitation, then substituted in-memory to complete the parse check.

**Verification:**
- All new logic executed green via Code Mode JS runtime (~100 assertions total across 4 batches, including negative/FP cases from akumar0205 adversarial fixtures).
- All 8 modified JS files parse OK with esprima after ES2020→ES2017 token substitution (see above for the two pre-existing-construct exceptions).
- `tests.html` ships the same assertions for browser-based verification (no JS runtime in this container, so browser run is left to the user; the identical logic was proven green via Code Mode).
- `aidc-scan`: clean (semgrep + gitleaks clean after fixes: SRI pinning added for the Plausible CDN script; dynamic RegExp in dependency matchers replaced by the `depMatchesPattern` boundary helper — equivalence proven over 13 boundary cases).

**Review gate note (AGENTS.md pre-completion review):** `aidc-review-record` is not installed in this container (only `aidc-scan` is on PATH), so no mechanical review record could be written. A fresh-eyes review was performed by a subagent given only the diff + task description + repo guidance docs. Its findings were triaged on 2026-11-20: **fixed** — 3 failing tests.html assertions (dedup behavior, provider-filter semantics, Bedrock vendor naming), contextual-ref duplicate components (unattributed refs now merge into existing entries), missing negative-lookahead guards on bare model literals (`gpt-4.1/4.5/5` + pre-existing `gpt-4`/`llama3`/`mistral`/`qwen2.5` phantoms), Grok variant capture, Bedrock vendor naming, `nova`/`titan` word-bounding, dead `.claude/skills` config entry, dead `provider === "Unknown"` filter clause, stale CHANGELOG wording (OWASP scope + docs section), GAP_ANALYSIS citation imprecision. **Flagged for the user (not acted on):** the untracked `.github/workflows/sbom.yml` + `scripts/ci/*` pre-date this session and are unrelated to the detection work — confirm whether they should be committed or removed; the SRI hash pins the current Plausible script and will need updating if they rotate the file.

**Notes / follow-ups:** Deferred (documented in `mdfiles/GAP_ANALYSIS.md` as P3-experimental): GGUF/safetensors header parsing via HF Range requests, n8n/Dify workflow exports, baseline drift-comparison UI, model-file shard collapsing, evidence-grade provenance field expansion, raw-HTTP endpoint queries in the 10-query Search budget. `tests.html` is manual-run (open in browser); repo has no JS runtime to automate it — noted as the reason full coverage isn't CI-enforced.

---

## 2026-11-20 — Reference projects status update + detection gap analysis

**Summary:** Reviewed the refreshed `projects/` folder (2 new reference repos, 2 updated, 1 stale, 1 duplicate), created `projects/STATUS.md` to track them, and produced `mdfiles/GAP_ANALYSIS.md` listing 19 scenarios the analyzer does not currently detect, each with an implementation approach that stays within the HTML/JS/CSS-only codebase.

**Why:** The `projects/` folder holds the reference repos used to source and validate detection patterns. It was synced on 2026-11-20 (new: cisco `aibom` v1.10.1 and `aibom-akumar0205`; updated: `aibom-generator` / `owasp-aibom-generator`), but nothing in the repo recorded which projects are current, which have been mined into `js/`, and what new detection scenarios they expose. The gap analysis is the roadmap for absorbing them.

**What changed:**
- `projects/STATUS.md` (new) — per-project table: upstream, local HEAD + date, sync date, status (NEW / UPDATED / STALE / duplicate), mined-into-codebase flag, and sync commands.
- `mdfiles/GAP_ANALYSIS.md` (new) — gap scenarios P1 (data-only additions to `js/constants.js`), P2 (detector logic in `js/detectors.js`), P3 (BOM/schema/risk in `js/bom-generators.js` / `js/extended-aibom-generator.js`), each with file:line evidence from the reference repos and a JS-only implementation approach.

**How / commands run:**
```
for d in projects/*/; do git -C "$d" log -1 --format='%ci %h %s'; done   # per-project HEAD + date
ls -la --time-style=long-iso projects/                                   # sync dates (folder mtimes)
diff -qr projects/aibom-generator projects/owasp-aibom-generator --exclude=.git   # => IDENTICAL
for d in ai-spotter xbom aibom aibom-akumar0205 aibom-generator; \
  do timeout 12 git -C projects/$d fetch --dry-run; done                 # xbom: 1d747df..2b092b7 stale; rest current
grep -n -i "langgraph\|google-adk\|strands\|cohere'\|guardrails\|langfuse\|bedrock\|..." js/*.js   # confirmed gaps absent in our code
```
Four parallel subagent explorations inventoried (a) our full detection surface across `js/`, (b) cisco `aibom` (KNOWN_AI_PACKAGES, model registry, agent signatures, MCP/A2A detectors), (c) `aibom-akumar0205` (detectors, 10 OWASP risk rules, evidence-graded provenance schema, adversarial fixtures), (d) `aibom-generator` + ai-spotter + xbom signature corpus.

**Errors encountered & resolution:** none blocking. Notable findings folded into the docs instead of ad-hoc fixes: `owasp-aibom-generator` is a byte-identical duplicate of `aibom-generator` (different org remote) — flagged for user decision, not deleted; `xbom` upstream has newer commits than our clone — flagged for re-sync, not pulled (projects/ folder is user-managed).

**Verification:** Docs-only change (no code touched). Gap claims spot-verified against `js/` by grep: no `langgraph`/`google-adk`/`strands`/`cohere`/`guardrails`/`langfuse`/`bedrock` SDK signatures; `API_ENDPOINTS` consumed only in the 200-file fallback path (`detectors.js:604`); Anthropic code-model regexes require date suffixes (`detectors.js:1785-1806`); `data.truncated` never checked (`github-api.js:80-125`); `.ipynb` absent from code/model detector extension lists. `aidc-scan` run on changed files.

**Notes / follow-ups:** Top follow-up (user decision pending): implement gap #7 (generic `model=`/`model_name=` kwarg extraction in `modelsIdentifierDetector`) — biggest recall win, ~40 lines; then the P1 data additions (langgraph/ADK/provider SDKs/observability/guardrails). Duplicate checkout and xbom re-sync await user confirmation.

---

## YYYY-MM-DD — <short title>

**Summary:** One or two sentences on what changed and the user-facing effect.

**Why:** The problem, request, or constraint that prompted this. Link the issue
/ ticket / discussion if there is one.

**What changed:**
- File-by-file or component-by-component list of the edits.

**How / commands run:**
```
# exact commands executed, with the relevant output
```

**Errors encountered & resolution:** Anything that went wrong and how it was
fixed (or why it was left as-is).

**Verification:** How the change was proven to work — tests run, scanners,
manual checks, screenshots.

**Notes / follow-ups:** Design choices, trade-offs, and anything deferred.
