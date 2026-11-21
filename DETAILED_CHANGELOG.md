# Detailed Changelog

The long-form companion to `CHANGELOG.md`. Where `CHANGELOG.md` says *what*
changed in one line, this file records *why* and *how* — enough for a future
reader to audit, reproduce, or roll back any change without re-deriving it.

Add a new entry (newest first) for every meaningful change. Use the template
below; drop sections that genuinely don't apply.

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
