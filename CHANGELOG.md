# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Requirements gap-closing pass** (full CERT-In / G7 / OWASP audit): system producer (`metadata.manufacturer` + component `supplier` = repo owner, G7 #13), system version (package.json/pyproject.toml → component version + `aibom:system:version`, G7 #14), system timestamp (repo last-push → `aibom:system:timestamp`, G7 #15), SBOM version (`aibom:sbom-version`, G7 #2), SBOM authoring entity (`metadata.manufacturer`, G7 #1 → partial), system application areas (`aibom:application-areas`, G7 #19), model timestamps (`aibom:release-date` from bundled cards / `aibom:last-modified` from HF API, G7 #23), tokenizer identity (`aibom:tokenizer` from tokenizer_config.json, G7 #29), model licensing from bundled cards (CERT-In #5 / G7 #31), security-controls property from guardrail findings (CERT-In #12), **dataset components** (R5-lite: data-pipeline datasets → `type: data` components with source attribution + hub URLs + repo dependency edges in JSON/XML and `ai_Dataset` elements in SPDX — CERT-In #9/#10, G7 #33/#36/#41, OWASP #8), and the R6 vulnerability-posture honesty note in the extended AIBOM analysis notes. Follow-up: **HuggingFace datasets API enrichment** — `fetchHuggingFaceDatasetInfo` resolves HF dataset names for license/description/last-modified/downloads (license-if-public tier, capped 25), closing G7 #42 (dataset license). Scorecard: CERT-In **89.5%** weighted / 84.2% strict · G7 **71.0%** / 66.0% · OWASP **70.8%** / 50.0%.
- **HF enrichment uplift from OWASP-AIBOM-Generator comparison** (`guidance/sample/Sweaterdog_Andy-3.6_aibom_1_7.json`): HuggingFace hub models are now **commit-pinned** — the API's commit sha becomes the component `version` and is appended to the purl (`pkg:huggingface/<org>/<model>@<sha>`), giving an immutable, verifiable model revision (closes CERT-In #2 and G7 #22); correct 1.7 attribution (`supplier`/`manufacturer`/`authors` = the HF org, not the platform); training datasets emitted with hub URLs (`contents.url`); `distribution` (model files) and commit-specific `vcs` external references. Scorecard movement: CERT-In 78.9% weighted / 63.2% strict (was 73.7/57.9), G7 52.0% / 42.0% (was 50.0/40.0).
- **HuggingFace models now always get a model card**: the HF API is queried whenever any detected model is HuggingFace-sourced (previously gated on `providersUsed` reporting HuggingFace), and when the remote card README has no parseable YAML, a structured card is synthesized from the verified API details (`buildModelCardDataFromHuggingFace` in `js/utils.js`) — task from `pipeline_tag`, capability tags (license/dataset/arxiv metadata filtered out), architecture/context-window from `config.json`, license, hub origin (`aibom:origin: open-source-hub`) and model-page reference. Nothing is fabricated: intended-use/limitations stay absent when the API doesn't provide them; card provenance (`aibom:model-card-source`) distinguishes "HuggingFace API — <model url>" from bundled card files.

- **R1/R3/R4 implemented** (previously deferred 2026-11-20; guidance §5) + **BOM download UX**:
  - R1 — artifact hashes: Git-LFS pointer parsing in `modelsDetector` (≤512-byte pointer files → `oid sha256:`) attaches verified SHA-256 hashes to matching model components (CycloneDX `hashes`, SPDX `checksum`, XML `<hashes>`), with `aibom:artifact:path` / `aibom:hash-source` properties; unmatched artifacts produce no hash claim
  - R3 — header self-descriptions on every BOM: `aibom:scope` (repo static analysis @ scanned ref), `aibom:completeness` (partial — post-build), `aibom:generation-context` (after-build + native CycloneDX `metadata.lifecycles`), `aibom:authorship`, `aibom:graph-type`; SPDX document `comment` + extended AIBOM `source_scope`
  - R4 — attestation presence detection: new `attestationDetector` scans the tree for sigstore bundles, signatures, in-toto links/keys, SLSA provenance files and attestation tooling in GitHub workflows; `aibom:attestation` records detected types or an explicit "none found in repository scan"
  - BOM section UX: per-format **Download** button first (Copy secondary), raw JSON/XML view collapsed by default with a **Show content** toggle, and a **Download all** button for all four formats
  - Scorecard movement (all honest): CERT-In 73.7% weighted / 57.9% strict (#19 attestations met), G7 50.0% / 40.0% (#8 generation context, #26/#27 hashes met), OWASP 68.8% / 45.8% (#1–3 header met, #18 hashes met, #19 attestations partial)
- **Standards-compliance uplift from Snyk AIBOM comparison** (analysis in `projects/snyk/glm-comparision.md`; ChatGPT's independent take in `projects/snyk/compare.md`):
  - Clean component identity: library components now carry real names, versions and PURLs (`pkg:pypi/langchain@0.1.13`) from structured `dependencyInfo` — no more `"Dependency: <name>"` with placeholder version `detected`; model components never invent a version (`latest` removed, unknown stays unknown) and keep the verbatim source identifier
  - CycloneDX 1.7 schema conformance: modelCard enrichment remapped to valid field names (`task` singular string, `considerations.useCases`, `considerations.technicalLimitations`, `considerations.ethicalConsiderations` risk objects); non-schema card data (capabilities, training data, context length, lifecycle status, enrichment source, out-of-scope uses, base model, model type) moved to `modelCard.properties` under the `aibom:` namespace
  - Native CycloneDX evidence: `evidence.identity` (technique manifest-analysis/source-code-analysis + confidence) and `evidence.occurrences` (file/line, snippet as `additionalContext`); SPDX packages preserve detection evidence as `comment` and carry purls as `externalIdentifier`
  - External AI APIs as CycloneDX `services`: provider-matched models emit the provider's public inference endpoint (Google Generative Language API, OpenAI, Anthropic, Mistral, Cohere, Groq) with `authenticated: true`, wired into the dependency graph (repo → service, model → service)
  - New `aiImportsDetector`: undeclared-but-imported AI packages (the `langchain-community`/`langchain-core` class) detected in source with technique `source-code-analysis` and version unknown — closes the recall gap vs manifest-only scanning (Snyk's 80% vs our 60% library recall on this repo)
  - MCP SDK detection for Go/Java/Rust (ported from cyfinoid/aibommaker PR #2: `mark3labs/mcp-go`, `modelcontextprotocol/go-sdk`, `metoro-io/mcp-golang`, `io.modelcontextprotocol.sdk:mcp`, `rmcp`, `mcp-sdk`, `mcp-server` + Go code patterns + extended-dependency wiring)
  - AIBOM standards scorecard updated honestly: CERT-In #2 and G7 #22 (model version) now unmet instead of partial-credit for invented versions; CERT-In #16 (out-of-scope usage) now met — out-of-scope uses are extracted from local model cards (`aibom:out-of-scope-use`); net CERT-In 68.4% weighted / 52.6% strict (was 65.8/47.4), G7 44.0% (was 45.0), OWASP unchanged
- **Standards Compliance** (new `js/compliance.js`, rendered as its own section below the generated BOM with its own collapse control): the freshly generated CycloneDX 1.7 JSON and SPDX 3.0.1 JSON-LD are validated field-by-field against their specs (serialNumber URN, timestamps, bom-ref uniqueness, dependency/service ref resolution, `@context`, `creationInfo`), the NTIA 2021 minimum-elements baseline is checked honestly (pass/warn/fail per element, including supplier and author gaps), and the AIBOM standards scorecard from `guidance/guidance_details.md` §6 — CERT-In Table 10, G7 SBOM-for-AI minimum elements, OWASP AIBOM Foundations, weighted + strict — is now visible element-by-element in the UI instead of living only in the docs.

### Fixed

- **Two CodeQL `javascript-typescript` alerts fixed** (first detected 2026-11-21 on main):
  - **`js/incomplete-url-substring-sanitization`** (`js/detectors.js:1833`): the Git-LFS pointer check used `content.includes("https://git-lfs.github.com/spec/v1")` — the constant is a full URL that matches anywhere in the content. Fix: `content.startsWith("version https://git-lfs.github.com/spec/v1")` — per the LFS spec a pointer file *begins* with the version line, so this is both stricter (a doc file that merely mentions the LFS URL is no longer treated as a pointer) and position-anchored. Covered by 2 new `tests.html` assertions (mention-only file rejected, CRLF pointer still parsed).
  - **`js/incomplete-multi-character-sanitization`** (`scripts/tests/run-tests-html.js:37`): the test-harness console prettifier `v.replace(/<[^>]+>/g, '')` can re-form tags from nested input (`<<script>script>` strips to `<script>`). Fix: apply the strip to a fixpoint in a loop (the remediation CodeQL's own docs recommend; the query explicitly exempts replaces applied repeatedly in a loop). Behavior unchanged for well-formed input.
  - **Related hardening — `parseRepoInput`** (`js/github-api.js`, same CWE-20 class, not one of the reported alerts): repository input was validated by matching `github.com/` anywhere in the string, so `https://evil.example/github.com/owner/repo` or `https://github.com.evil.example/owner/repo` parsed as GitHub repos, and the extracted `owner`/`repo` flow into GitHub API URLs, evidence links, and generated BOMs. Now: URL-shaped input is parsed with `new URL()` and the **host** must be exactly `github.com`/`www.github.com`; slugs validated against GitHub's charset rules (`.git` stripped; `.`/`..` rejected); bare-host pastes (`github.com/o/r`), protocol-relative `//…`, and scp/ssh forms normalized and kept working; `git@github.com:o/r` now parses (previously garbage) and `https://gitlab.com/o/r` fails fast instead of producing a bogus `owner="gitlab.com"` call. 26 new `tests.html` assertions cover accepted forms, all substring bypasses, userinfo/backslash/percent-encoding tricks, and malformed-slug rejection.
- **`yargs/helpers` misdetected as a HuggingFace model** (`import { hideBin } from 'yargs/helpers';`): the HF-slug candidate rule relied on a hand-maintained npm-framework denylist (`next/`, `react/`, `lodash/` …) that didn't include `yargs/` — and the HF API 404-drop only helped when the API was reachable. New structural rule (`isNpmImportSpecifier` in `js/utils.js`): a `org/model` slug extracted from an import/require/from-import statement is a module specifier, not a model reference — models are never importable modules. Rejected locally with zero API calls, before any HF rate limit can matter.
- **Real-scan validation findings** (`guidance/sample/` — Mindcraft-for-Andy-3.5, 18 model components):
  - **False-positive model**: the npm subpath import `yargs/helpers` was detected as an HuggingFace-style model (`org/repo` slug shape). Fix: when the HF API answers 404 for a slug candidate, the candidate is dropped (definitively not a hub model); uncertain failures (429/auth) are kept.
  - **Duplicate model components**: the same model detected under two names (`models/text-embedding-004` + bare `text-embedding-004`, `deepseek-ai/DeepSeek-V3` + `deepseek-v3`) shipped as two components. Fix: base-name dedup (last path segment, case-insensitive) merges duplicates into the richer component (card/purl present) and unions evidence occurrences.
  - **Missing model purls**: purls now emitted for Mistral, xAI, DeepSeek, Groq, Cohere models (`pkg:ml/<provider>/<name>`), not just OpenAI/Anthropic/Google/HuggingFace.
  - Model card **References section** rendered empty: cards carry `modelPage`/`pricing`/`announcement`/`paper` keys but the panel only rendered `modelSpecificDocs`/`officialDocs`. The panel now renders every http(s) reference with a labeled link, and card references flow into the BOM as schema-valid component `externalReferences` (`website`/`citation`/`model-card`/`documentation`).
- **HuggingFace models missing model cards**: three compounding gaps — (1) the HF API was only queried when `providersUsed` reported HuggingFace, so plain-name HF models were never enriched; (2) `modelCardData` was only set when the remote README's YAML frontmatter parsed non-empty; (3) the bundled-card lookup has no HF entries. Fix: the HF API is now queried whenever any detected model is HuggingFace-sourced, and when no card YAML parses, a structured card is synthesized from the verified API details (`buildModelCardDataFromHuggingFace`) — task from `pipeline_tag`, capability tags (license/dataset/arxiv metadata filtered out), architecture/context-window from `config.json`, license, hub origin (`aibom:origin: open-source-hub`) and model-page reference. Nothing is fabricated: intended-use/limitations stay absent when the API doesn't provide them. Card provenance (`aibom:model-card-source`) now distinguishes "HuggingFace API — <model url>" from bundled card files. Additionally, the findings UI falls back to the HF API itself when a HF finding has no card after the bundled lookup (covers scan-time fetch failures like rate limits or gated models — e.g. `meta-llama/Meta-Llama-3-8B`), extended to any HF-slug model id (`org/repo`) regardless of provider attribution — provider signatures like DeepSeek can claim HF-slug models too, and the API 404s honestly for names that aren't on the hub.
- **`[object Object]` in Model Card Information**: structured card fields (`intendedUse` as `{primaryUses, outOfScope}`, `limitations` as `{knownLimitations}`) rendered as `[object Object]` in the findings UI (e.g. Google `models/embedding-001`) and were embedded as raw objects in generated BOMs. New `formatModelCardField` helper in `js/utils.js` renders them as readable text ("Semantic search and retrieval; … . Out of scope: …") in both `js/ui.js` and the `js/bom-generators.js` modelCard extension.

- **Detection coverage from 2026-11 reference-project sync** (details in `mdfiles/GAP_ANALYSIS.md`, test suite in `tests.html`):
  - 16 new LLM provider/gateway signatures (Cohere, Mistral, Groq, xAI Grok, Together, Perplexity, Fireworks, Replicate, AI21, Stability, Aleph Alpha, Azure OpenAI, AWS Bedrock, Vertex AI, OpenRouter, LiteLLM) with SDK packages, code patterns, and API endpoints
  - 11 new agent-framework signatures (LangGraph, Google ADK, OpenAI Agents SDK, PydanticAI, SmolAgents, Strands, DeepAgents, Haystack, DSPy, Instructor, Semantic Kernel) plus AutoGen ecosystem variants
  - New guardrails and LLM-observability categories (NVIDIA Guardrails, Guardrails AI, LLM Guard, Presidio, Langfuse, LangSmith, Arize Phoenix, Traceloop, Galileo)
  - Contextual model extraction: `model=`/`model_name=`/`model_id=`/`deployment_name=` kwargs, module constants, and env-with-default dataflow now capture unknown/new model ids without literal-pattern updates
  - Bedrock ARN normalization (`us.anthropic.claude-...-v2:0` → `claude-3-5-sonnet`), Ollama model-tag detection (`qwen3:4b`), and newer model literals (GPT-4.1/4.5/5, o1-pro/o3/o4-mini, Gemini 2.5, Claude 3.7/4.x bare aliases, Llama 4, Qwen3, Grok, Amazon Nova/Titan)
  - Fallback manifest parsing for `go.mod`, `Cargo.toml`, `pom.xml`, and `build.gradle` (previously only Python/Node manifests were parsed without the SBOM API)
  - Jupyter notebook support: `.ipynb` cells are extracted and scanned by code/model detectors
  - A2A Agent Card detection (`.well-known/agent.json`), Semantic Kernel protocol activation (patterns existed but were never scanned), framework config files (`langgraph.json`, `crewai.yaml`, `dspy.toml`), and `SKILL.md` agent-skill artifacts
  - Digest-pinned image detection (Dockerfile/k8s `@sha256:`) and k8s model-env configuration as infrastructure provenance evidence
  - OWASP Top 10 for LLM Applications (2025) exposure assessment in the Extended AIBOM risk section — 6 of the 10 categories with detectable surfaces (LLM01/02/03/04/06/08) plus a guardrail mitigation indicator; categories requiring runtime evidence (LLM05/07/09/10) are intentionally not fabricated
  - Dynamic RegExp elimination in the dependency matchers (`depMatchesPattern` word-boundary helper; fixes `detect-non-literal-regexp` finding) and subresource integrity (SRI) pinning for the Plausible analytics script
- **Scan-completeness warning**: GitHub tree truncation (`truncated` flag) is now detected and surfaced in the UI instead of being silently ignored

### Changed

- **Analysis Notes section moved to the bottom of the results flow** (below Standards Compliance) and reformatted: gaps now render as a compact three-column table (Missing / What we searched / What it would add) with category chips and icons, a count in the heading, and a clearer caption stating that "not detected" means the repository shows no trace — not an error. Scan-completeness warnings keep their warning-styled block above the table.
- **Standards Compliance scorecard notes cleaned to factual statements**: notes now state only where an element is implemented or why it cannot be — no dates, no change-log commentary ("added …", "removed …", "R… deferred") in the UI; history stays in the changelog
- README "What It Detects" updated to reflect the new detection surface
- Duplicate model components eliminated: unattributed contextual model refs now merge into existing provider-keyed entries; bare model-name literals (`gpt-4`, `gpt-4.1`, `gpt-4.5`, `gpt-5`, `llama3`, `mistral`, `qwen2.5`) no longer substring-match inside their longer variants
- Grok pattern now captures the specific variant (`grok-2`, `grok-4`, …) instead of collapsing to "grok"; Bedrock signature vendor unified to "AWS Bedrock"; `nova`/`titan` provider attribution word-bounded

### Documentation (2026-11-20)

- **Reference-project status tracker** (`projects/STATUS.md`): records upstream, HEAD, sync date, and mined-into-codebase status for every `projects/` entry after the 2026-11-20 sync — new projects `aibom` (cisco-ai-defense v1.10.1) and `aibom-akumar0205`, updated `aibom-generator`; `owasp-aibom-generator` byte-identical duplicate removed by the user; `xbom` re-synced to `2b092b7`.
- **Gap analysis** (`mdfiles/GAP_ANALYSIS.md`): 19 detection scenarios the analyzer does not yet cater for, distilled from the newly synced reference projects, each with a concrete HTML/JS/CSS-only implementation approach and priority order (implementation status tracked in the doc header).
- **Detection test suite** (`tests.html`): self-contained browser-runnable assertions for the new pure helpers, manifest parsers, signature registry, infrastructure patterns, and OWASP derivation (no test framework needed — plain HTML/JS like the app itself).
- **Guidance inventory** (`guidance/guidance_details.md`): documents all 8 guidance documents in `guidance/` (OWASP AIBOM Foundations, G7 SBOM-for-AI minimum elements, CERT-In technical guidelines, NIST AI RMF, OWASP GenAI IR guide, SPDX AIBOM experience report, AIBoMGen, CISA AIBOM Tiger Team deck) with per-document AIBOM requirements, a cross-document minimum-bar synthesis, an element-by-element coverage matrix against this generator, prioritized recommendations (R1–R10; R1/R3/R4 deferred by user decision 2026-11-20), and a **compliance scorecard** (§6): weighted vs strict conformance per document — CERT-In Table 10 **65.8%** (12.5/19), G7 minimum elements **45.0%** (22.5/50), OWASP Foundations **50.0%** (12/24) — with per-element status tables, uplift analysis per recommendation, and the structural (⛔) limits of a post-hoc scanner.

## [0.0.4] - 2025-12-26

### Added

#### Model Card Integration in UI
- **Live Model Card Display**: Model cards now appear directly in AI model findings
  - Rich model information including description, intended use, limitations, training data
  - Ethical considerations, bias/fairness, safety measures, and privacy considerations
  - Technical specifications like context length and capabilities
  - Direct links to official provider documentation
- **Dynamic Model Card Loading**:
  - Model cards loaded on-demand during UI rendering
  - Efficient caching prevents multiple fetches of same model card
  - Filename normalization handles model names with special characters
- **Enhanced Model Detection**:
  - Improved pattern matching for model identification
  - Better integration between detection and model card display
  - Support for all major AI providers (OpenAI, Anthropic, Google, etc.)

#### Performance Improvements
- **Model Card Caching**: Prevents redundant loading of model card data
- **Async UI Loading**: Non-blocking model card fetching during findings display
- **Memory Optimization**: Efficient storage and retrieval of model metadata

#### BOM Generation Enhancements
- **Model Card Data Integration**: Model cards enrich BOM output with comprehensive metadata
- **Improved Component Generation**: Better handling of ML model components
- **Standard Compliance**: CycloneDX 1.7 and SPDX format enhancements

### Fixed
- **Model Card Loading**: Fixed multiple loading issues and caching problems
- **UI Display**: Model cards now properly display in findings interface
- **Async Operations**: Proper async/await handling throughout the application

## [0.0.3] - 2025-12-26

### Added

#### Model Cards System
- **Comprehensive model cards database** with 100+ model cards for major AI providers
  - OpenAI: GPT-4, GPT-4o, GPT-3.5-turbo, o1-preview, o1-mini, DALL-E models, text embeddings
  - Anthropic: Claude-3 family (Opus, Sonnet, Haiku, 3.5-Sonnet)
  - Google: Gemini models (1.5-flash/pro, 2.0-flash-exp), Gemma 2/3, embedding models
  - Meta: Llama 3.x family, CodeLlama, MedLlama2
  - Microsoft: Phi-3, Phi-4
  - Cohere: Command-A, Command-R, Command-R-Plus, Command-R7B-Arabic
  - DeepSeek: DeepSeek-Coder-v2, DeepSeek-R1, DeepSeek-v3
  - Alibaba: Qwen 2.5, Qwen 2.5-Coder, QWQ
  - Mistral: Mistral, Mistral-Large, Mixtral-8x7B, Mathstral
  - 01.ai: Yi model
  - EPFL: Meditron
  - NexusFlow: Athene-v2
- **Model card generation scripts**
  - `generate_cards.py`: Automated model card generation from templates
  - `extract_factual_info.py`: Extract factual information from model documentation
  - `extract_official_info.py`: Extract official model information from provider sources
  - `update_from_official_sources.py`: Update model cards from official sources
- **Structured model metadata** in JSON format with comprehensive fields
  - Model capabilities, limitations, training data, performance metrics
  - Ethical considerations, bias assessments, safety information
  - Technical specifications, input/output formats, supported languages
- **Model card templates** (JSON, Markdown, YAML) for consistent formatting
- **Official sources tracking** with `official_models_found.json` for source verification

#### Enhanced File Detection
- **Improved README and security file detection**
  - Better pattern matching for documentation files
  - Enhanced security file recognition (SECURITY.md, etc.)
  - Improved file type detection and parsing
- **Model card file detection integration**
  - Automatic detection of model card files in repositories
  - Support for multiple model card formats (JSON, Markdown, YAML)

#### Pattern Updates and False Positive Reduction
- **Comprehensive pattern updates** across detection systems
  - Enhanced model detection patterns with reduced false positives
  - Improved hardware and infrastructure pattern matching
  - Better dependency and library detection
- **False positive filtering**
  - Word boundary matching to prevent substring matches
  - Context-aware pattern validation
  - Enhanced validation for model name detection

### Fixed
- **Reduced false positives in model detection**
  - Better word boundary handling for model names
  - Improved pattern specificity to avoid common word matches
  - Enhanced validation logic for detected patterns

### Technical Details

#### New Files
- `modelcards/` directory with 100+ model card files across providers
- Model card generation and extraction scripts in `modelcards/`
- Template files for consistent model card formatting

#### Modified Files
- `js/constants.js` - Major pattern updates and false positive reductions
- `js/detectors.js` - Enhanced file detection for documentation and model cards
- `js/extended-aibom-generator.js` - Model card integration
- `js/github-api.js` - Improved API handling for model card sources
- `js/ui.js` - Model card display enhancements
- `index.html` - Model card UI integration

## [0.0.2] - 2025-11-14

### Added

#### Enhanced HuggingFace Model Metadata Extraction
- **Comprehensive HuggingFace API integration**
  - Fetches `config.json` for model architecture details (model_type, architectures, vocab_size, etc.)
  - Fetches `README.md` for ModelCard YAML frontmatter parsing
  - Extracts `cardData` fields: license, language, base_model, datasets, model_summary, model_type
  - Extracts `eval_results` for performance metrics
  - Adds metadata fields: `primaryPurpose`, `suppliedBy`, `typeOfModel`, `architectures`
- **ModelCard YAML parser**
  - Parses HuggingFace ModelCard YAML frontmatter from README.md
  - Extracts structured metadata: license, language, datasets, base_model, model_type, etc.
  - Handles arrays, nested objects, and multi-line values
  - Merges parsed YAML data with API cardData for comprehensive metadata
- **Enhanced ModelCard properties in BOM**
  - Energy consumption: `energyConsumption`, `energyQuantity`, `energyUnit`
  - Training information: `hyperparameter`, `informationAboutTraining`, `modelDataPreprocessing`
  - Safety & ethics: `safetyRiskAssessment`, `useSensitivePersonalInformation`
  - Explainability: `modelExplainability`
  - Metrics: `metric`, `metricDecisionThreshold`
  - Application: `informationAboutApplication`
  - Limitations and ethical considerations from ModelCard
- **Quantitative Analysis section**
  - Adds `quantitativeAnalysis` section to modelCard with `performanceMetrics` from eval_results
  - Converts HuggingFace eval_results to CycloneDX performanceMetrics format
  - Includes graphics placeholder for future visualization support
- **Enhanced metadata properties**
  - Component-level properties: `primaryPurpose`, `suppliedBy`, `typeOfModel`, `domain`, `language`
  - Main BOM component metadata via `extractModelMetadata()` function
  - Domain inference from model tags (medical, healthcare, finance, legal, education, etc.)
  - All metadata properties added to CycloneDX BOM main component

### Fixed
- **Fixed incorrect evidence attribution for OpenAI dependencies**
  - "OpenAI-compatible" API endpoint findings (from `/v1/chat/completions`) no longer incorrectly matched to `openai` dependency
  - These endpoints are often used through `litellm` or other libraries, not the OpenAI SDK directly
  - Added `litellm` SDK detection patterns so `litellm` code usage is properly matched to `litellm` dependency
  - Evidence now correctly shows which library is actually being used in code
- **Fixed false positive detection for "yi" model**
  - Pattern now uses word boundaries to prevent matching "yi" inside common words like "yield", "lying", "dying"
  - Pattern matches: `"yi"`, `'yi'`, or `yi` as standalone word (not substring)
  - Added false positive filter in `isValidModelName` to exclude common words containing "yi"
  - Prevents false matches in Python `yield` statements and other common code patterns
- **Fixed incomplete model name detection for Cohere models**
  - Added missing pattern for "command-r7b-arabic" model
  - Reordered Cohere model patterns: more specific patterns (command-r7b-arabic, command-r-plus) checked before general pattern (command-r)
  - Updated "command-r" pattern to use negative lookahead to prevent matching inside "command-r7b-arabic"
  - Model findings now show full model name (e.g., "command-r7b-arabic" instead of truncated "command-r")
- **Enhanced GPU hardware detection to capture specific GPU models**
  - Added patterns to detect specific GPU models from code (A10G, H100, T4, V100, A100, etc.)
  - Detects GPU models from Modal (`gpu="A10G"`), AWS SageMaker (`instance_type="ml.g5.xlarge"`), GCP Vertex AI (`accelerator_type="NVIDIA_TESLA_T4"`), Azure ML (`vm_size="NC6"`), and generic patterns
  - Hardware findings now show specific GPU models in description (e.g., "GPU compute detected: A10G, H100:1")
  - GPU models included in `hardwareInfo.models` and added to BOM as `aibom:hardware:models` property
  - Evidence includes specific GPU model information for better traceability

## [0.0.1] - 2025-11-13

### Added

#### Enhanced Model Detection
- Added detection for HuggingFace models with `hf.co/` URL pattern
  - Supports full paths: `hf.co/organization/model-name:quantization`
  - Extracts model path and handles quantization suffixes (Q8_0, Q2_K, etc.)
- Expanded Ollama/Local model detection
  - Added Llama 3.x family: llama3, llama3.1, llama3.2, llama3.3, llama3.2-vision
  - Added CodeLlama models: codellama:7b, codellama:70b
  - Added DeepSeek models: deepseek-coder-v2, deepseek-r1, deepseek-v3
  - Added Qwen models: qwen2.5, qwen2.5-coder, qwq
  - Added Gemma models: gemma2, gemma3
  - Added Phi models: phi3, phi4
  - Added specialized models: medllama2, meditron, mathstral, yi, athene-v2
  - Added Cohere models: command-a, command-r, command-r7b-arabic
- Better detection of models in arrays/lists (MODEL_IDS, MODELS, etc.)

#### Hardware Detection
- Added comprehensive hardware detection system for GPU, TPU, and specialized compute
- Detects CUDA, cuDNN, PyTorch GPU, TensorFlow GPU, cuPy dependencies
- Detects TPU usage through TensorFlow TPU, JAX configurations
- Detects specialized hardware: TensorRT, OpenVINO, ONNX Runtime, CoreML
- Hardware patterns now scan both dependencies and code files
- Hardware findings include evidence with file locations and code snippets
- **Fixed TPU false positives**: TPU patterns now use word boundaries and only scan Python files
  - Prevents false matches on "output", "timeout", "interrupted" in JavaScript
  - TPU is TensorFlow/JAX specific, so only Python files are scanned
  - GPU patterns also improved with word boundaries
  - Specialized hardware (TensorRT, OpenVINO) restricted to Python files

#### Infrastructure & Deployment Detection
- Added infrastructure detection for containerization (Docker, Docker Compose)
- Detects GPU-enabled containers (NVIDIA CUDA base images, GPU runtime)
- Kubernetes orchestration detection (deployments, services, GPU scheduling)
- Cloud platform detection: AWS SageMaker, GCP Vertex AI, Azure ML, AWS Bedrock, Modal, Replicate
- MLOps tools detection: MLflow, Weights & Biases, TensorBoard, ClearML
- Infrastructure findings include platform details and deployment configurations

#### Documentation Parser & Governance
- Added documentation parser for model cards and governance documentation
- Extracts intended use, limitations, ethical considerations from README and MODEL_CARD files
- Detects bias/fairness discussions in documentation
- Parses security considerations from SECURITY.md files
- Supports multiple documentation file formats (README.md, MODEL_CARD.md, ETHICS.md, BIAS.md, etc.)
- Documentation completeness scoring system

#### Risk Assessment
- Added comprehensive risk detector for security and compliance evaluation
- Detects deprecated and unmaintained dependencies
- Scans for vulnerability mentions in documentation
- Analyzes ethical considerations and bias/fairness documentation
- Provides overall risk level (low, medium, high) with scoring algorithm
- Generates actionable recommendations for improvements
- Note: Missing documentation is logged but not treated as a finding (see Analysis Notes instead)

#### Extended AIBOM Format
- Created new Extended AIBOM format (JSON) with comprehensive AI system metadata
- Includes standard CycloneDX 1.7 BOM as foundation for compatibility
- Extended metadata sections:
  - Hardware: compute requirements, GPU/TPU/specialized hardware
  - Infrastructure: deployment platforms, cloud services, MLOps tools
  - Model Governance: intended use, limitations, ethical considerations, bias/fairness
  - Risk Assessment: security concerns, recommendations based on findings
  - Data Pipeline: data loading, preprocessing, feature engineering libraries
  - **Analysis Notes**: NEW - Documents what could NOT be detected (transparent about limitations)
    - Missing documentation (README, MODEL_CARD, SECURITY files)
    - Undetectable components (training data, model weights, runtime metrics)
    - Detection limitations (context-specific gaps)
    - Suggested improvements (actionable recommendations)
- Summary statistics with documentation completeness scoring
- Based on industry best practices from Snyk and Trail of Bits RFI response

#### Enhanced Standard BOMs
- CycloneDX 1.7 JSON/XML now include hardware metadata properties
- Added `aibom:hardware:detected`, `aibom:hardware:types`, `aibom:hardware:libraries` properties
- Infrastructure metadata in main component properties
- Added `aibom:infrastructure:detected`, `aibom:infrastructure:platforms` properties
- Governance indicators: `aibom:governance:documented`, `aibom:governance:limitations`, etc.
- All standard BOMs enhanced with detectable hardware and infrastructure information
- **Improved modelCard generation for ML models**
  - Uses explicit `modelType` from detection (more accurate than keyword matching)
  - Adds `architectureFamily` for common models (llama, mistral, gemma, phi, qwen, deepseek)
  - Properly handles all model types: text-generation, embeddings, text-to-image, multimodal
  - Only includes modelCard if it has actual content (prevents empty modelCards)
  - Better task, input, and output format detection

#### UI Enhancements
- Added "Extended AIBOM" tab to BOM output section
- **Added "Analysis Notes" section** displayed before Generated AI BOM section
  - Shows missing documentation with purpose and impact
  - Lists detection limitations based on findings
  - Displays undetectable components (inherent limitations)
  - Collapsible section with expand/collapse functionality
  - Card-based grid layout for easy scanning
  - Appears for all analyses, not just Extended AIBOM format
- New category filters: Hardware, Infrastructure, Governance, Risk
- Extended AIBOM format supports copy to clipboard and download
- Informational banner explaining Extended AIBOM format features
- Download naming convention updated for extended format
- Fixed scrollbar visibility in BOM output preview (reduced max-height from 1000px to 600px)

#### Documentation
- Added comprehensive Extended AIBOM specification document (`docs/EXTENDED_AIBOM_SPEC.md`)
- Added centralized references document (`REFERENCES.md`) with all academic, industry, and regulatory sources
- Updated README with all new detection capabilities
- Documented hardware, infrastructure, governance, and risk assessment features
- Added references to Snyk, Trail of Bits, and arXiv 2510.07070 AIBOM standard
- Included examples and use cases for Extended AIBOM format

### Changed

#### Detection Pipeline
- Enhanced analyzer to support new detector types with contextual data passing
- Added support for parsers (documentation parser) vs detectors
- Detectors can now access findings from previous detectors (via `needsAllFindings`)
- New detector flags: `needsAllFindings`, `needsParsedDocs`, `isParser`
- Detection pipeline now includes 12 detectors (up from 8)
- Added `parsedDocs` state tracking across analyzer pipeline
- **Metadata detector now logs only** (doesn't create findings)
  - Repository keywords are informational, not AIBOM components
  - Metadata already captured in BOM metadata section
  - Reduces noise in findings list
- **Prompt detector now logs only** (doesn't create findings)
  - Prompts are not components in AIBOM specifications (CycloneDX, SPDX)
  - Prompts are inputs/configuration, not part of the bill of materials
  - Directory names (prompts/, templates/, etc.) are organizational structure, not components
  - Prompt template files are logged for analysis but not included as findings
  - Aligns with AIBOM specification focus on components (dependencies, models, hardware, infrastructure)
- **Infrastructure detector now only reports ML-specific infrastructure**
  - Generic Docker/Kubernetes detection removed (deployment infrastructure, not AIBOM components)
  - Only reports ML-specific containerization: GPU-enabled containers, ML framework base images (PyTorch, TensorFlow, HuggingFace)
  - Only reports ML-specific orchestration: GPU scheduling in Kubernetes (nvidia.com/gpu)
  - Cloud ML platforms (SageMaker, Vertex AI, Azure ML) still reported (ML-specific platforms)
  - MLOps tools (MLflow, W&B) still reported (ML-specific dependencies)
  - All infrastructure findings now include evidence (file paths and code snippets)
  - Aligns with AIBOM specification: infrastructure is HOW the system runs, not WHAT components are in it
  - ML-specific infrastructure (GPU, ML platforms) is relevant because it indicates hardware requirements and ML context

#### Constants & Patterns
- Added `HARDWARE_PATTERNS` with GPU, TPU, and specialized compute patterns
- Added `INFRASTRUCTURE_PATTERNS` for Docker, Kubernetes, cloud platforms
- Added `DOCUMENTATION_FILES` list for governance documentation detection
- Added `DATA_PIPELINE_PATTERNS` for data loading and preprocessing detection
- Added `RISK_KEYWORDS` for vulnerability, deprecation, bias, and ethical concerns
- All new patterns include pattern matching and weight scoring

#### Detection Behavior
- **Changed risk detector to only create positive findings** (what IS found)
  - Missing documentation is logged but not included as AIBOM findings
  - AIBOM now focuses on discovered components and capabilities
  - Analysis notes track gaps separately from actual findings
- **Removed confidence score from UI**
  - Score badge removed from Analysis Results header
  - Console logging simplified to remove scoring metrics
  - Focus shifted from scoring to comprehensive documentation
- **Fixed insecure URL substring validation in Go module detection**
  - Replaced `includes('github.com/')` with proper regex validation
  - Prevents false positives from malicious URLs (e.g., `malicious.com/github.com/package`)
  - Now validates that `github.com` is the actual domain, not just a substring
  - Supports Go module formats: `github.com/owner/repo`, `https://github.com/owner/repo`, `git@github.com:owner/repo`
- **Added GitHub SBOM download link to dependency findings**
  - Evidence for dependencies detected via GitHub SBOM API now includes clickable link
  - Links to `https://github.com/{owner}/{repo}/network/dependencies` for SBOM download
  - Improves user experience by providing direct access to GitHub's dependency graph

### Technical Details

#### New Files
- `js/extended-aibom-generator.js` - Extended AIBOM format generator
- `docs/EXTENDED_AIBOM_SPEC.md` - Formal specification for Extended AIBOM
- `REFERENCES.md` - Centralized references for all academic, industry, and regulatory sources

#### Modified Files
- `js/constants.js` - Added hardware, infrastructure, documentation, data pipeline, and risk patterns
- `js/detectors.js` - Added 4 new detectors: hardware, infrastructure, documentation parser, risk
- `js/analyzer.js` - Enhanced detection pipeline with new detector types
- `js/bom-generators.js` - Added hardware/infrastructure metadata to standard BOMs
- `js/ui.js` - Added Extended AIBOM tab rendering, Analysis Notes section, and download logic
- `index.html` - Added Extended AIBOM tab, Analysis Notes section, and new category filters
- `styles.css` - Added Analysis Notes card styles, fixed scrollbar visibility
- `README.md` - Documented all new features and capabilities

### Implementation Approach

#### Based on Industry Best Practices
- **Snyk's Essential Guide to AIBOMs**: Implemented 8 actionable tips
  - Complete inventory of components
  - Risk and limitation identification
  - Model lineage tracking (where detectable)
  - Standards alignment
  - Reproducibility support

- **Trail of Bits RFI Response**: Addressed key recommendations
  - Hardware Bill of Materials (HBOM) for specialized compute
  - Data transformation and pipeline tracking
  - Infrastructure security configuration detection
  - ML-specific components beyond traditional SBOM
  - Complementary security techniques

#### Detection Philosophy
- **Auto-detection only**: No manual input required or accepted
- **Evidence-based**: All findings linked to specific files and line numbers
- **Reproducible**: Same repository produces same AIBOM
- **Comprehensive**: Hardware, infrastructure, governance, risks, and data pipeline
- **Positive findings only**: AIBOM documents what IS found, not what's missing
  - Missing documentation is logged for analysis but not included as findings
  - Focus on discovered components, capabilities, and governance indicators
  - Negative findings (gaps) tracked separately for improvement recommendations
- **De-emphasized scoring**: Removed confidence score display from UI
  - AIBOM focuses on comprehensive documentation, not arbitrary scoring
  - Categories and findings speak for themselves
- **Added Analysis Notes section**: NEW practical feature
  - **Scan-specific**: Documents what we scanned for but didn't find in THIS repository
  - **NOT philosophical**: No generic limitations that apply to all scans
  - Shows components we actively searched for but were not present:
    - Documentation: README.md, MODEL_CARD.md, SECURITY.md (if not found)
    - Hardware: GPU/TPU libraries (if no hardware detected despite having models)
    - Infrastructure: Docker, Kubernetes, cloud configs (if not found)
    - Governance: Model governance docs (if models but no governance found)
    - Data Pipeline: Data processing libraries (if models but no data libs found)
  - Each entry shows: Category, Item name, What we scanned, AIBOM benefit
  - Suggested improvements with actionable file recommendations
  - Philosophy: "Looked for but didn't find" vs "fundamentally undetectable"

#### Limitations Acknowledged
- Cannot detect runtime-only behaviors
- No access to private training data
- Cannot measure model performance metrics
- Limited visibility into third-party API models
- Cannot verify actual training infrastructure

### References
- Snyk: [Essential Guide to AI Bills of Materials](https://snyk.io/articles/ai-security/ai-bill-of-materials-aibom/)
- Trail of Bits: [Response to US Army AIBOM RFI](https://blog.trailofbits.com/2024/02/28/our-response-to-the-us-armys-rfi-on-developing-aibom-tools/)
- arXiv 2510.07070: [Building an Open AIBOM Standard in the Wild](https://arxiv.org/html/2510.07070v1) - Experience report on developing AIBOM specification extending ISO/IEC 5962:2021 SPDX
- CycloneDX 1.7 Specification
- SPDX 3.0.1 Specification
- NIST AI Risk Management Framework
- EU AI Act compliance indicators

## Future Considerations

Based on ongoing research and the emerging open AIBOM standard (arXiv 2510.07070):
- **SPDX AI Extension Alignment**: The open AIBOM standard extends ISO/IEC 5962:2021 SPDX to include:
  - Dataset components and provenance
  - Training artifacts and configurations
  - AI-specific metadata aligned with EU AI Act
  - Validated through 90+ contributors and industrial case studies
- Integration with formal AIBOM standards as they stabilize
- AI/ML vulnerability database support
- Dataset provenance tracking when standardized
- Training artifact detection (hyperparameters, training configs)
- Model performance metrics extraction from documentation
- License compliance analysis for AI components
- Carbon footprint estimation for training and inference
- Alignment with ISO/IEC 5962:2021 SPDX AI extensions

---

**Note:** This project is experimental. While implementing industry best practices from Snyk and Trail of Bits, the Extended AIBOM format is designed to be practical and immediately useful while standards bodies work on formal specifications.

