# ⚠️ EXPERIMENTAL CODE

**The author prefers working on code directly rather than focusing on specifications.** While the AI BOM specifications are being sorted by committees, this repository focuses on analyzing code of AI/LLM-based projects to identify components. Once BOM formats are finalized, this tool might become the aibom generator by cyfinoid or be archived as more mature solutions appear.

**To reiterate: This is experimental code. We make no guarantees it will produce output in the correct format or work consistently.**

---

# AI BOM Generator

A client-side web application that analyzes GitHub repositories for AI/LLM usage and generates machine-readable AI Bill of Materials (AI BOM) in CycloneDX 1.7 and SPDX 3.0.1 formats.

## 🎯 Key Features

- **Smart Detection**: Language-aware scanning with provider-specific model identification
- **Machine-Readable**: Individual components per dependency with exact line numbers and code snippets
- **Precise Evidence**: Every finding links to exact file and line number in GitHub
- **Zero False Positives**: Filters out MIME types, framework imports, and documentation files
- **No Backend**: Runs entirely in your browser
- **Standards Compliant**: CycloneDX 1.7 (JSON/XML) and SPDX 3.0.1

## ⚡ Quick Start

### Requirements

**GitHub Personal Access Token (REQUIRED)**

The tool requires a GitHub token to operate efficiently. Analysis typically needs 100+ API requests:
- Without token: 60 requests/hour (insufficient for most repositories)
- With token: 5,000 requests/hour

**Create a token**: GitHub Settings → Developer settings → Personal access tokens → Generate new token (classic)
- **No scopes required** - leave all checkboxes unchecked
- This provides read-only access to public repositories

### Running Locally

1. Clone this repository
2. Open `index.html` in a modern browser (Chrome, Firefox, Safari, Edge)
3. Enter a GitHub repository (`owner/repo` or full URL)
4. **Paste your GitHub token** (required for accurate analysis)
5. Click "Analyze Repository"

**No server, no installation, no dependencies required** - just open the HTML file!

**Note:** The code is now split into manageable JavaScript files in the `js/` folder for easier maintenance.

## 🔍 What It Detects

### Dependencies
Individual components for each AI/LLM library with version and exact location:
- **Primary Detection**: Uses GitHub's Dependency Graph SBOM API (SPDX format) for comprehensive, accurate dependency detection
- **Fallback Detection**: Manual parsing of manifest files when SBOM API is unavailable (Python, Node.js, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`)
- **Supported Ecosystems**: Python, Node.js, Go, Java, Rust
- **Example Libraries**: `openai`, `anthropic`, `langchain`, `transformers`, `chromadb`, `@anthropic-ai/sdk`, `ai`
- **Agent Frameworks**: `langgraph`, `google-adk`, `openai-agents`, `crewai`, `autogen`/`ag2`, `pydantic-ai`, `smolagents`, `strands-agents`, `deepagents`, `haystack-ai`, `dspy`, `instructor`, `semantic-kernel`
- **Safety & Observability**: guardrails/moderation (`nemoguardrails`, `llm-guard`, `presidio`, `rebuff`) and LLM tracing (`langfuse`, `langsmith`, `arize-phoenix`, `traceloop`)

### AI Models
Identifies specific models with type classification:
- **Text Generation**: GPT-4o, GPT-4.1/4.5/5, o1/o3/o4-mini, Claude 3.x/4.x (incl. bare aliases like `claude-sonnet-4-5`), Gemini 1.5/2.0/2.5, Llama 3/4, Qwen, Grok
- **Embeddings**: text-embedding-3-large, models/embedding-001
- **Image Generation**: DALL-E-3, Stable Diffusion
- **Bedrock-style ids**: `anthropic.claude-...`/`meta.llama...` ARN forms normalized to public model names
- **Contextual extraction**: model ids passed as `model=`/`model_name=` kwargs, module constants (`MODEL_NAME = "..."`), and env defaults (`os.environ.get("MODEL", "gpt-4o")`, `process.env.X ?? "..."`) are captured even when the exact model is not in the built-in list
- **Notebooks**: `.ipynb` files are scanned for model and SDK usage
- **Local runtimes**: Ollama-style model tags (`qwen3:4b`) detected in Ollama-related files

### Code Usage
SDK imports and API calls with precise line numbers
- **Providers**: OpenAI, Anthropic, Google, Cohere, Mistral, Groq, xAI, Together, Perplexity, Fireworks, Replicate, AI21, Stability, Aleph Alpha, Azure OpenAI, AWS Bedrock, Vertex AI, LiteLLM, OpenRouter
- **Raw HTTP**: provider API endpoints (`api.openai.com`, `bedrock-runtime`, `localhost:11434`, ...) detected even without an SDK import
- **Notebooks**: `.ipynb` cells are converted to source and scanned

### Configuration
Model names and API keys in config files

### Hardware Requirements
Detects specialized compute requirements:
- **GPU**: CUDA, cuDNN, PyTorch GPU, TensorFlow GPU
- **TPU**: TensorFlow TPU, JAX TPU configurations
- **Specialized**: TensorRT, OpenVINO, ONNX Runtime

### Infrastructure & Deployment
Identifies deployment platforms and tools:
- **Containerization**: Docker, Docker Compose, GPU-enabled containers, digest-pinned base images (`FROM ...@sha256:...`)
- **Orchestration**: Kubernetes deployments and services, digest-pinned images, model configuration injected via pod environment (`MODEL_DEPLOYMENT=gpt-4o-mini`)
- **Cloud Platforms**: AWS SageMaker, GCP Vertex AI, Azure ML, AWS Bedrock
- **MLOps**: MLflow, Weights & Biases, TensorBoard, ClearML

### Governance & Documentation
Analyzes model documentation for responsible AI:
- **Intended Use**: Purpose and use case documentation
- **Limitations**: Known constraints and limitations
- **Ethical Considerations**: Privacy, consent, responsible use
- **Bias & Fairness**: Demographic parity, fairness assessments

### Risk Assessment
Evaluates security and compliance risks:
- **Missing Documentation**: README, MODEL_CARD, SECURITY files
- **Vulnerabilities**: Deprecated packages, known issues
- **Compliance**: Documentation completeness scoring
- **Recommendations**: Actionable improvement suggestions

## 🎓 AI-Assisted Development

This project was developed with **Cursor IDE** and **Claude Code**. All AI-generated code has been reviewed and validated to ensure quality and correctness. 

## 📋 Output Formats

### CycloneDX 1.7 (JSON & XML)
- Individual components per dependency with PURL
- ML model components with type classification
- Evidence with file:line precision
- Relationship tracking for duplicate models

### SPDX 3.0.1 (JSON-LD)
- AIPackage elements for models
- Provider attribution and model types
- Detection method provenance
- Standards-compliant relationships

### Extended AIBOM Format (JSON)
A comprehensive format that enhances standard BOMs with industry best practices from [Snyk](https://snyk.io/articles/ai-security/ai-bill-of-materials-aibom/) and [Trail of Bits](https://blog.trailofbits.com/2024/02/28/our-response-to-the-us-armys-rfi-on-developing-aibom-tools/):

**Hardware Detection:**
- GPU/TPU/specialized compute requirements
- CUDA, TensorRT, OpenVINO detection
- Hardware libraries and dependencies

**Infrastructure & Deployment:**
- Containerization (Docker, container images)
- Orchestration (Kubernetes)
- Cloud platforms (AWS SageMaker, GCP Vertex AI, Azure ML)
- MLOps tools (MLflow, Weights & Biases, TensorBoard)

**Model Governance:**
- Documented intended use
- Limitations and constraints
- Ethical considerations
- Bias and fairness assessments
- Model provenance

**Risk Assessment:**
- Missing documentation warnings
- Security considerations
- Deprecated dependencies
- Overall risk level evaluation
- Actionable recommendations

**Data Pipeline:**
- Data loading libraries
- Preprocessing frameworks
- Feature engineering tools
- ML frameworks

**Summary Statistics:**
- Documentation completeness score
- Category breakdown
- Risk level assessment

**Analysis Notes:** *Scan-specific gaps*
- Components scanned for but not found in this repository
- Documentation: README, MODEL_CARD, SECURITY files (if missing)
- Hardware: GPU/TPU libraries (if not detected)
- Infrastructure: Docker, Kubernetes, cloud configs (if not found)
- Governance: Model documentation (if models present but no governance)
- Data Pipeline: Data processing libraries (if not detected)
- Actionable suggestions for improving AIBOM completeness

> **Note:** Analysis notes are **scan-specific** - they list what we actively searched for in THIS repository but didn't find. Not philosophical limitations, but practical gaps that could be filled.

### Standards Compliance (report section)

The **Standards Compliance** section (below the generated BOM) checks and scores the output in two halves:

**Generated documents (dynamic, per scan):** the freshly generated CycloneDX JSON and SPDX JSON-LD are validated field-by-field against their respective specifications — required/recommended fields (`serialNumber` URN format, `metadata.timestamp`, `bom-ref` uniqueness, dependency/service ref resolution, `@context`, `creationInfo`, element/relationship integrity) — plus the [NTIA "The Minimum Elements For An SBOM" (2021)](https://www.ntia.gov/report/2021/minimum-elements-software-supply-chain-security) seven-element baseline (supplier, name, version, unique identifiers, relationships, author, timestamp). Results are honest: satisfied checks report **PASS**, partially satisfied checks report **PARTIAL** with the exact tally (e.g. "1/2 components carry supplier attribution"), and missing required fields report **MISSING** — no blanket pass.

**AIBOM standards scorecard (static, per tool version):** element-by-element conformance of the tool's AIBOM output surface against CERT-In Technical Guidelines Table 10 (19 elements), the G7 Cyber Group SBOM-for-AI minimum elements (50 elements), and the OWASP AIBOM Foundations checklist (24 points), with weighted (✅ 1.0 / 🟡 0.5 / ❌ 0) and strict (✅ only) scores, per-element status, and the structural (⛔) limits of a post-hoc, browser-only scanner. Full methodology and per-element citations: `guidance/guidance_details.md` §6.

Current headline (2026-11-21 post-uplift): CERT-In **68.4%** weighted / 52.6% strict · G7 **44.0%** / 34.0% · OWASP **50.0%** / 29.2%. (The 2026-11-20 snapshot in `guidance/guidance_details.md` §6 read 65.8/45.0/50.0 weighted. Deltas are honest: model-version elements dropped to unmet because invented `latest` versions were removed per the Snyk-comparison review, while the out-of-scope-usage element rose to met — out-of-scope uses are now extracted from local model cards.)

### Identity, evidence and external services

- **Clean component identity**: library components carry real names, versions and PURLs (`pkg:pypi/langchain@0.1.13`) instead of `"Dependency: …"` with placeholder versions; model components keep the verbatim source identifier and never invent a version (unknown stays unknown).
- **Native CycloneDX evidence**: `evidence.identity` (technique `manifest-analysis` for SBOM/manifest finds, `source-code-analysis` for code finds, with confidence) and `evidence.occurrences` (file, line, snippet as `additionalContext`); SPDX exports preserve the same as package `comment`s.
- **External AI services**: cloud models emit CycloneDX `services` entries (provider, public API endpoint, authenticated) wired into the dependency graph (repo → service, model → service), documenting the third-party trust boundary.
- **Import analysis**: undeclared-but-imported AI packages (e.g. `langchain-community`, `langchain-core`) are detected directly in source (`aiImportsDetector`) and added with version unknown — closing the recall gap vs manifest-only scanning.
- **Model card schema conformance**: enrichment is emitted using the CycloneDX 1.7 `modelCard` schema names (`task`, `considerations.useCases`, `considerations.technicalLimitations`, `considerations.ethicalConsiderations`); non-schema card data rides in `modelCard.properties` under the `aibom:` namespace, including `aibom:lifecycle-status`.

## 🚀 How It Works

1. **SBOM-First Approach**: Leverages GitHub's Dependency Graph SBOM API for efficient, standardized dependency detection
2. **Automatic Fallback**: If SBOM API is unavailable, falls back to manual parsing of manifest files
3. **Smart Scanning**: Only scans file types matching detected repository languages (TypeScript → .ts/.tsx, Python → .py)
4. **Provider Detection**: Identifies which AI providers are used (OpenAI, Google, HuggingFace, etc.) based on dependencies
5. **Model Classification**: Distinguishes between LLM (text-generation), embedding models, and image generation
6. **Precise Evidence**: Tracks exact file and line number for every detection
7. **Machine-Readable**: Each dependency is a separate component, queryable and tooling-compatible

## 📊 Example Output

For a repository using LangChain with Google AI:

```json
{
  "components": [
    {
      "type": "library",
      "name": "langchain-google-genai",
      "version": "1.0.0",
      "purl": "pkg:pypi/langchain-google-genai@1.0.0",
      "properties": [
        {"name": "cdx:evidence:location:0", "value": "requirements.txt:12"}
      ]
    },
    {
      "type": "machine-learning-model",
      "author": "Google",
      "name": "models/embedding-001",
      "properties": [
        {"name": "category", "value": "embeddings"},
        {"name": "intended-use", "value": "Text embeddings for semantic search"},
        {"name": "evidence:location:1", "value": "main.py:23"}
      ]
    }
  ]
}
```

## 🛡️ Privacy & Security

- ✅ All processing in browser (no backend)
- ✅ No data sent to external servers (except GitHub API)
- ✅ Tokens never stored or transmitted
- ✅ Generated BOMs remain local

## 🌐 Browser Support

Chrome/Edge 90+, Firefox 88+, Safari 14+, Modern mobile browsers


---

## 📜 License

GNU General Public License v3 (GPLv3) - see [LICENSE](LICENSE) file for details.

## 💬 Community & Discussion

Join our Discord server for discussions, questions, and collaboration:

**[Join our Discord Server](https://discord.gg/7trkcUFrgR)**

Connect with other security researchers, share your findings, and get help with usage and development.

## 🙏 Acknowledgments

- Attempts to follow CycloneDX 1.7 and SPDX 3.0.1 specifications (not claiming full compliance)
- Inspired by the need for AI transparency in software supply chains

## ⚠️ Disclaimer

This tool is designed for security auditing and analysis of systems you own or have explicit permission to analyze. Always ensure you have proper authorization before using this tool against any systems or repositories you don't own. The authors are not responsible for any misuse of this software.

## 🔬 Cyfinoid Research

**Cutting-Edge Software Supply Chain Security Research**

Pioneering advanced software supply chain security research and developing innovative security tools for the community. This tool is part of our free research toolkit - helping security researchers and organizations identify software supply chain vulnerabilities and assess license compliance.

### 🌐 Software Supply Chain Focus

Specializing in software supply chain attacks, CI/CD pipeline security, and offensive security research. Our research tools help organizations understand their software supply chain vulnerabilities and develop effective defense strategies.

### 🎓 Learn & Explore

Explore our professional training programs, latest research insights, and free open source tools developed from our cutting-edge cybersecurity research.

**[Upcoming Trainings](https://cyfinoid.com/trainings/#upcoming-trainings)** | **[Read Our Blog](https://cyfinoid.com/blog/)** | **[Open Source by Cyfinoid](https://cyfinoid.com/opensource-by-cyfinoid/)**

Hands-on training in software supply chain security, CI/CD pipeline attacks, and offensive security techniques

© 2025 Cyfinoid Research.