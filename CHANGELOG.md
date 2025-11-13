# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1] - 2025-01-XX

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

