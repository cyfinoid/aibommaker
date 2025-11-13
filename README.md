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
- Python: `openai`, `anthropic`, `langchain`, `transformers`, `chromadb`
- Node.js: `openai`, `@anthropic-ai/sdk`, `langchain`, `ai`

### AI Models
Identifies specific models with type classification:
- **Text Generation**: GPT-4o, Claude-3, Gemini-Pro
- **Embeddings**: text-embedding-3-large, models/embedding-001
- **Image Generation**: DALL-E-3, Stable Diffusion

### Code Usage
SDK imports and API calls with precise line numbers

### Configuration
Model names and API keys in config files

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

## 🚀 How It Works

1. **Smart Scanning**: Only scans file types matching detected repository languages (TypeScript → .ts/.tsx, Python → .py)
2. **Provider Detection**: Identifies which AI providers are used (OpenAI, Google, HuggingFace, etc.) based on dependencies
3. **Model Classification**: Distinguishes between LLM (text-generation), embedding models, and image generation
4. **Precise Evidence**: Tracks exact file and line number for every detection
5. **Machine-Readable**: Each dependency is a separate component, queryable and tooling-compatible

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