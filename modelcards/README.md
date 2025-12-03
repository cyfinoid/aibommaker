# Model Cards Directory

This directory contains model cards for all AI/LLM models detected by the AI BOM Generator tool. Model cards are provided in both Markdown (human-readable) and JSON (machine-readable) formats.

## Structure

```
modelcards/
├── README.md (this file)
├── modelcard-info.md (research notes and references)
├── template.md (Markdown template)
├── template.json (JSON schema template)
├── template.yaml (YAML schema template)
├── generate_cards.py (script to generate model cards)
├── openai/ (OpenAI models)
├── anthropic/ (Anthropic models)
├── google/ (Google models)
├── mistral/ (Mistral AI models)
├── cohere/ (Cohere models)
├── meta/ (Meta/Llama models)
├── deepseek/ (DeepSeek models)
├── alibaba/ (Alibaba/Qwen models)
├── microsoft/ (Microsoft/Phi models)
├── epfl/ (EPFL models)
├── 01ai/ (01.AI/Yi models)
├── nexusflow/ (Nexusflow models)
└── huggingface/ (HuggingFace models - template/guide)
```

## Model Card Format

Each model card follows a standardized format based on:
- Google Model Cards standard
- HuggingFace Model Card format
- Industry best practices from OECD, IAPP, and other organizations

### Standard Sections

1. **Model Details**: Name, provider, type, version, release date
2. **Model Description**: Brief overview of the model
3. **Intended Use**: Primary use cases and out-of-scope applications
4. **Model Architecture**: Architecture type, context length, parameters
5. **Training Data**: Information about training datasets
6. **Training Procedure**: Training methodology
7. **Evaluation**: Evaluation data, metrics, performance summary
8. **Limitations**: Known constraints and limitations
9. **Ethical Considerations**: Bias, fairness, safety, privacy
10. **Access and Usage**: API access, rate limits, pricing, licensing
11. **Hardware and Software Requirements**: Deployment requirements
12. **References**: Links to official documentation
13. **Citation**: How to cite the model
14. **Additional Information**: Notes and disclaimers

## Model Coverage

This directory contains model cards for **50+ models** across multiple providers:

- **OpenAI**: 10 models (GPT-4o, GPT-4, GPT-3.5 Turbo, O1 series, embeddings, DALL-E)
- **Anthropic**: 4 models (Claude 3.5 Sonnet, Claude 3 Opus/Sonnet/Haiku)
- **Google**: 9 models (Gemini series, Gemma, embeddings)
- **Mistral**: 4 models (Mistral Large, Mixtral, Mathstral)
- **Cohere**: 4 models (Command R/R Plus/A, Command R7B Arabic)
- **Meta**: 6 models (Llama 3.x series, Code Llama, MedLlama2)
- **DeepSeek**: 3 models (DeepSeek Coder V2, R1, V3)
- **Alibaba**: 3 models (Qwen2.5, Qwen2.5 Coder, QWQ)
- **Microsoft**: 2 models (Phi-3, Phi-4)
- **EPFL**: 1 model (Meditron)
- **01.AI**: 1 model (Yi)
- **Nexusflow**: 1 model (Athene V2)
- **HuggingFace**: Template/guide (models are dynamically detected)

## File Naming Convention

- Markdown files: `{model-name}.md`
- JSON files: `{model-name}.json`
- Model names are normalized (lowercase, hyphens for separators)
- Slashes in model names are replaced with hyphens in filenames (e.g., `models/embedding-001` → `models-embedding-001.md`)

## Usage

### Reading Model Cards

- **Markdown format**: Open `.md` files in any text editor or markdown viewer
- **JSON format**: Parse `.json` files programmatically or view in JSON viewers

### Generating New Model Cards

Use the `generate_cards.py` script to generate model cards:

```bash
python3 generate_cards.py
```

To add a new model, edit the `MODELS` list in `generate_cards.py` and run the script.

## Important Notes

### SaaS Models

For SaaS-based services (OpenAI, Anthropic, Google, Mistral, Cohere), we don't have direct API access but use various documents provided by service providers to create model cards. Some technical details may be limited due to the proprietary nature of these models.

### Open Source Models

For open-source models (Meta, DeepSeek, Alibaba, Microsoft, etc.), model cards are based on publicly available documentation, research papers, and model repositories. More detailed information may be available in official documentation.

### HuggingFace Models

HuggingFace models are dynamically detected in code. Individual model cards are not created for each HuggingFace model, but a template/guide is provided. Users should refer to HuggingFace's model card format and individual model pages on the HuggingFace Hub.

## References

See `modelcard-info.md` for research references and standards used in creating these model cards.

## Last Updated

2025-01-27

