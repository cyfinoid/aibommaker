# HuggingFace Model Cards

## Overview

HuggingFace models are dynamically detected in code repositories. Individual model cards are not pre-generated for HuggingFace models because:

1. There are thousands of models on the HuggingFace Hub
2. Models are frequently added, updated, or removed
3. Each model has its own model card on the HuggingFace Hub

## Using HuggingFace Model Cards

### Finding Model Cards

When a HuggingFace model is detected in code (e.g., `"microsoft/DialoGPT-medium"` or `"hf.co/bert-base-uncased"`), refer to:

1. **HuggingFace Hub**: https://huggingface.co/models (replace `{model-id}` with actual model identifier, e.g., `microsoft/DialoGPT-medium`)
   - Each model page includes a model card in the README.md
   - Contains model details, usage examples, limitations, etc.

2. **Model Card Format**: HuggingFace uses a YAML frontmatter + Markdown format
   - See: https://huggingface.co/docs/hub/model-cards

### HuggingFace Model Card Format

HuggingFace model cards typically include:

```yaml
---
license: apache-2.0
tags:
- text-generation
- pytorch
- transformer
---

# Model Card for {Model Name}

## Model Details

- **Model Type**: {type}
- **Language**: {language}
- **License**: {license}

## Model Description

{description}

## Intended Use

{intended use cases}

## Training Data

{training data information}

## Evaluation Results

{evaluation metrics}

## Limitations and Bias

{limitations}

## Citation

{citation}
```

### Example

For a detected model like `"microsoft/DialoGPT-medium"`:
- Model card: https://huggingface.co/microsoft/DialoGPT-medium
- Contains full model card with all details

## Integration with AI BOM Generator

When the AI BOM Generator detects a HuggingFace model:

1. The model is identified with provider: "HuggingFace"
2. The model name is extracted (e.g., `microsoft/DialoGPT-medium`)
3. Users should refer to the HuggingFace Hub for the complete model card
4. The AI BOM will include a reference to the HuggingFace model page

## Creating Model Cards for HuggingFace Models

If you need to create a local model card for a specific HuggingFace model:

1. Use the template in the parent directory (`../template.md` or `../template.json`)
2. Fill in information from the HuggingFace Hub model page
3. Save as `huggingface/{model-name-sanitized}.md` and `.json`

## References

- HuggingFace Model Cards Documentation: https://huggingface.co/docs/hub/model-cards
- HuggingFace Hub: https://huggingface.co/models
- Model Card Template: https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/templates/modelcard_template.md

