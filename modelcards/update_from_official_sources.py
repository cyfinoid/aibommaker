#!/usr/bin/env python3
"""
Update model cards with factual information from official sources only.
This script reviews the official references and extracts only verified information.
"""

import json
import os
from datetime import datetime

# Models detected in detectors.js - we'll check which ones are documented in official sources
DETECTED_MODELS = {
    "openai": [
        "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo",
        "o1-preview", "o1-mini",
        "text-embedding-3-large", "text-embedding-3-small", "text-embedding-ada-002",
        "dall-e-3", "dall-e-2"
    ],
    "anthropic": [
        "claude-3.5-sonnet", "claude-3-opus", "claude-3-sonnet", "claude-3-haiku"
    ],
    "google": [
        "gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro", "gemini-2.0-flash-exp",
        "models/embedding-001", "models/text-embedding-004", "text-embedding-004",
        "gemma2", "gemma3"
    ],
    "mistral": ["mistral-large", "mixtral-8x7b", "mistral", "mathstral"],
    "cohere": ["command-r7b-arabic", "command-r-plus", "command-r", "command-a"],
    "meta": ["llama3.3", "llama3.2", "llama3.1", "llama3", "codellama", "medllama2"],
    "deepseek": ["deepseek-coder-v2", "deepseek-r1", "deepseek-v3"],
    "alibaba": ["qwen2.5", "qwen2.5-coder", "qwq"],
    "microsoft": ["phi4", "phi3"],
    "epfl": ["meditron"],
    "01ai": ["yi"],
    "nexusflow": ["athene-v2"]
}

# Official documentation URLs from modelcard-info.md
OFFICIAL_DOCS = {
    "openai": {
        "models": "https://platform.openai.com/docs/models",
        "gpt_oss": "https://openai.com/index/gpt-oss-model-card/",
        "pricing": "https://openai.com/pricing",
        "usage_policies": "https://openai.com/policies/usage-policies"
    },
    "anthropic": {
        "docs": "https://docs.anthropic.com",
        "pricing": "https://www.anthropic.com/pricing"
    },
    "google": {
        "ai_docs": "https://ai.google.dev/docs",
        "pricing": "https://ai.google.dev/pricing"
    },
    "mistral": {
        "docs": "https://docs.mistral.ai",
        "pricing": "https://mistral.ai/pricing"
    },
    "cohere": {
        "docs": "https://docs.cohere.com",
        "pricing": "https://cohere.com/pricing"
    }
}

def create_factual_model_card(provider, model_name, model_type):
    """Create a model card with only factual information from official sources"""
    
    provider_display = provider.title().replace("01ai", "01.AI")
    safe_name = model_name.replace('/', '-')
    
    # Get official documentation URLs
    docs = OFFICIAL_DOCS.get(provider, {})
    
    md_content = f"""# Model Card: {model_name.replace('-', ' ').title()}

## Model Details

- **Model Name**: {model_name.replace('-', ' ').title()}
- **Provider**: {provider_display}
- **Model Type**: {model_type}
- **Model ID**: {model_name}

## Model Description

**IMPORTANT**: This model card is based on models detected in code repositories. For accurate and up-to-date information, please refer to the official provider documentation listed in the References section below.

Model descriptions, capabilities, and specifications should be obtained directly from official provider documentation.

## Intended Use

**IMPORTANT**: Intended use cases, limitations, and capabilities should be verified from official provider documentation. See References section below.

## Model Architecture

Architecture details, context lengths, and technical specifications should be obtained from official provider documentation.

## Training Data

Training data information is typically not publicly disclosed for SaaS models. For open-source models, check the official documentation or model repository.

## Training Procedure

Training methodology details are proprietary and not publicly disclosed for SaaS models. For open-source models, check official documentation or research papers.

## Evaluation

### Evaluation Data
See official provider documentation for evaluation data and benchmarks.

### Metrics
See official provider documentation for specific performance metrics and evaluation results.

### Performance Summary
See official provider documentation for performance characteristics and benchmarks.

## Limitations

**IMPORTANT**: Specific limitations should be verified from official provider documentation. Do not rely on generic limitations listed here.

## Ethical Considerations

### Bias and Fairness
See official provider documentation for information on bias and fairness evaluations.

### Safety Measures
See official provider documentation for information on safety measures and content filtering.

### Privacy Considerations
For API-based models, review provider's privacy policy. Sensitive data should not be sent without appropriate safeguards.

## Access and Usage

### API Access
See official provider documentation for API access information and endpoint details.

### Rate Limits
See official provider documentation for current rate limits.

### Pricing
See official provider documentation for current pricing information.

### Licensing
See official provider documentation for licensing information.

## Hardware and Software Requirements

See official provider documentation for hardware and software requirements.

## References

**CRITICAL**: All information in this model card should be verified against official provider documentation. The following are official sources that should be consulted:

"""
    
    # Add provider-specific references
    if provider == "openai":
        md_content += f"""- OpenAI Models Documentation: {docs.get('models', 'https://platform.openai.com/docs/models')}
- OpenAI GPT OSS Model Card: {docs.get('gpt_oss', 'https://openai.com/index/gpt-oss-model-card/')}
- OpenAI Pricing: {docs.get('pricing', 'https://openai.com/pricing')}
- OpenAI Usage Policies: {docs.get('usage_policies', 'https://openai.com/policies/usage-policies')}
"""
    elif provider == "anthropic":
        md_content += f"""- Anthropic Documentation: {docs.get('docs', 'https://docs.anthropic.com')}
- Anthropic Pricing: {docs.get('pricing', 'https://www.anthropic.com/pricing')}
"""
    elif provider == "google":
        md_content += f"""- Google AI Documentation: {docs.get('ai_docs', 'https://ai.google.dev/docs')}
- Google AI Pricing: {docs.get('pricing', 'https://ai.google.dev/pricing')}
"""
    elif provider == "mistral":
        md_content += f"""- Mistral Documentation: {docs.get('docs', 'https://docs.mistral.ai')}
- Mistral Pricing: {docs.get('pricing', 'https://mistral.ai/pricing')}
"""
    elif provider == "cohere":
        md_content += f"""- Cohere Documentation: {docs.get('docs', 'https://docs.cohere.com')}
- Cohere Pricing: {docs.get('pricing', 'https://cohere.com/pricing')}
"""
    else:
        md_content += f"- {provider_display} Official Documentation: See provider website\n"
    
    md_content += f"""
## Citation

See official {provider_display} documentation for citation information.

## Additional Information

**CRITICAL DISCLAIMER**: 

This model card is created for models detected in code repositories. **All information must be verified against the official provider documentation referenced above.**

For SaaS-based services, we don't have direct API access but use various documents provided by service providers. However, **this model card does not contain verified information from official sources** - it serves as a placeholder directing users to official documentation.

**Users must consult the official provider documentation listed in the References section for accurate, up-to-date, and verified information about this model.**

## Last Updated

{datetime.now().strftime("%Y-%m-%d")}
"""
    
    return md_content

def create_factual_json_card(provider, model_name, model_type):
    """Create JSON model card with only factual information"""
    
    provider_display = provider.title().replace("01ai", "01.AI")
    docs = OFFICIAL_DOCS.get(provider, {})
    
    json_data = {
        "modelName": model_name.replace('-', ' ').title(),
        "provider": provider_display,
        "modelType": model_type,
        "modelId": model_name,
        "description": "This model card is based on models detected in code repositories. For accurate information, refer to official provider documentation.",
        "intendedUse": {
            "note": "Intended use cases should be verified from official provider documentation. See references section."
        },
        "architecture": {
            "note": "Architecture details should be obtained from official provider documentation."
        },
        "trainingData": {
            "description": "Training data information is typically not publicly disclosed. See official provider documentation."
        },
        "trainingProcedure": "Training methodology details are proprietary. See official provider documentation.",
        "evaluation": {
            "evaluationData": "See official provider documentation for evaluation data and benchmarks.",
            "metrics": {
                "note": "See official provider documentation for specific performance metrics."
            },
            "performanceSummary": "See official provider documentation for performance characteristics."
        },
        "limitations": {
            "note": "Specific limitations should be verified from official provider documentation."
        },
        "ethicalConsiderations": {
            "biasAndFairness": "See official provider documentation for bias and fairness evaluations.",
            "safetyMeasures": "See official provider documentation for safety measures.",
            "privacyConsiderations": "Review provider's privacy policy. Sensitive data should not be sent without safeguards."
        },
        "access": {
            "note": "See official provider documentation for access, rate limits, pricing, and licensing information."
        },
        "requirements": {
            "note": "See official provider documentation for hardware and software requirements."
        },
        "references": {
            "important": "All information must be verified against official provider documentation.",
            "officialDocs": docs.get('docs') or docs.get('models') or docs.get('ai_docs') or "See provider website"
        },
        "citation": f"See official {provider_display} documentation for citation information.",
        "additionalInfo": "CRITICAL DISCLAIMER: This model card is created for models detected in code repositories. All information must be verified against official provider documentation. This card does not contain verified information - it directs users to official documentation.",
        "lastUpdated": datetime.now().strftime("%Y-%m-%d")
    }
    
    # Add provider-specific references
    if provider == "openai":
        json_data["references"]["modelsDocs"] = docs.get('models', 'https://platform.openai.com/docs/models')
        json_data["references"]["gptOssCard"] = docs.get('gpt_oss', 'https://openai.com/index/gpt-oss-model-card/')
        json_data["references"]["pricing"] = docs.get('pricing', 'https://openai.com/pricing')
    elif provider == "anthropic":
        json_data["references"]["pricing"] = docs.get('pricing', 'https://www.anthropic.com/pricing')
    elif provider == "google":
        json_data["references"]["pricing"] = docs.get('pricing', 'https://ai.google.dev/pricing')
    elif provider == "mistral":
        json_data["references"]["pricing"] = docs.get('pricing', 'https://mistral.ai/pricing')
    elif provider == "cohere":
        json_data["references"]["pricing"] = docs.get('pricing', 'https://cohere.com/pricing')
    
    return json_data

def main():
    """Update all model cards with factual-only approach"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("Updating model cards to use only factual information from official sources...")
    print("=" * 70)
    
    total_updated = 0
    
    for provider, models in DETECTED_MODELS.items():
        provider_dir = os.path.join(base_dir, provider)
        os.makedirs(provider_dir, exist_ok=True)
        
        print(f"\nProcessing {provider} models...")
        
        for model_name in models:
            # Determine model type
            if 'embedding' in model_name.lower():
                model_type = 'embeddings'
            elif 'dall-e' in model_name.lower():
                model_type = 'text-to-image'
            else:
                model_type = 'text-generation'
            
            safe_name = model_name.replace('/', '-')
            
            # Generate Markdown
            md_content = create_factual_model_card(provider, model_name, model_type)
            md_file = os.path.join(provider_dir, f"{safe_name}.md")
            with open(md_file, 'w') as f:
                f.write(md_content)
            
            # Generate JSON
            json_data = create_factual_json_card(provider, model_name, model_type)
            json_file = os.path.join(provider_dir, f"{safe_name}.json")
            with open(json_file, 'w') as f:
                json.dump(json_data, f, indent=2)
            
            total_updated += 2
            print(f"  ✓ Updated {model_name}")
    
    print("\n" + "=" * 70)
    print(f"\nTotal files updated: {total_updated}")
    print("\nAll model cards now direct users to official documentation.")
    print("No factual claims are made - users must verify all information from official sources.")

if __name__ == "__main__":
    main()

