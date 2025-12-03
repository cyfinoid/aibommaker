#!/usr/bin/env python3
"""
Script to generate model cards in both Markdown and JSON formats
"""

import json
import os
from datetime import datetime

# Model definitions with provider-specific information
MODELS = [
    # OpenAI - Text Generation
    {"provider": "openai", "name": "gpt-4", "display_name": "GPT-4", "type": "text-generation", 
     "release_date": "2023-03-14", "context_length": 8192, "description": "GPT-4 is OpenAI's advanced language model with improved capabilities over GPT-3.5."},
    {"provider": "openai", "name": "gpt-3.5-turbo", "display_name": "GPT-3.5 Turbo", "type": "text-generation",
     "release_date": "2022-11-30", "context_length": 16385, "description": "GPT-3.5 Turbo is a fast and cost-effective language model optimized for chat applications."},
    {"provider": "openai", "name": "o1-preview", "display_name": "O1 Preview", "type": "text-generation",
     "release_date": "2024-09-12", "context_length": 200000, "description": "O1 Preview is OpenAI's reasoning model optimized for complex problem-solving tasks."},
    {"provider": "openai", "name": "o1-mini", "display_name": "O1 Mini", "type": "text-generation",
     "release_date": "2024-09-12", "context_length": 128000, "description": "O1 Mini is a smaller, faster version of O1 optimized for reasoning tasks."},
    
    # OpenAI - Embeddings
    {"provider": "openai", "name": "text-embedding-3-large", "display_name": "Text Embedding 3 Large", "type": "embeddings",
     "release_date": "2024-01-25", "description": "Large embedding model producing 3072-dimensional embeddings."},
    {"provider": "openai", "name": "text-embedding-3-small", "display_name": "Text Embedding 3 Small", "type": "embeddings",
     "release_date": "2024-01-25", "description": "Small embedding model producing 1536-dimensional embeddings."},
    {"provider": "openai", "name": "text-embedding-ada-002", "display_name": "Text Embedding Ada 002", "type": "embeddings",
     "release_date": "2022-12-15", "description": "Previous generation embedding model producing 1536-dimensional embeddings."},
    
    # OpenAI - Image Generation
    {"provider": "openai", "name": "dall-e-3", "display_name": "DALL-E 3", "type": "text-to-image",
     "release_date": "2023-10-01", "description": "DALL-E 3 is OpenAI's advanced text-to-image generation model with improved quality and safety."},
    {"provider": "openai", "name": "dall-e-2", "display_name": "DALL-E 2", "type": "text-to-image",
     "release_date": "2022-04-06", "description": "DALL-E 2 generates images from text descriptions with high quality and artistic capabilities."},
    
    # Anthropic
    {"provider": "anthropic", "name": "claude-3.5-sonnet", "display_name": "Claude 3.5 Sonnet", "type": "text-generation",
     "release_date": "2024-06-20", "context_length": 200000, "description": "Claude 3.5 Sonnet is Anthropic's most capable model, excelling at complex tasks and reasoning."},
    {"provider": "anthropic", "name": "claude-3-opus", "display_name": "Claude 3 Opus", "type": "text-generation",
     "release_date": "2024-03-04", "context_length": 200000, "description": "Claude 3 Opus is Anthropic's most powerful model for complex reasoning tasks."},
    {"provider": "anthropic", "name": "claude-3-sonnet", "display_name": "Claude 3 Sonnet", "type": "text-generation",
     "release_date": "2024-03-04", "context_length": 200000, "description": "Claude 3 Sonnet balances capability and speed for most tasks."},
    {"provider": "anthropic", "name": "claude-3-haiku", "display_name": "Claude 3 Haiku", "type": "text-generation",
     "release_date": "2024-03-04", "context_length": 200000, "description": "Claude 3 Haiku is Anthropic's fastest and most cost-effective model."},
    
    # Google - Gemini
    {"provider": "google", "name": "gemini-1.5-pro", "display_name": "Gemini 1.5 Pro", "type": "text-generation",
     "release_date": "2024-02-15", "context_length": 1000000, "description": "Gemini 1.5 Pro is Google's advanced multimodal model with 1M token context window."},
    {"provider": "google", "name": "gemini-1.5-flash", "display_name": "Gemini 1.5 Flash", "type": "text-generation",
     "release_date": "2024-02-15", "context_length": 1000000, "description": "Gemini 1.5 Flash is Google's fast and efficient multimodal model."},
    {"provider": "google", "name": "gemini-pro", "display_name": "Gemini Pro", "type": "text-generation",
     "release_date": "2023-12-06", "context_length": 32768, "description": "Gemini Pro is Google's general-purpose multimodal language model."},
    {"provider": "google", "name": "gemini-2.0-flash-exp", "display_name": "Gemini 2.0 Flash Experimental", "type": "text-generation",
     "release_date": "2024-12-11", "context_length": 1000000, "description": "Gemini 2.0 Flash Experimental is Google's experimental next-generation model."},
    
    # Google - Embeddings
    {"provider": "google", "name": "models/embedding-001", "display_name": "Text Embedding 001", "type": "embeddings",
     "release_date": "2023-08-01", "description": "Google's text embedding model for semantic search and similarity tasks."},
    {"provider": "google", "name": "models/text-embedding-004", "display_name": "Text Embedding 004", "type": "embeddings",
     "release_date": "2024-01-01", "description": "Google's improved text embedding model with better performance."},
    {"provider": "google", "name": "text-embedding-004", "display_name": "Text Embedding 004", "type": "embeddings",
     "release_date": "2024-01-01", "description": "Google's improved text embedding model with better performance."},
    
    # Google - Gemma
    {"provider": "google", "name": "gemma2", "display_name": "Gemma 2", "type": "text-generation",
     "release_date": "2024-05-28", "description": "Gemma 2 is Google's open-source language model family."},
    {"provider": "google", "name": "gemma3", "display_name": "Gemma 3", "type": "text-generation",
     "release_date": "2024-12-01", "description": "Gemma 3 is the latest version of Google's open-source language model family."},
    
    # Mistral
    {"provider": "mistral", "name": "mistral-large", "display_name": "Mistral Large", "type": "text-generation",
     "release_date": "2024-02-26", "context_length": 32000, "description": "Mistral Large is Mistral AI's flagship model for complex reasoning tasks."},
    {"provider": "mistral", "name": "mixtral-8x7b", "display_name": "Mixtral 8x7B", "type": "text-generation",
     "release_date": "2024-01-08", "context_length": 32000, "description": "Mixtral 8x7B is a sparse mixture-of-experts model with high performance."},
    {"provider": "mistral", "name": "mistral", "display_name": "Mistral", "type": "text-generation",
     "release_date": "2023-09-27", "context_length": 8192, "description": "Mistral is Mistral AI's base language model."},
    {"provider": "mistral", "name": "mathstral", "display_name": "Mathstral", "type": "text-generation",
     "release_date": "2024-01-01", "description": "Mathstral is Mistral AI's model specialized for mathematical reasoning."},
    
    # Cohere
    {"provider": "cohere", "name": "command-r7b-arabic", "display_name": "Command R7B Arabic", "type": "text-generation",
     "release_date": "2024-01-01", "description": "Command R7B Arabic is Cohere's model optimized for Arabic language tasks."},
    {"provider": "cohere", "name": "command-r-plus", "display_name": "Command R Plus", "type": "text-generation",
     "release_date": "2024-03-01", "description": "Command R Plus is Cohere's advanced model for enterprise RAG applications."},
    {"provider": "cohere", "name": "command-r", "display_name": "Command R", "type": "text-generation",
     "release_date": "2024-03-01", "description": "Command R is Cohere's model optimized for retrieval-augmented generation."},
    {"provider": "cohere", "name": "command-a", "display_name": "Command A", "type": "text-generation",
     "release_date": "2024-01-01", "description": "Command A is Cohere's model for general-purpose tasks."},
    
    # Meta
    {"provider": "meta", "name": "llama3.3", "display_name": "Llama 3.3", "type": "text-generation",
     "release_date": "2024-12-01", "description": "Llama 3.3 is Meta's latest open-source language model."},
    {"provider": "meta", "name": "llama3.2", "display_name": "Llama 3.2", "type": "text-generation",
     "release_date": "2024-09-12", "description": "Llama 3.2 is Meta's improved open-source language model."},
    {"provider": "meta", "name": "llama3.1", "display_name": "Llama 3.1", "type": "text-generation",
     "release_date": "2024-07-23", "description": "Llama 3.1 is Meta's open-source language model with improved capabilities."},
    {"provider": "meta", "name": "llama3", "display_name": "Llama 3", "type": "text-generation",
     "release_date": "2024-04-18", "description": "Llama 3 is Meta's open-source language model family."},
    {"provider": "meta", "name": "codellama", "display_name": "Code Llama", "type": "text-generation",
     "release_date": "2023-08-24", "description": "Code Llama is Meta's open-source model specialized for code generation."},
    {"provider": "meta", "name": "medllama2", "display_name": "MedLlama2", "type": "text-generation",
     "release_date": "2023-01-01", "description": "MedLlama2 is a medical domain-specific variant of Llama 2."},
    
    # DeepSeek
    {"provider": "deepseek", "name": "deepseek-coder-v2", "display_name": "DeepSeek Coder V2", "type": "text-generation",
     "release_date": "2024-01-01", "description": "DeepSeek Coder V2 is DeepSeek's advanced code generation model."},
    {"provider": "deepseek", "name": "deepseek-r1", "display_name": "DeepSeek R1", "type": "text-generation",
     "release_date": "2024-01-01", "description": "DeepSeek R1 is DeepSeek's reasoning model."},
    {"provider": "deepseek", "name": "deepseek-v3", "display_name": "DeepSeek V3", "type": "text-generation",
     "release_date": "2024-01-01", "description": "DeepSeek V3 is DeepSeek's latest general-purpose language model."},
    
    # Alibaba
    {"provider": "alibaba", "name": "qwen2.5", "display_name": "Qwen2.5", "type": "text-generation",
     "release_date": "2024-01-01", "description": "Qwen2.5 is Alibaba's open-source language model."},
    {"provider": "alibaba", "name": "qwen2.5-coder", "display_name": "Qwen2.5 Coder", "type": "text-generation",
     "release_date": "2024-01-01", "description": "Qwen2.5 Coder is Alibaba's code generation model."},
    {"provider": "alibaba", "name": "qwq", "display_name": "QWQ", "type": "text-generation",
     "release_date": "2024-01-01", "description": "QWQ is Alibaba's specialized model."},
    
    # Microsoft
    {"provider": "microsoft", "name": "phi4", "display_name": "Phi-4", "type": "text-generation",
     "release_date": "2024-01-01", "description": "Phi-4 is Microsoft's small language model optimized for efficiency."},
    {"provider": "microsoft", "name": "phi3", "display_name": "Phi-3", "type": "text-generation",
     "release_date": "2024-04-23", "description": "Phi-3 is Microsoft's small language model family."},
    
    # EPFL
    {"provider": "epfl", "name": "meditron", "display_name": "Meditron", "type": "text-generation",
     "release_date": "2023-01-01", "description": "Meditron is EPFL's medical language model based on Llama 2."},
    
    # 01.AI
    {"provider": "01ai", "name": "yi", "display_name": "Yi", "type": "text-generation",
     "release_date": "2023-11-01", "description": "Yi is 01.AI's open-source language model family."},
    
    # Nexusflow
    {"provider": "nexusflow", "name": "athene-v2", "display_name": "Athene V2", "type": "text-generation",
     "release_date": "2024-01-01", "description": "Athene V2 is Nexusflow's specialized model."},
]

def get_provider_info(provider):
    """Get provider-specific information"""
    provider_info = {
        "openai": {
            "api_url": "https://api.openai.com",
            "docs_url": "https://platform.openai.com/docs",
            "pricing_url": "https://openai.com/pricing",
            "licensing": "Proprietary. Usage subject to OpenAI's Terms of Service."
        },
        "anthropic": {
            "api_url": "https://api.anthropic.com",
            "docs_url": "https://docs.anthropic.com",
            "pricing_url": "https://www.anthropic.com/pricing",
            "licensing": "Proprietary. Usage subject to Anthropic's Terms of Service."
        },
        "google": {
            "api_url": "https://generativelanguage.googleapis.com",
            "docs_url": "https://ai.google.dev/docs",
            "pricing_url": "https://ai.google.dev/pricing",
            "licensing": "Varies by model. Check Google AI documentation."
        },
        "mistral": {
            "api_url": "https://api.mistral.ai",
            "docs_url": "https://docs.mistral.ai",
            "pricing_url": "https://mistral.ai/pricing",
            "licensing": "Varies by model. Check Mistral AI documentation."
        },
        "cohere": {
            "api_url": "https://api.cohere.ai",
            "docs_url": "https://docs.cohere.com",
            "pricing_url": "https://cohere.com/pricing",
            "licensing": "Proprietary. Usage subject to Cohere's Terms of Service."
        },
        "meta": {
            "api_url": None,
            "docs_url": "https://llama.meta.com",
            "pricing_url": None,
            "licensing": "Open source. Check model-specific license (typically Llama 3 Community License or Apache 2.0)."
        },
        "deepseek": {
            "api_url": None,
            "docs_url": "https://github.com/deepseek-ai",
            "pricing_url": None,
            "licensing": "Open source. Check model-specific license."
        },
        "alibaba": {
            "api_url": None,
            "docs_url": "https://github.com/QwenLM/Qwen",
            "pricing_url": None,
            "licensing": "Open source. Apache 2.0 License."
        },
        "microsoft": {
            "api_url": None,
            "docs_url": "https://github.com/microsoft",
            "pricing_url": None,
            "licensing": "Open source. MIT License."
        },
        "epfl": {
            "api_url": None,
            "docs_url": "https://github.com/epfLLM/meditron",
            "pricing_url": None,
            "licensing": "Open source. Check model-specific license."
        },
        "01ai": {
            "api_url": None,
            "docs_url": "https://github.com/01-ai/Yi",
            "pricing_url": None,
            "licensing": "Open source. Apache 2.0 License."
        },
        "nexusflow": {
            "api_url": None,
            "docs_url": "https://github.com/nexusflowai",
            "pricing_url": None,
            "licensing": "Check model-specific license."
        }
    }
    return provider_info.get(provider, {})

def generate_markdown(model):
    """Generate Markdown model card with only factual information from official sources"""
    provider_info = get_provider_info(model["provider"])
    provider_display = model["provider"].title().replace("01ai", "01.AI")
    
    md = f"""# Model Card: {model['display_name']}

## Model Details

- **Model Name**: {model['display_name']}
- **Provider**: {provider_display}
- **Model Type**: {model['type']}
- **Model ID**: {model['name']}

## Model Description

**Note**: Model description and detailed information should be obtained from official provider documentation. See References section below.

## Intended Use

**Note**: Intended use cases and limitations should be verified from official provider documentation. See References section below.

## Model Architecture

"""
    
    if 'context_length' in model:
        md += f"- **Context Length**: {model['context_length']:,} tokens (as stated in official documentation)\n"
    else:
        md += "- **Context Length**: See official documentation\n"
    
    md += "- **Architecture Details**: See official documentation\n"

    md += """
## Training Data

Training data details are not publicly disclosed for most SaaS models. For open-source models, check the official documentation or model repository.

## Training Procedure

Training methodology details are proprietary and not publicly disclosed for SaaS models. For open-source models, check official documentation or research papers.

## Evaluation

### Evaluation Data
See official provider documentation for evaluation data and benchmarks.

### Metrics
See official provider documentation for specific performance metrics and evaluation results.

### Performance Summary
See official provider documentation for performance characteristics and benchmarks.
"""

    md += """
## Limitations

**Note**: Specific limitations should be verified from official provider documentation. Common limitations may include:
- May generate incorrect or biased information
- Knowledge cutoff may not include recent events
- Performance may vary across different languages and domains
"""

    if provider_info.get('api_url'):
        md += "- Rate limits apply for API access\n"

    md += """
## Ethical Considerations

### Bias and Fairness
See official provider documentation for information on bias and fairness evaluations.

### Safety Measures
See official provider documentation for information on safety measures and content filtering.

### Privacy Considerations
For API-based models, review provider's privacy policy. Sensitive data should not be sent without appropriate safeguards.
"""

    md += f"""
## Access and Usage

"""
    
    if provider_info.get('api_url'):
        md += f"""### API Access
Available through {provider_display}'s API. See official documentation for API endpoint details.

### Rate Limits
See {provider_display}'s official documentation for current rate limits.

### Pricing
See {provider_info.get('pricing_url', provider_info.get('docs_url', 'provider website'))} for current pricing information.

"""
    else:
        md += f"""### Access
See {provider_display}'s official documentation for download and usage instructions.

### Deployment
See official documentation for hardware requirements and deployment instructions.

"""
    
    md += f"""### Licensing
{provider_info.get('licensing', 'See official documentation for licensing information.')}
"""

    md += """
## Hardware and Software Requirements

"""
    
    if provider_info.get('api_url'):
        md += """- **API Access**: Internet connection required
- **SDK**: See official documentation for supported SDKs
"""
    else:
        md += """- **Hardware**: See official documentation for hardware requirements
- **Software**: See official documentation for software dependencies
"""

    md += f"""
## References

**IMPORTANT**: All information in this model card should be verified against official provider documentation. The following are official sources:

- {provider_display} Official Documentation: {provider_info.get('docs_url', 'See provider website')}
"""
    
    if provider_info.get('api_url'):
        md += f"- {provider_display} API Documentation: {provider_info.get('docs_url', provider_info.get('api_url', 'See provider website'))}\n"
    if provider_info.get('pricing_url'):
        md += f"- {provider_display} Pricing: {provider_info['pricing_url']}\n"

    md += f"""
## Citation

See official {provider_display} documentation for citation information.
"""

    md += """
## Additional Information

**IMPORTANT DISCLAIMER**: 

This model card is created based on publicly available information from official provider sources. For SaaS-based services, we don't have direct API access but use various documents provided by service providers. 

**All information should be verified against the official provider documentation referenced above.** Some technical details may be limited or unavailable due to the proprietary nature of SaaS models.

For the most accurate and up-to-date information, please refer to the official provider documentation listed in the References section.

## Last Updated

""" + datetime.now().strftime("%Y-%m-%d")
    
    return md

def generate_json(model):
    """Generate JSON model card with only factual information from official sources"""
    provider_info = get_provider_info(model["provider"])
    provider_display = model["provider"].title().replace("01ai", "01.AI")
    
    json_data = {
        "modelName": model['display_name'],
        "provider": provider_display,
        "modelType": model['type'],
        "modelId": model['name'],
        "description": "Model description and detailed information should be obtained from official provider documentation. See references section.",
        "intendedUse": {
            "note": "Intended use cases and limitations should be verified from official provider documentation. See references section."
        },
        "architecture": {
            "note": "Architecture details should be verified from official provider documentation."
        },
        "trainingData": {
            "description": "Training data details are not publicly disclosed for most SaaS models. For open-source models, check the official documentation or model repository."
        },
        "trainingProcedure": "Training methodology details are proprietary and not publicly disclosed for SaaS models. For open-source models, check official documentation or research papers.",
        "evaluation": {
            "evaluationData": "See official provider documentation for evaluation data and benchmarks.",
            "metrics": {
                "note": "See official provider documentation for specific performance metrics and evaluation results."
            },
            "performanceSummary": "See official provider documentation for performance characteristics and benchmarks."
        },
        "limitations": {
            "note": "Specific limitations should be verified from official provider documentation. Common limitations may include: may generate incorrect or biased information, knowledge cutoff may not include recent events, performance may vary across different languages and domains."
        },
        "ethicalConsiderations": {
            "biasAndFairness": "See official provider documentation for information on bias and fairness evaluations.",
            "safetyMeasures": "See official provider documentation for information on safety measures and content filtering.",
            "privacyConsiderations": "For API-based models, review provider's privacy policy. Sensitive data should not be sent without appropriate safeguards."
        },
        "access": {
            "licensing": provider_info.get('licensing', 'See official documentation for licensing information.')
        },
        "requirements": {
            "hardware": "See official documentation for hardware requirements" if not provider_info.get('api_url') else "API Access: Internet connection required",
            "software": ["See official documentation for software dependencies"] if not provider_info.get('api_url') else ["See official documentation for supported SDKs"]
        },
        "references": {
            "important": "All information in this model card should be verified against official provider documentation.",
            "officialDocs": provider_info.get('docs_url', 'See provider website')
        },
        "citation": f"See official {provider_display} documentation for citation information.",
        "additionalInfo": "IMPORTANT DISCLAIMER: This model card is created based on publicly available information from official provider sources. For SaaS-based services, we don't have direct API access but use various documents provided by service providers. All information should be verified against the official provider documentation referenced above. Some technical details may be limited or unavailable due to the proprietary nature of SaaS models.",
        "lastUpdated": datetime.now().strftime("%Y-%m-%d")
    }
    
    if 'context_length' in model:
        json_data["architecture"]["contextLength"] = f"{model['context_length']:,} tokens (as stated in official documentation)"
    
    if provider_info.get('api_url'):
        json_data["access"]["apiAccess"] = f"Available through {provider_display}'s API. See documentation for API endpoint details."
        json_data["access"]["rateLimits"] = f"See {provider_display}'s official documentation for current rate limits."
        json_data["access"]["pricing"] = f"See {provider_info.get('pricing_url', provider_info.get('docs_url', 'provider website'))} for current pricing information."
        json_data["references"]["apiDocs"] = provider_info.get('docs_url', provider_info.get('api_url', 'See provider website'))
    else:
        json_data["access"]["access"] = f"See {provider_display}'s official documentation for download and usage instructions."
        json_data["access"]["deployment"] = "See official documentation for hardware requirements and deployment instructions."
    
    if provider_info.get('pricing_url'):
        json_data["references"]["pricing"] = provider_info['pricing_url']
    
    return json_data

def main():
    """Generate all model cards"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    for model in MODELS:
        provider_dir = os.path.join(base_dir, model["provider"])
        os.makedirs(provider_dir, exist_ok=True)
        
        # Sanitize model name for filename (replace slashes with hyphens)
        safe_name = model['name'].replace('/', '-')
        
        # Generate Markdown
        md_content = generate_markdown(model)
        md_file = os.path.join(provider_dir, f"{safe_name}.md")
        with open(md_file, 'w') as f:
            f.write(md_content)
        print(f"Generated: {md_file}")
        
        # Generate JSON
        json_data = generate_json(model)
        json_file = os.path.join(provider_dir, f"{safe_name}.json")
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"Generated: {json_file}")

if __name__ == "__main__":
    main()

