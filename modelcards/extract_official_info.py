#!/usr/bin/env python3
"""
Script to extract factual information from official model card references
"""

import json
import re
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# Official references from modelcard-info.md
REFERENCES = {
    "openai_models": "https://platform.openai.com/docs/models",
    "openai_gpt_oss": "https://openai.com/index/gpt-oss-model-card/",
    "google_model_cards": "https://modelcards.withgoogle.com/model-cards",
    "huggingface": "https://huggingface.co/docs/hub/model-cards",
    "anthropic": "https://docs.anthropic.com",
    "google_ai": "https://ai.google.dev/docs",
}

def fetch_url_content(url):
    """Fetch content from URL"""
    try:
        req = Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (compatible; ModelCardExtractor/1.0)')
        with urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8', errors='ignore')
    except (URLError, HTTPError, Exception) as e:
        print(f"  Error fetching {url}: {e}")
        return None

def extract_openai_models(content):
    """Extract model information from OpenAI documentation"""
    models = {}
    if not content:
        return models
    
    # Look for model names in the content
    # Pattern: gpt-4o, gpt-4-turbo, gpt-3.5-turbo, etc.
    model_patterns = [
        r'gpt-4o(?:-mini)?',
        r'gpt-4(?:-turbo)?',
        r'gpt-3\.5-turbo',
        r'o1(?:-preview|-mini)?',
        r'text-embedding-3-(?:large|small)',
        r'text-embedding-ada-002',
        r'dall-e-[23]',
    ]
    
    for pattern in model_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            model_id = matches[0].lower()
            models[model_id] = {
                "source": "openai_models",
                "found": True
            }
    
    return models

def extract_anthropic_models(content):
    """Extract model information from Anthropic documentation"""
    models = {}
    if not content:
        return models
    
    # Look for Claude models
    claude_patterns = [
        r'claude-3\.5-sonnet',
        r'claude-3-opus',
        r'claude-3-sonnet',
        r'claude-3-haiku',
    ]
    
    for pattern in claude_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            model_id = matches[0].lower()
            models[model_id] = {
                "source": "anthropic",
                "found": True
            }
    
    return models

def extract_google_models(content):
    """Extract model information from Google documentation"""
    models = {}
    if not content:
        return models
    
    # Look for Gemini models
    gemini_patterns = [
        r'gemini-1\.5-pro',
        r'gemini-1\.5-flash',
        r'gemini-pro',
        r'gemini-2\.0-flash-exp',
        r'gemma[23]',
    ]
    
    for pattern in gemini_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            model_id = matches[0].lower()
            models[model_id] = {
                "source": "google_ai",
                "found": True
            }
    
    return models

def main():
    """Extract information from official references"""
    print("Reviewing official references from modelcard-info.md...")
    print("=" * 60)
    
    all_models = {}
    
    # Check OpenAI references
    print("\n1. Checking OpenAI documentation...")
    for ref_name, url in [("openai_models", REFERENCES["openai_models"]), 
                          ("openai_gpt_oss", REFERENCES["openai_gpt_oss"])]:
        print(f"   Fetching {ref_name}: {url}")
        content = fetch_url_content(url)
        if content:
            models = extract_openai_models(content)
            all_models.update(models)
            print(f"   Found {len(models)} models")
        else:
            print(f"   Could not fetch {ref_name}")
    
    # Check Anthropic
    print("\n2. Checking Anthropic documentation...")
    print(f"   Fetching: {REFERENCES['anthropic']}")
    content = fetch_url_content(REFERENCES["anthropic"])
    if content:
        models = extract_anthropic_models(content)
        all_models.update(models)
        print(f"   Found {len(models)} models")
    else:
        print("   Could not fetch Anthropic docs")
    
    # Check Google
    print("\n3. Checking Google AI documentation...")
    print(f"   Fetching: {REFERENCES['google_ai']}")
    content = fetch_url_content(REFERENCES["google_ai"])
    if content:
        models = extract_google_models(content)
        all_models.update(models)
        print(f"   Found {len(models)} models")
    else:
        print("   Could not fetch Google AI docs")
    
    print("\n" + "=" * 60)
    print(f"\nTotal models found in official sources: {len(all_models)}")
    print("\nModels found:")
    for model_id, info in sorted(all_models.items()):
        print(f"  - {model_id} (from {info['source']})")
    
    # Save results
    with open('official_models_found.json', 'w') as f:
        json.dump(all_models, f, indent=2)
    
    print("\nResults saved to official_models_found.json")

if __name__ == "__main__":
    main()

