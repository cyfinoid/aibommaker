# Official Sources Review

This document tracks what information should be extracted from each official reference provided in `modelcard-info.md`.

## References to Review

1. **https://platform.openai.com/docs/models** - OpenAI's official model documentation
   - Should contain: List of available models, model specifications, capabilities
   - Extract: Model names, context lengths, capabilities, limitations (as documented)

2. **https://openai.com/index/gpt-oss-model-card/** - OpenAI's GPT OSS model card
   - Should contain: Model card format example, GPT model information
   - Extract: Model card structure, factual information about GPT models

3. **https://modelcards.withgoogle.com/model-cards** - Google Model Cards format
   - Should contain: Model card format standards, example model cards
   - Extract: Standard format structure, required fields

4. **https://docs.anthropic.com** - Anthropic Claude documentation
   - Should contain: Claude model information, capabilities, limitations
   - Extract: Model names, specifications, capabilities (as documented)

5. **https://ai.google.dev/docs** - Google AI (Gemini) documentation
   - Should contain: Gemini model information, capabilities, limitations
   - Extract: Model names, specifications, capabilities (as documented)

6. **https://huggingface.co/docs/hub/model-cards** - HuggingFace model card format
   - Should contain: Model card format standards
   - Extract: Format structure, metadata fields

7. **https://arxiv.org/abs/1810.03993** - Original Model Cards paper
   - Should contain: Model card framework definition
   - Extract: Standard sections, required fields

## Important Notes

- Only include models that are documented in these official sources
- Only include information that is explicitly stated in these sources
- Do not paraphrase or interpret - use exact information from sources
- If information is not available in official sources, note that in the model card

## Models Detected in Codebase

The following models are detected in `js/detectors.js`:
- OpenAI: gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-4, gpt-3.5-turbo, o1-preview, o1-mini, text-embedding-3-large, text-embedding-3-small, text-embedding-ada-002, dall-e-3, dall-e-2
- Anthropic: claude-3.5-sonnet, claude-3-opus, claude-3-sonnet, claude-3-haiku
- Google: gemini-1.5-pro, gemini-1.5-flash, gemini-pro, gemini-2.0-flash-exp, models/embedding-001, models/text-embedding-004, text-embedding-004, gemma2, gemma3
- Mistral: mistral-large, mixtral-8x7b, mistral, mathstral
- Cohere: command-r7b-arabic, command-r-plus, command-r, command-a
- Meta: llama3.3, llama3.2, llama3.1, llama3, codellama, medllama2
- DeepSeek: deepseek-coder-v2, deepseek-r1, deepseek-v3
- Alibaba: qwen2.5, qwen2.5-coder, qwq
- Microsoft: phi4, phi3
- EPFL: meditron
- 01.AI: yi
- Nexusflow: athene-v2

## Action Required

For each model detected:
1. Check if it's documented in the official references above
2. If yes: Extract factual information from those sources
3. If no: Note in model card that official documentation may not be available
4. Only include information that can be verified from official sources

