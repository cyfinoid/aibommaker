// Constants and patterns for AI/LLM detection

const GITHUB_API_BASE = 'https://api.github.com';
const HUGGINGFACE_API_BASE = 'https://huggingface.co/api';

const LLM_DEPENDENCIES = {
    python: [
        'openai', 'anthropic', 'google-generativeai', 'langchain', 'langchain-openai',
        'langchain-anthropic', 'langchain-google-genai', 'llama-index', 'llama-index-core',
        'haystack-ai', 'transformers', 'sentence-transformers', 'vllm', 'huggingface-hub',
        'llama-cpp-python', 'litellm', 'cohere', 'replicate', 'stability-sdk', 'together',
        'pinecone-client', 'chromadb', 'weaviate-client', 'qdrant-client', 'faiss-cpu', 'faiss-gpu'
    ],
    node: [
        'openai', '@anthropic-ai/sdk', '@google/generative-ai', 'langchain', 'langchain-openai',
        'langchain-anthropic', 'ai', 'llamaindex', '@mistralai/mistralai', 'cohere-ai',
        'replicate', '@huggingface/inference', '@pinecone-database/pinecone', 'chromadb',
        'weaviate-client', 'qdrant-client', 'vectordb'
    ],
    go: ['github.com/sashabaranov/go-openai', 'github.com/anthropics/anthropic-sdk-go', 
         'github.com/google/generative-ai-go', 'github.com/tmc/langchaingo'],
    java: ['com.openai:openai-java', 'com.anthropic:anthropic-sdk-java', 
           'com.google.cloud:google-cloud-aiplatform', 'dev.langchain4j:langchain4j'],
    rust: ['async-openai', 'anthropic-sdk', 'llm-chain']
};

const MANIFEST_FILES = {
    python: ['requirements.txt', 'pyproject.toml', 'Pipfile', 'Pipfile.lock', 'setup.py', 'poetry.lock'],
    node: ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
    go: ['go.mod', 'go.sum'],
    java: ['pom.xml', 'build.gradle', 'build.gradle.kts'],
    rust: ['Cargo.toml', 'Cargo.lock']
};

const SDK_PATTERNS = {
    python: [
        { pattern: /import\s+openai/i, provider: 'OpenAI', weight: 5 },
        { pattern: /from\s+openai\s+import/i, provider: 'OpenAI', weight: 5 },
        { pattern: /openai\.ChatCompletion/i, provider: 'OpenAI', weight: 5 },
        { pattern: /openai\.chat\.completions/i, provider: 'OpenAI', weight: 5 },
        { pattern: /openai\.Embedding/i, provider: 'OpenAI', weight: 5 },
        { pattern: /OpenAI\(/i, provider: 'OpenAI', weight: 5 },
        
        { pattern: /import\s+anthropic/i, provider: 'Anthropic', weight: 5 },
        { pattern: /from\s+anthropic\s+import/i, provider: 'Anthropic', weight: 5 },
        { pattern: /Anthropic\(/i, provider: 'Anthropic', weight: 5 },
        { pattern: /messages\.create\(/i, provider: 'Anthropic', weight: 4 },
        
        { pattern: /import\s+google\.generativeai/i, provider: 'Google', weight: 5 },
        { pattern: /genai\.GenerativeModel/i, provider: 'Google', weight: 5 },
        { pattern: /\.generate_content\(/i, provider: 'Google', weight: 4 },
        
        { pattern: /from\s+langchain/i, provider: 'LangChain', weight: 4 },
        { pattern: /import\s+langchain/i, provider: 'LangChain', weight: 4 },
        
        { pattern: /from\s+llama_index/i, provider: 'LlamaIndex', weight: 4 },
        { pattern: /import\s+llama_index/i, provider: 'LlamaIndex', weight: 4 }
    ],
    
    javascript: [
        { pattern: /from\s+['"]openai['"]/i, provider: 'OpenAI', weight: 5 },
        { pattern: /require\s*\(\s*['"]openai['"]/i, provider: 'OpenAI', weight: 5 },
        { pattern: /new\s+OpenAI\s*\(/i, provider: 'OpenAI', weight: 5 },
        { pattern: /\.chat\.completions\.create/i, provider: 'OpenAI', weight: 5 },
        
        { pattern: /from\s+['"]@anthropic-ai\/sdk['"]/i, provider: 'Anthropic', weight: 5 },
        { pattern: /require\s*\(\s*['"]@anthropic-ai\/sdk['"]/i, provider: 'Anthropic', weight: 5 },
        { pattern: /new\s+Anthropic\s*\(/i, provider: 'Anthropic', weight: 5 },
        
        { pattern: /from\s+['"]@google\/generative-ai['"]/i, provider: 'Google', weight: 5 },
        { pattern: /GoogleGenerativeAI/i, provider: 'Google', weight: 5 },
        
        { pattern: /from\s+['"]langchain/i, provider: 'LangChain', weight: 4 },
        { pattern: /require\s*\(\s*['"]langchain/i, provider: 'LangChain', weight: 4 },
        
        { pattern: /from\s+['"]ai['"]/i, provider: 'Vercel AI', weight: 4 },
        { pattern: /generateText|streamText/i, provider: 'Vercel AI', weight: 4 }
    ]
};

const API_ENDPOINTS = [
    { pattern: /api\.openai\.com/i, provider: 'OpenAI', weight: 4 },
    { pattern: /api\.anthropic\.com/i, provider: 'Anthropic', weight: 4 },
    { pattern: /generativelanguage\.googleapis\.com/i, provider: 'Google', weight: 4 },
    { pattern: /api\.groq\.com/i, provider: 'Groq', weight: 4 },
    { pattern: /api\.openrouter\.ai/i, provider: 'OpenRouter', weight: 4 },
    { pattern: /api\.together\.xyz/i, provider: 'Together AI', weight: 4 },
    { pattern: /api\.cohere\.ai/i, provider: 'Cohere', weight: 4 },
    { pattern: /api\.replicate\.com/i, provider: 'Replicate', weight: 4 },
    { pattern: /\/v1\/chat\/completions/i, provider: 'OpenAI-compatible', weight: 3 },
    { pattern: /\/v1\/completions/i, provider: 'OpenAI-compatible', weight: 3 },
    { pattern: /\/v1\/embeddings/i, provider: 'OpenAI-compatible', weight: 3 }
];

const CONFIG_PATTERNS = [
    { pattern: /OPENAI_API_KEY/i, provider: 'OpenAI', weight: 3 },
    { pattern: /ANTHROPIC_API_KEY/i, provider: 'Anthropic', weight: 3 },
    { pattern: /GOOGLE_API_KEY|GEMINI_API_KEY/i, provider: 'Google', weight: 3 },
    { pattern: /AZURE_OPENAI_/i, provider: 'Azure OpenAI', weight: 3 },
    { pattern: /MISTRAL_API_KEY/i, provider: 'Mistral', weight: 3 },
    { pattern: /GROQ_API_KEY/i, provider: 'Groq', weight: 3 },
    { pattern: /COHERE_API_KEY/i, provider: 'Cohere', weight: 3 },
    { pattern: /REPLICATE_API_TOKEN/i, provider: 'Replicate', weight: 3 },
    { pattern: /OLLAMA_HOST|OLLAMA_API/i, provider: 'Ollama', weight: 3 },
    { pattern: /HUGGINGFACE_TOKEN|HF_TOKEN/i, provider: 'HuggingFace', weight: 3 }
];

const MODEL_PATTERNS = [
    { pattern: /gpt-4o/i, provider: 'OpenAI', model: 'GPT-4o' },
    { pattern: /gpt-4-turbo|gpt-4-1106/i, provider: 'OpenAI', model: 'GPT-4 Turbo' },
    { pattern: /gpt-4(?!\.)/i, provider: 'OpenAI', model: 'GPT-4' },
    { pattern: /gpt-3\.5-turbo/i, provider: 'OpenAI', model: 'GPT-3.5 Turbo' },
    { pattern: /claude-3-opus/i, provider: 'Anthropic', model: 'Claude 3 Opus' },
    { pattern: /claude-3\.5-sonnet/i, provider: 'Anthropic', model: 'Claude 3.5 Sonnet' },
    { pattern: /claude-3-sonnet/i, provider: 'Anthropic', model: 'Claude 3 Sonnet' },
    { pattern: /claude-3-haiku/i, provider: 'Anthropic', model: 'Claude 3 Haiku' },
    { pattern: /gemini-1\.5-pro/i, provider: 'Google', model: 'Gemini 1.5 Pro' },
    { pattern: /gemini-1\.5-flash/i, provider: 'Google', model: 'Gemini 1.5 Flash' },
    { pattern: /gemini-pro/i, provider: 'Google', model: 'Gemini Pro' },
    { pattern: /mistral-large/i, provider: 'Mistral', model: 'Mistral Large' },
    { pattern: /mixtral-8x7b/i, provider: 'Mistral', model: 'Mixtral 8x7B' }
];

const PROMPT_INDICATORS = [
    'You are a helpful assistant',
    'You are an AI assistant',
    'You are a coding assistant',
    'system prompt',
    'user prompt',
    'assistant prompt',
    'few-shot',
    'zero-shot',
    'chain-of-thought',
    'tool calling',
    'function calling',
    'RAG',
    'retrieval augmented generation'
];

const CI_PATTERNS = [
    { pattern: /ai-pr-review/i, description: 'AI PR Review Action' },
    { pattern: /chatgpt-action/i, description: 'ChatGPT Action' },
    { pattern: /openai-pr-reviewer/i, description: 'OpenAI PR Reviewer' },
    { pattern: /gpt-commit-summarizer/i, description: 'GPT Commit Summarizer' },
    { pattern: /copilot-cli/i, description: 'GitHub Copilot CLI' }
];

const MODEL_FILE_PATTERNS = [
    { extension: '.gguf', description: 'GGUF model file (llama.cpp format)' },
    { extension: '.safetensors', description: 'SafeTensors model file' },
    { extension: '.bin', description: 'Binary model file', pathMatch: /models?|checkpoints?/i },
    { filename: 'tokenizer.json', description: 'Tokenizer configuration' },
    { filename: 'tokenizer.model', description: 'Tokenizer model' },
    { filename: 'tokenizer_config.json', description: 'Tokenizer configuration' },
    { filename: 'config.json', description: 'Model configuration', pathMatch: /models?/i },
    { filename: 'generation_config.json', description: 'Generation configuration' },
    { filename: 'Modelfile', description: 'Ollama Modelfile' },
    { filename: 'ollama.yaml', description: 'Ollama configuration' },
    { filename: 'model_index.json', description: 'Model index file' }
];

