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

// CONFIG_PATTERNS removed - we don't scan for API keys anymore
// Reasons:
// 1. Good projects don't commit API keys (use env vars at runtime)
// 2. Code/dependencies are better AI indicators
// 3. Security: shouldn't log or expose secret references

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

// Hardware detection patterns for GPU/TPU/specialized compute
const HARDWARE_PATTERNS = {
    gpu: {
        dependencies: ['torch', 'tensorflow-gpu', 'cuda', 'cudnn', 'cupy', 'pycuda', 'cupy-cuda'],
        patterns: [
            // Use word boundaries and specific contexts to avoid false positives
            { pattern: /\b(cuda|nvidia)\b/i, type: 'GPU', weight: 3 },
            { pattern: /\bgpu\b/i, type: 'GPU', weight: 3 },
            { pattern: /device\s*=\s*['"]cuda['"]/i, type: 'GPU', weight: 5 },
            { pattern: /\.to\(['"]cuda['"]\)/i, type: 'GPU', weight: 5 },
            { pattern: /\.cuda\(\)/i, type: 'GPU', weight: 5 },
            { pattern: /torch\.cuda/i, type: 'GPU', weight: 5 },
            { pattern: /tf\.config\.experimental\.list_physical_devices\(['"]GPU['"]\)/i, type: 'GPU', weight: 5 }
        ]
    },
    tpu: {
        dependencies: ['tensorflow', 'jax', 'cloud-tpu-client'],
        patterns: [
            // Use word boundaries and specific contexts to avoid false positives (output, timeout, etc.)
            { pattern: /\btpu\b/i, type: 'TPU', weight: 4 },
            { pattern: /['"]tpu['"]/i, type: 'TPU', weight: 5 },
            { pattern: /device.*=.*tpu/i, type: 'TPU', weight: 5 },
            { pattern: /tf\.distribute\.TPUStrategy/i, type: 'TPU', weight: 5 },
            { pattern: /jax\.devices\(['"]tpu['"]\)/i, type: 'TPU', weight: 5 },
            { pattern: /cloud-tpu|tpu-vm|tpu_name/i, type: 'TPU', weight: 5 }
        ]
    },
    specialized: {
        dependencies: ['tensorrt', 'openvino', 'onnxruntime-gpu', 'onnxruntime', 'coreml'],
        patterns: [
            { pattern: /tensorrt/i, type: 'TensorRT', weight: 4 },
            { pattern: /openvino/i, type: 'OpenVINO', weight: 4 },
            { pattern: /onnxruntime/i, type: 'ONNX Runtime', weight: 4 },
            { pattern: /coreml/i, type: 'CoreML', weight: 4 }
        ]
    }
};

// Infrastructure and deployment patterns
const INFRASTRUCTURE_PATTERNS = {
    containerization: {
        files: ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.dockerignore'],
        patterns: [
            { pattern: /FROM\s+nvidia\/cuda/i, platform: 'Docker + NVIDIA CUDA', weight: 5 },
            { pattern: /FROM\s+pytorch\/pytorch/i, platform: 'Docker + PyTorch', weight: 5 },
            { pattern: /FROM\s+tensorflow\/tensorflow/i, platform: 'Docker + TensorFlow', weight: 5 },
            { pattern: /FROM\s+huggingface/i, platform: 'Docker + HuggingFace', weight: 5 },
            { pattern: /--gpus/i, platform: 'Docker GPU', weight: 4 },
            { pattern: /runtime:\s*nvidia/i, platform: 'Docker NVIDIA Runtime', weight: 5 }
        ]
    },
    orchestration: {
        files: ['deployment.yaml', 'deployment.yml', 'service.yaml', 'service.yml', 
                'pod.yaml', 'pod.yml', 'kustomization.yaml', 'helm-chart.yaml'],
        patterns: [
            { pattern: /kind:\s*Deployment/i, platform: 'Kubernetes', weight: 5 },
            { pattern: /kind:\s*Service/i, platform: 'Kubernetes', weight: 4 },
            { pattern: /kind:\s*Pod/i, platform: 'Kubernetes', weight: 4 },
            { pattern: /nvidia\.com\/gpu/i, platform: 'Kubernetes GPU', weight: 5 }
        ]
    },
    cloud: {
        patterns: [
            { pattern: /sagemaker/i, platform: 'AWS SageMaker', weight: 5 },
            { pattern: /aws\.sagemaker/i, platform: 'AWS SageMaker', weight: 5 },
            { pattern: /vertex-ai|vertexai/i, platform: 'GCP Vertex AI', weight: 5 },
            { pattern: /google\.cloud\.aiplatform/i, platform: 'GCP AI Platform', weight: 5 },
            { pattern: /azureml|azure-ml/i, platform: 'Azure ML', weight: 5 },
            { pattern: /from\s+azureml/i, platform: 'Azure ML', weight: 5 },
            { pattern: /bedrock/i, platform: 'AWS Bedrock', weight: 5 },
            { pattern: /modal\.com|modal\.run/i, platform: 'Modal', weight: 4 },
            { pattern: /replicate\.com/i, platform: 'Replicate', weight: 4 }
        ]
    },
    mlops: {
        dependencies: ['mlflow', 'wandb', 'tensorboard', 'clearml', 'neptune-client', 'comet-ml'],
        patterns: [
            { pattern: /mlflow/i, platform: 'MLflow', weight: 4 },
            { pattern: /wandb/i, platform: 'Weights & Biases', weight: 4 },
            { pattern: /tensorboard/i, platform: 'TensorBoard', weight: 3 },
            { pattern: /clearml/i, platform: 'ClearML', weight: 4 }
        ]
    }
};

// Documentation files for governance and model cards
const DOCUMENTATION_FILES = [
    'README.md', 'readme.md', 'Readme.md',
    'MODEL_CARD.md', 'model-card.md', 'ModelCard.md', 'model_card.md',
    'SECURITY.md', 'security.md', 'Security.md',
    'LIMITATIONS.md', 'limitations.md', 'Limitations.md',
    'ETHICS.md', 'ethics.md', 'Ethics.md',
    'FAIRNESS.md', 'fairness.md',
    'BIAS.md', 'bias.md',
    'CONTRIBUTING.md', 'contributing.md',
    'CODE_OF_CONDUCT.md', 'code_of_conduct.md'
];

// Data pipeline and preprocessing patterns
const DATA_PIPELINE_PATTERNS = {
    loading: {
        dependencies: ['datasets', 'huggingface-datasets', 'pandas', 'numpy', 'dask', 'ray'],
        patterns: [
            { pattern: /datasets\.load_dataset/i, tool: 'HuggingFace Datasets', weight: 4 },
            { pattern: /pd\.read_csv|pd\.read_json|pd\.read_parquet/i, tool: 'Pandas', weight: 3 },
            { pattern: /np\.load|np\.loadtxt/i, tool: 'NumPy', weight: 2 }
        ]
    },
    preprocessing: {
        dependencies: ['scikit-learn', 'sklearn', 'nltk', 'spacy', 'transformers', 'torchvision', 'albumentations'],
        patterns: [
            { pattern: /from\s+sklearn\.preprocessing/i, tool: 'scikit-learn preprocessing', weight: 3 },
            { pattern: /AutoTokenizer|Tokenizer/i, tool: 'Tokenization', weight: 4 },
            { pattern: /transforms\.|Compose\(/i, tool: 'Data augmentation', weight: 3 },
            { pattern: /ImageDataGenerator|augment/i, tool: 'Image augmentation', weight: 3 }
        ]
    },
    feature_engineering: {
        patterns: [
            { pattern: /FeatureExtractor|feature_extraction/i, tool: 'Feature extraction', weight: 3 },
            { pattern: /TfidfVectorizer|CountVectorizer/i, tool: 'Text vectorization', weight: 3 },
            { pattern: /PCA|TSNE|UMAP/i, tool: 'Dimensionality reduction', weight: 3 }
        ]
    }
};

// Risk and security keywords
const RISK_KEYWORDS = {
    vulnerabilities: ['vulnerability', 'CVE', 'security advisory', 'exploit', 'patch'],
    deprecation: ['deprecated', 'unmaintained', 'obsolete', 'end of life', 'EOL'],
    bias: ['bias', 'fairness', 'discrimination', 'equity', 'demographic parity'],
    limitations: ['limitation', 'constraint', 'does not support', 'not recommended', 'known issue'],
    ethical: ['ethical', 'privacy', 'consent', 'harmful', 'misuse', 'dual use']
};

