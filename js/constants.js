// Constants and patterns for AI/LLM detection
// ============================================================================
// This file contains extensible registries for AI package detection.
// Users can add new packages by extending the arrays in each category.
// ============================================================================

const GITHUB_API_BASE = 'https://api.github.com';
const HUGGINGFACE_API_BASE = 'https://huggingface.co/api';

// ============================================================================
// AI PACKAGE REGISTRY - Extensible categorized lists of AI-related packages
// ============================================================================
// To add new packages: Simply add to the appropriate category array.
// Each package entry can be a string (package name) or an object with metadata.
// ============================================================================

const AI_PACKAGE_REGISTRY = {
    // ==========================================================================
    // LLM Provider SDKs - Direct API access to LLM providers
    // ==========================================================================
    llm_providers: {
        python: [
            'openai', 'anthropic', 'google-generativeai', 'cohere', 'mistralai',
            'replicate', 'together', 'groq', 'fireworks-ai', 'anyscale',
            'ai21', 'aleph-alpha-client', 'stability-sdk', 'deepseek-ai'
        ],
        node: [
            'openai', '@anthropic-ai/sdk', '@google/generative-ai', 'cohere-ai',
            '@mistralai/mistralai', 'replicate', 'groq-sdk', '@ai-sdk/openai',
            '@ai-sdk/anthropic', '@ai-sdk/google', '@ai-sdk/mistral'
        ],
        go: [
            'github.com/sashabaranov/go-openai',
            'github.com/anthropics/anthropic-sdk-go',
            'github.com/google/generative-ai-go',
            'github.com/cohere-ai/cohere-go'
        ],
        java: [
            'com.openai:openai-java',
            'com.anthropic:anthropic-sdk-java',
            'com.google.cloud:google-cloud-aiplatform'
        ],
        rust: ['async-openai', 'anthropic-sdk', 'mistral-rs']
    },
    
    // ==========================================================================
    // LLM Frameworks - Orchestration and abstraction layers
    // ==========================================================================
    llm_frameworks: {
        python: [
            'langchain', 'langchain-core', 'langchain-openai', 'langchain-anthropic',
            'langchain-google-genai', 'langchain-community', 'langgraph',
            'llama-index', 'llama-index-core', 'llama-index-llms-openai',
            'haystack-ai', 'dspy-ai', 'guidance', 'outlines', 'instructor',
            'litellm', 'magentic', 'marvin', 'promptflow', 'semantic-kernel',
            'autogen', 'crewai', 'agency-swarm'
        ],
        node: [
            'langchain', '@langchain/core', '@langchain/openai', '@langchain/anthropic',
            '@langchain/google-genai', '@langchain/community', '@langchain/langgraph',
            'llamaindex', 'ai', '@vercel/ai', 'flowise', 'langflow'
        ],
        go: ['github.com/tmc/langchaingo'],
        java: ['dev.langchain4j:langchain4j', 'dev.langchain4j:langchain4j-open-ai'],
        rust: ['llm-chain', 'langchain-rust']
    },
    
    // ==========================================================================
    // Local LLM Inference - Running models locally
    // ==========================================================================
    local_inference: {
        python: [
            'llama-cpp-python', 'vllm', 'transformers', 'huggingface-hub',
            'accelerate', 'bitsandbytes', 'auto-gptq', 'exllama', 'exllamav2',
            'ctransformers', 'gpt4all', 'mlx', 'mlx-lm', 'ollama'
        ],
        node: ['@huggingface/inference', 'ollama', 'node-llama-cpp'],
        go: ['github.com/ollama/ollama'],
        rust: ['llama-cpp-rs', 'candle', 'candle-core']
    },
    
    // ==========================================================================
    // Vector Databases & Embeddings - Semantic search infrastructure
    // ==========================================================================
    vector_stores: {
        python: [
            'pinecone-client', 'chromadb', 'weaviate-client', 'qdrant-client',
            'faiss-cpu', 'faiss-gpu', 'milvus', 'pymilvus', 'pgvector',
            'lancedb', 'vespa', 'opensearch-py', 'elasticsearch',
            'sentence-transformers', 'fastembed'
        ],
        node: [
            '@pinecone-database/pinecone', 'chromadb', 'weaviate-client',
            'qdrant-client', 'vectordb', '@lancedb/lancedb', '@upstash/vector'
        ],
        go: ['github.com/pinecone-io/go-pinecone', 'github.com/weaviate/weaviate-go-client'],
        java: ['io.pinecone:pinecone-client', 'io.weaviate:client']
    },
    
    // ==========================================================================
    // AI Agents & Autonomous Systems
    // ==========================================================================
    ai_agents: {
        python: [
            'autogen', 'crewai', 'agency-swarm', 'agentops', 'langchain-agents',
            'superagi', 'agents', 'llama-agents', 'phidata', 'composio',
            'browser-use', 'lavague', 'agent-protocol'
        ],
        node: [
            '@langchain/langgraph', 'autogen', 'agent-protocol',
            '@browserbasehq/stagehand', 'browser-use'
        ]
    },
    
    // ==========================================================================
    // MCP (Model Context Protocol) - Anthropic's protocol for tool integration
    // ==========================================================================
    mcp_protocol: {
        python: [
            'mcp', 'anthropic-mcp', 'mcp-server', 'mcp-client',
            'mcp-server-sqlite', 'mcp-server-git', 'mcp-server-filesystem',
            'mcp-server-github', 'mcp-server-postgres', 'mcp-server-slack'
        ],
        node: [
            '@modelcontextprotocol/sdk', '@modelcontextprotocol/server-filesystem',
            '@modelcontextprotocol/server-github', '@modelcontextprotocol/server-gitlab',
            '@modelcontextprotocol/server-postgres', '@modelcontextprotocol/server-sqlite',
            '@modelcontextprotocol/server-slack', '@modelcontextprotocol/server-memory',
            '@modelcontextprotocol/server-brave-search', '@modelcontextprotocol/server-fetch',
            '@modelcontextprotocol/server-puppeteer', '@modelcontextprotocol/server-sequential-thinking',
            '@anthropic-ai/mcp', 'mcp-framework'
        ],
        rust: ['mcp-rust', 'mcp-server']
    },
    
    // ==========================================================================
    // A2A (Agent-to-Agent) & Multi-Agent Protocols
    // ==========================================================================
    a2a_protocols: {
        python: [
            'agent-protocol', 'a2a', 'agent-communication-protocol',
            'openagents', 'agentverse', 'fetchai-uagents', 'uagents'
        ],
        node: [
            'agent-protocol', '@agent-protocol/client', '@agent-protocol/sdk',
            'agentverse'
        ]
    },
    
    // ==========================================================================
    // AI Plugin Systems & Tool Calling
    // ==========================================================================
    plugin_systems: {
        python: [
            'openai-function-calling', 'toolformer', 'gorilla-llm', 'composio',
            'langchain-tools', 'semantic-kernel-plugins', 'openapi-llm'
        ],
        node: [
            '@langchain/tools', 'ai-plugin', 'chatgpt-plugin', 'composio-core'
        ]
    },
    
    // ==========================================================================
    // RAG (Retrieval Augmented Generation) & Document Processing
    // ==========================================================================
    rag_document: {
        python: [
            'unstructured', 'llama-parse', 'docling', 'pymupdf', 'pypdf',
            'pdfplumber', 'markdownify', 'trafilatura', 'beautifulsoup4',
            'llama-index-readers', 'langchain-document-loaders'
        ],
        node: [
            'pdf-parse', '@langchain/document-loaders', 'cheerio', 'puppeteer',
            'unstructured-client'
        ]
    },
    
    // ==========================================================================
    // Prompt Engineering & Evaluation
    // ==========================================================================
    prompt_eval: {
        python: [
            'promptfoo', 'ragas', 'deepeval', 'langsmith', 'phoenix-ai',
            'arize-phoenix', 'langfuse', 'traceloop', 'openllmetry',
            'prompttools', 'giskard'
        ],
        node: [
            'promptfoo', 'langsmith', '@langfuse/langfuse', 'langwatch'
        ]
    }
};

// ==========================================================================
// AI DEVELOPMENT TOOLS - IDE plugins, copilots, and AI-assisted coding
// Confidence: Low - These indicate AI-assisted development, not AI functionality
// ==========================================================================
const AI_DEV_TOOLS = {
    // IDE Extensions and Copilots (detected via config files or dependencies)
    ide_copilots: {
        // Config files that indicate AI tool usage
        config_files: [
            '.cursor',                    // Cursor IDE directory
            '.cursor/rules',              // Cursor custom rules
            '.cursorrules',               // Cursor rules file
            '.cursorignore',              // Cursor ignore file
            'cursor.json',                // Cursor config
            '.github/copilot',            // GitHub Copilot config
            '.github/copilot-instructions.md', // Copilot instructions
            'copilot-instructions.md',    // Copilot instructions (root)
            '.aider',                     // Aider AI config
            '.aider.conf.yml',            // Aider config
            '.aider.input.history',       // Aider history
            'aider.conf.yml',             // Aider config
            '.continue',                  // Continue.dev config
            'continue.json',              // Continue config
            '.cody',                      // Sourcegraph Cody
            'cody.json',                  // Cody config
            '.windsurf',                  // Windsurf/Codeium config
            '.codeium',                   // Codeium config
            '.tabnine',                   // TabNine config
            '.amazonq',                   // Amazon Q config
            '.aws/amazonq',               // Amazon Q AWS config
            'CLAUDE.md',                  // Claude Code conventions file
            'claude.md',                  // Claude Code conventions file (lowercase)
            '.claude',                    // Claude config directory
        ],
        // Node.js dependencies that indicate AI tooling
        node: [
            '@anthropic-ai/claude-code',
            '@cursor/sdk',
            'aider-chat',
            'continue-dev'
        ],
        // Python dependencies
        python: [
            'aider-chat',
            'claude-dev'
        ],
        // VSCode extension identifiers (from extensions.json or workspace recommendations)
        vscode_extensions: [
            'github.copilot',
            'github.copilot-chat',
            'anthropic.claude-vscode',
            'continue.continue',
            'codeium.codeium',
            'tabnine.tabnine-vscode',
            'amazonwebservices.aws-toolkit-vscode',
            'sourcegraph.cody-ai'
        ]
    },
    
    // AI Code Generation and Review Tools
    code_gen_tools: {
        python: [
            'gpt-engineer', 'aider-chat', 'mentat', 'codegen', 'smol-developer',
            'auto-gpt', 'babyagi', 'jarvis', 'devika', 'opendevin', 'swe-agent',
            'openhands'
        ],
        node: [
            'smol-ai', 'gpt-pilot', 'code-gpt'
        ]
    },
    
    // AI-Assisted Testing
    testing_tools: {
        python: [
            'codium-ai', 'cover-agent', 'qodo-cover', 'pythagora-io',
            'testpilot', 'testgen-llm'
        ],
        node: [
            '@qodo/cover-agent', 'testpilot'
        ]
    }
};

// ==========================================================================
// PROTOCOL & STANDARD DETECTION - MCP, A2A, OpenAPI for LLMs
// ==========================================================================
const AI_PROTOCOL_PATTERNS = {
    // MCP (Model Context Protocol) detection
    mcp: {
        config_files: [
            // Standard MCP config files
            'mcp.json',
            'mcp-config.json',
            'mcp-servers.json',
            'mcp_config.json',
            'mcp_servers.json',
            '.mcp/config.json',
            '.mcp/servers.json',
            // Claude Desktop config (contains MCP servers)
            'claude_desktop_config.json',
            // Cursor MCP config
            '.cursor/mcp.json',
            'cursor-mcp.json',
            // Cline/Roo config
            'cline_mcp_settings.json',
            'roo_mcp_settings.json',
            // Generic tool configs that may contain MCP
            '.config/mcp/servers.json',
            'config/mcp.json'
        ],
        code_patterns: [
            { pattern: /McpServer|MCP\.Server|mcp\.server/i, type: 'MCP Server' },
            { pattern: /McpClient|MCP\.Client|mcp\.client/i, type: 'MCP Client' },
            { pattern: /@modelcontextprotocol/i, type: 'MCP SDK' },
            { pattern: /from\s+mcp\s+import|import\s+mcp/i, type: 'MCP Python' },
            { pattern: /tool\s*\(\s*["'].*["']\s*,\s*["'].*["']\s*\)/i, type: 'MCP Tool Definition' },
            { pattern: /\.register_tool\s*\(|\.add_tool\s*\(/i, type: 'MCP Tool Registration' },
            { pattern: /ToolResult|CallToolResult/i, type: 'MCP Tool Result' }
        ],
        json_patterns: [
            // Look for MCP server configuration in JSON
            { key: 'mcpServers', type: 'MCP Server Config' },
            { key: 'mcp-servers', type: 'MCP Server Config' },
            { key: 'modelContextProtocol', type: 'MCP Config' }
        ]
    },
    
    // A2A (Agent-to-Agent) Protocol
    a2a: {
        config_files: [
            'a2a.json',
            'agent-protocol.json',
            '.agent-protocol/config.json'
        ],
        code_patterns: [
            { pattern: /agent-protocol|AgentProtocol/i, type: 'Agent Protocol' },
            { pattern: /agent_protocol|from\s+agent_protocol/i, type: 'A2A Python' },
            { pattern: /TaskRequest|TaskResponse|AgentMessage/i, type: 'A2A Messages' },
            { pattern: /agent\.communicate|send_to_agent/i, type: 'A2A Communication' }
        ]
    },
    
    // OpenAPI/OpenAI Function Calling
    function_calling: {
        code_patterns: [
            { pattern: /function_call|tool_choice|tools\s*[=:]\s*\[/i, type: 'Function Calling' },
            { pattern: /\.functions\s*=|"functions"\s*:/i, type: 'OpenAI Functions' },
            { pattern: /ToolMessage|tool_calls|parallel_tool_calls/i, type: 'Tool Calls' }
        ]
    },
    
    // Semantic Kernel Plugins
    semantic_kernel: {
        config_files: [
            'sk-config.json',
            'semantic-kernel.json'
        ],
        code_patterns: [
            { pattern: /semantic[-_]?kernel|from\s+semantic_kernel/i, type: 'Semantic Kernel' },
            { pattern: /@kernel_function|KernelPlugin/i, type: 'SK Plugin' }
        ]
    }
};

// ==========================================================================
// BACKWARD COMPATIBILITY - Generate LLM_DEPENDENCIES from registry
// ==========================================================================
const LLM_DEPENDENCIES = {
    python: [
        ...AI_PACKAGE_REGISTRY.llm_providers.python || [],
        ...AI_PACKAGE_REGISTRY.llm_frameworks.python || [],
        ...AI_PACKAGE_REGISTRY.local_inference.python || [],
        ...AI_PACKAGE_REGISTRY.vector_stores.python || []
    ],
    node: [
        ...AI_PACKAGE_REGISTRY.llm_providers.node || [],
        ...AI_PACKAGE_REGISTRY.llm_frameworks.node || [],
        ...AI_PACKAGE_REGISTRY.local_inference.node || [],
        ...AI_PACKAGE_REGISTRY.vector_stores.node || []
    ],
    go: [
        ...AI_PACKAGE_REGISTRY.llm_providers.go || [],
        ...AI_PACKAGE_REGISTRY.llm_frameworks.go || [],
        ...AI_PACKAGE_REGISTRY.local_inference.go || [],
        ...AI_PACKAGE_REGISTRY.vector_stores.go || []
    ],
    java: [
        ...AI_PACKAGE_REGISTRY.llm_providers.java || [],
        ...AI_PACKAGE_REGISTRY.llm_frameworks.java || [],
        ...AI_PACKAGE_REGISTRY.vector_stores.java || []
    ],
    rust: [
        ...AI_PACKAGE_REGISTRY.llm_providers.rust || [],
        ...AI_PACKAGE_REGISTRY.llm_frameworks.rust || [],
        ...AI_PACKAGE_REGISTRY.local_inference.rust || []
    ]
};

// ==========================================================================
// EXTENDED DEPENDENCIES - All AI-adjacent packages (includes protocols, agents)
// ==========================================================================
const AI_EXTENDED_DEPENDENCIES = {
    python: [
        ...LLM_DEPENDENCIES.python,
        ...AI_PACKAGE_REGISTRY.ai_agents?.python || [],
        ...AI_PACKAGE_REGISTRY.mcp_protocol?.python || [],
        ...AI_PACKAGE_REGISTRY.a2a_protocols?.python || [],
        ...AI_PACKAGE_REGISTRY.plugin_systems?.python || [],
        ...AI_PACKAGE_REGISTRY.rag_document?.python || [],
        ...AI_PACKAGE_REGISTRY.prompt_eval?.python || []
    ],
    node: [
        ...LLM_DEPENDENCIES.node,
        ...AI_PACKAGE_REGISTRY.ai_agents?.node || [],
        ...AI_PACKAGE_REGISTRY.mcp_protocol?.node || [],
        ...AI_PACKAGE_REGISTRY.a2a_protocols?.node || [],
        ...AI_PACKAGE_REGISTRY.plugin_systems?.node || [],
        ...AI_PACKAGE_REGISTRY.rag_document?.node || [],
        ...AI_PACKAGE_REGISTRY.prompt_eval?.node || []
    ],
    go: [...LLM_DEPENDENCIES.go],
    java: [...LLM_DEPENDENCIES.java],
    rust: [
        ...LLM_DEPENDENCIES.rust,
        ...AI_PACKAGE_REGISTRY.mcp_protocol?.rust || []
    ]
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
        // OpenAI
        { pattern: /import\s+openai/i, provider: 'OpenAI', weight: 5 },
        { pattern: /from\s+openai\s+import/i, provider: 'OpenAI', weight: 5 },
        { pattern: /openai\.ChatCompletion/i, provider: 'OpenAI', weight: 5 },
        { pattern: /openai\.chat\.completions/i, provider: 'OpenAI', weight: 5 },
        { pattern: /openai\.Embedding/i, provider: 'OpenAI', weight: 5 },
        { pattern: /OpenAI\(/i, provider: 'OpenAI', weight: 5 },
        
        // Anthropic
        { pattern: /import\s+anthropic/i, provider: 'Anthropic', weight: 5 },
        { pattern: /from\s+anthropic\s+import/i, provider: 'Anthropic', weight: 5 },
        { pattern: /Anthropic\(/i, provider: 'Anthropic', weight: 5 },
        { pattern: /messages\.create\(/i, provider: 'Anthropic', weight: 4 },
        
        // Google
        { pattern: /import\s+google\.generativeai/i, provider: 'Google', weight: 5 },
        { pattern: /genai\.GenerativeModel/i, provider: 'Google', weight: 5 },
        { pattern: /\.generate_content\(/i, provider: 'Google', weight: 4 },
        
        // LangChain
        { pattern: /from\s+langchain/i, provider: 'LangChain', weight: 4 },
        { pattern: /import\s+langchain/i, provider: 'LangChain', weight: 4 },
        
        // LiteLLM
        { pattern: /import\s+litellm/i, provider: 'LiteLLM', weight: 5 },
        { pattern: /from\s+litellm\s+import/i, provider: 'LiteLLM', weight: 5 },
        { pattern: /litellm\./i, provider: 'LiteLLM', weight: 4 },
        
        // LlamaIndex
        { pattern: /from\s+llama_index/i, provider: 'LlamaIndex', weight: 4 },
        { pattern: /import\s+llama_index/i, provider: 'LlamaIndex', weight: 4 },
        
        // MCP (Model Context Protocol)
        { pattern: /from\s+mcp\s+import/i, provider: 'MCP', weight: 4, category: 'protocol' },
        { pattern: /import\s+mcp/i, provider: 'MCP', weight: 4, category: 'protocol' },
        { pattern: /mcp\.server|mcp\.client/i, provider: 'MCP', weight: 5, category: 'protocol' },
        { pattern: /McpServer\(|McpClient\(/i, provider: 'MCP', weight: 5, category: 'protocol' },
        
        // Agent Protocol / A2A
        { pattern: /from\s+agent_protocol/i, provider: 'Agent Protocol', weight: 4, category: 'protocol' },
        { pattern: /import\s+agent_protocol/i, provider: 'Agent Protocol', weight: 4, category: 'protocol' },
        
        // CrewAI / AutoGen
        { pattern: /from\s+crewai/i, provider: 'CrewAI', weight: 4, category: 'agents' },
        { pattern: /from\s+autogen/i, provider: 'AutoGen', weight: 4, category: 'agents' },
        { pattern: /import\s+autogen/i, provider: 'AutoGen', weight: 4, category: 'agents' }
    ],
    
    javascript: [
        // OpenAI
        { pattern: /from\s+['"]openai['"]/i, provider: 'OpenAI', weight: 5 },
        { pattern: /require\s*\(\s*['"]openai['"]/i, provider: 'OpenAI', weight: 5 },
        { pattern: /new\s+OpenAI\s*\(/i, provider: 'OpenAI', weight: 5 },
        { pattern: /\.chat\.completions\.create/i, provider: 'OpenAI', weight: 5 },
        
        // Anthropic
        { pattern: /from\s+['"]@anthropic-ai\/sdk['"]/i, provider: 'Anthropic', weight: 5 },
        { pattern: /require\s*\(\s*['"]@anthropic-ai\/sdk['"]/i, provider: 'Anthropic', weight: 5 },
        { pattern: /new\s+Anthropic\s*\(/i, provider: 'Anthropic', weight: 5 },
        
        // Google
        { pattern: /from\s+['"]@google\/generative-ai['"]/i, provider: 'Google', weight: 5 },
        { pattern: /GoogleGenerativeAI/i, provider: 'Google', weight: 5 },
        
        // LangChain
        { pattern: /from\s+['"]langchain/i, provider: 'LangChain', weight: 4 },
        { pattern: /require\s*\(\s*['"]langchain/i, provider: 'LangChain', weight: 4 },
        { pattern: /from\s+['"]@langchain\//i, provider: 'LangChain', weight: 4 },
        
        // Vercel AI SDK
        { pattern: /from\s+['"]ai['"]/i, provider: 'Vercel AI', weight: 4 },
        { pattern: /from\s+['"]@ai-sdk\//i, provider: 'Vercel AI', weight: 4 },
        { pattern: /generateText|streamText/i, provider: 'Vercel AI', weight: 4 },
        
        // MCP (Model Context Protocol)
        { pattern: /from\s+['"]@modelcontextprotocol/i, provider: 'MCP', weight: 5, category: 'protocol' },
        { pattern: /require\s*\(['"]@modelcontextprotocol/i, provider: 'MCP', weight: 5, category: 'protocol' },
        { pattern: /McpServer|McpClient/i, provider: 'MCP', weight: 4, category: 'protocol' },
        { pattern: /StdioServerTransport|SSEServerTransport/i, provider: 'MCP', weight: 4, category: 'protocol' },
        
        // Agent Protocol / A2A
        { pattern: /from\s+['"]agent-protocol/i, provider: 'Agent Protocol', weight: 4, category: 'protocol' },
        { pattern: /require\s*\(['"]agent-protocol/i, provider: 'Agent Protocol', weight: 4, category: 'protocol' }
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
    // OpenAI Models
    { pattern: /gpt-4o-mini/i, provider: 'OpenAI', model: 'GPT-4o Mini' },
    { pattern: /gpt-4o/i, provider: 'OpenAI', model: 'GPT-4o' },
    { pattern: /gpt-4-turbo|gpt-4-1106/i, provider: 'OpenAI', model: 'GPT-4 Turbo' },
    { pattern: /gpt-4(?![o\.])/i, provider: 'OpenAI', model: 'GPT-4' },
    { pattern: /gpt-3\.5-turbo/i, provider: 'OpenAI', model: 'GPT-3.5 Turbo' },
    { pattern: /o1-preview/i, provider: 'OpenAI', model: 'o1-preview' },
    { pattern: /o1-mini/i, provider: 'OpenAI', model: 'o1-mini' },
    { pattern: /o3-mini/i, provider: 'OpenAI', model: 'o3-mini' },
    
    // Anthropic Models
    { pattern: /claude-3-opus/i, provider: 'Anthropic', model: 'Claude 3 Opus' },
    { pattern: /claude-3\.5-sonnet|claude-3-5-sonnet/i, provider: 'Anthropic', model: 'Claude 3.5 Sonnet' },
    { pattern: /claude-3\.5-haiku|claude-3-5-haiku/i, provider: 'Anthropic', model: 'Claude 3.5 Haiku' },
    { pattern: /claude-3-sonnet/i, provider: 'Anthropic', model: 'Claude 3 Sonnet' },
    { pattern: /claude-3-haiku/i, provider: 'Anthropic', model: 'Claude 3 Haiku' },
    { pattern: /claude-opus-4|claude-4-opus/i, provider: 'Anthropic', model: 'Claude Opus 4' },
    { pattern: /claude-sonnet-4|claude-4-sonnet/i, provider: 'Anthropic', model: 'Claude Sonnet 4' },
    
    // Google Models
    { pattern: /gemini-2\.0-flash/i, provider: 'Google', model: 'Gemini 2.0 Flash' },
    { pattern: /gemini-2\.0-pro/i, provider: 'Google', model: 'Gemini 2.0 Pro' },
    { pattern: /gemini-1\.5-pro/i, provider: 'Google', model: 'Gemini 1.5 Pro' },
    { pattern: /gemini-1\.5-flash/i, provider: 'Google', model: 'Gemini 1.5 Flash' },
    { pattern: /gemini-pro/i, provider: 'Google', model: 'Gemini Pro' },
    { pattern: /gemma-2|gemma2/i, provider: 'Google', model: 'Gemma 2' },
    
    // Mistral Models
    { pattern: /mistral-large/i, provider: 'Mistral', model: 'Mistral Large' },
    { pattern: /mistral-medium/i, provider: 'Mistral', model: 'Mistral Medium' },
    { pattern: /mistral-small/i, provider: 'Mistral', model: 'Mistral Small' },
    { pattern: /mixtral-8x22b/i, provider: 'Mistral', model: 'Mixtral 8x22B' },
    { pattern: /mixtral-8x7b/i, provider: 'Mistral', model: 'Mixtral 8x7B' },
    { pattern: /codestral/i, provider: 'Mistral', model: 'Codestral' },
    
    // Meta Models
    { pattern: /llama-3\.3|llama3\.3/i, provider: 'Meta', model: 'Llama 3.3' },
    { pattern: /llama-3\.2|llama3\.2/i, provider: 'Meta', model: 'Llama 3.2' },
    { pattern: /llama-3\.1|llama3\.1/i, provider: 'Meta', model: 'Llama 3.1' },
    { pattern: /llama-3|llama3(?![.\d])/i, provider: 'Meta', model: 'Llama 3' },
    
    // DeepSeek Models
    { pattern: /deepseek-r1/i, provider: 'DeepSeek', model: 'DeepSeek R1' },
    { pattern: /deepseek-v3/i, provider: 'DeepSeek', model: 'DeepSeek V3' },
    { pattern: /deepseek-coder/i, provider: 'DeepSeek', model: 'DeepSeek Coder' },
    
    // Alibaba Models
    { pattern: /qwen-2\.5|qwen2\.5/i, provider: 'Alibaba', model: 'Qwen 2.5' },
    { pattern: /qwq/i, provider: 'Alibaba', model: 'QwQ' }
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
    // AI PR Review & Code Generation
    { pattern: /ai-pr-review/i, description: 'AI PR Review Action' },
    { pattern: /chatgpt-action/i, description: 'ChatGPT Action' },
    { pattern: /openai-pr-reviewer/i, description: 'OpenAI PR Reviewer' },
    { pattern: /gpt-commit-summarizer/i, description: 'GPT Commit Summarizer' },
    { pattern: /copilot-cli/i, description: 'GitHub Copilot CLI' },
    { pattern: /coderabbit/i, description: 'CodeRabbit AI Review' },
    { pattern: /codium-ai\/pr-agent/i, description: 'CodiumAI PR-Agent' },
    { pattern: /pr-agent/i, description: 'PR-Agent' },
    { pattern: /sweep-ai/i, description: 'Sweep AI' },
    { pattern: /deepsource/i, description: 'DeepSource AI' },
    { pattern: /sourcery-ai/i, description: 'Sourcery AI' },
    { pattern: /aider-chat/i, description: 'Aider Chat in CI' },
    { pattern: /claude-dev/i, description: 'Claude Dev Action' }
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
            // Specific GPU model detection (check first for accuracy)
            // Modal, RunPod, and other platforms: gpu="A10G", gpu="H100:1", etc.
            { pattern: /gpu\s*=\s*["']([A-Z0-9]+(?::\d+)?)["']/i, type: 'GPU', weight: 5, extractModel: true },
            // AWS SageMaker: instance_type="ml.g5.xlarge" (contains GPU)
            { pattern: /instance_type\s*=\s*["'](ml\.(g5|p3|p4|p5)[\w.-]+)["']/i, type: 'GPU', weight: 5, extractModel: true },
            // GCP Vertex AI: machine_type="n1-standard-4", accelerator_type="NVIDIA_TESLA_T4"
            { pattern: /accelerator_type\s*=\s*["'](NVIDIA_[\w_]+)["']/i, type: 'GPU', weight: 5, extractModel: true },
            // Azure ML: compute_target with GPU SKUs
            { pattern: /vm_size\s*=\s*["'](NC\d+|ND\d+|NV\d+[\w-]*)["']/i, type: 'GPU', weight: 5, extractModel: true },
            // Generic GPU model patterns: GPU="A100", gpu_type="H100"
            { pattern: /gpu[_-]?type\s*=\s*["']([A-Z0-9]+(?::\d+)?)["']/i, type: 'GPU', weight: 4, extractModel: true },
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
    'security.txt', // RFC 9116 security.txt file
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

