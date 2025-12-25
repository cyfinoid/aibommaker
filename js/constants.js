// Constants and patterns for AI/LLM detection
// ============================================================================
// This file contains extensible registries for AI package detection.
// Users can add new packages by extending the arrays in each category.
// ============================================================================

const GITHUB_API_BASE = 'https://api.github.com';
const HUGGINGFACE_API_BASE = 'https://huggingface.co/api';

// ============================================================================
// AI SIGNATURES - Structured detection patterns with rich metadata
// ============================================================================
// Inspired by xbom's YAML signatures but implemented as JavaScript objects
// Single source of truth for all AI/ML/MCP detection patterns
// ============================================================================
const AI_SIGNATURES = {
  // ==========================================================================
  // LLM PROVIDERS - Direct API access to LLM providers
  // ==========================================================================
  llm_providers: [
    {
      id: 'openai.client',
      vendor: 'OpenAI',
      product: 'OpenAI',
      service: 'AI Client',
      description: 'OpenAI client SDK for accessing GPT models',
      tags: ['ai', 'text', 'llm', 'api'],
      category: 'llm_providers',
      packages: {
        python: ['openai'],
        node: ['openai'],
        go: ['github.com/sashabaranov/go-openai'],
        java: ['com.openai:openai-java'],
        rust: ['async-openai']
      },
      codePatterns: {
        python: [
          { pattern: /import\s+openai/i, weight: 5 },
          { pattern: /from\s+openai\s+import/i, weight: 5 },
          { pattern: /openai\.ChatCompletion/i, weight: 5 },
          { pattern: /openai\.chat\.completions/i, weight: 5 },
          { pattern: /openai\.Embedding/i, weight: 5 },
          { pattern: /OpenAI\(/i, weight: 5 }
        ],
        javascript: [
          { pattern: /from\s+['"]openai['"]/i, weight: 5 },
          { pattern: /require\s*\(\s*['"]openai['"]/i, weight: 5 },
          { pattern: /new\s+OpenAI\s*\(/i, weight: 5 },
          { pattern: /\.chat\.completions\.create/i, weight: 5 }
        ]
      },
      apiEndpoints: [
        { pattern: /api\.openai\.com/i, weight: 4 }
      ],
      models: [
        { pattern: /gpt-4o-mini/i, name: 'GPT-4o Mini' },
        { pattern: /gpt-4o/i, name: 'GPT-4o' },
        { pattern: /gpt-4-turbo|gpt-4-1106/i, name: 'GPT-4 Turbo' },
        { pattern: /gpt-4(?![o\.])/i, name: 'GPT-4' },
        { pattern: /gpt-3\.5-turbo/i, name: 'GPT-3.5 Turbo' },
        { pattern: /o1-preview/i, name: 'o1-preview' },
        { pattern: /o1-mini/i, name: 'o1-mini' },
        { pattern: /o3-mini/i, name: 'o3-mini' }
      ]
    },
    {
      id: 'anthropic.client',
      vendor: 'Anthropic',
      product: 'Anthropic',
      service: 'AI Client',
      description: 'Anthropic client SDK for accessing Claude models',
      tags: ['ai', 'text', 'llm', 'api'],
      category: 'llm_providers',
      packages: {
        python: ['anthropic'],
        node: ['@anthropic-ai/sdk'],
        go: ['github.com/anthropics/anthropic-sdk-go'],
        java: ['com.anthropic:anthropic-sdk-java']
      },
      codePatterns: {
        python: [
          { pattern: /import\s+anthropic/i, weight: 5 },
          { pattern: /from\s+anthropic\s+import/i, weight: 5 },
          { pattern: /Anthropic\(/i, weight: 5 },
          { pattern: /messages\.create\(/i, weight: 4 }
        ],
        javascript: [
          { pattern: /from\s+['"]@anthropic-ai\/sdk['"]/i, weight: 5 },
          { pattern: /require\s*\(\s*['"]@anthropic-ai\/sdk['"]/i, weight: 5 },
          { pattern: /new\s+Anthropic\s*\(/i, weight: 5 }
        ]
      },
      apiEndpoints: [
        { pattern: /api\.anthropic\.com/i, weight: 4 }
      ],
      models: [
        { pattern: /claude-3-opus/i, name: 'Claude 3 Opus' },
        { pattern: /claude-3\.5-sonnet|claude-3-5-sonnet/i, name: 'Claude 3.5 Sonnet' },
        { pattern: /claude-3\.5-haiku|claude-3-5-haiku/i, name: 'Claude 3.5 Haiku' },
        { pattern: /claude-3-sonnet/i, name: 'Claude 3 Sonnet' },
        { pattern: /claude-3-haiku/i, name: 'Claude 3 Haiku' },
        { pattern: /claude-opus-4|claude-4-opus/i, name: 'Claude Opus 4' },
        { pattern: /claude-sonnet-4|claude-4-sonnet/i, name: 'Claude Sonnet 4' }
      ]
    },
    {
      id: 'google.generativeai',
      vendor: 'Google',
      product: 'Google AI',
      service: 'Generative AI Client',
      description: 'Google Generative AI SDK for accessing Gemini models',
      tags: ['ai', 'text', 'llm', 'api'],
      category: 'llm_providers',
      packages: {
        python: ['google-generativeai'],
        node: ['@google/generative-ai']
      },
      codePatterns: {
        python: [
          { pattern: /import\s+google\.generativeai/i, weight: 5 },
          { pattern: /genai\.GenerativeModel/i, weight: 5 },
          { pattern: /\.generate_content\(/i, weight: 4 }
        ],
        javascript: [
          { pattern: /from\s+['"]@google\/generative-ai['"]/i, weight: 5 },
          { pattern: /GoogleGenerativeAI/i, weight: 5 }
        ]
      },
      apiEndpoints: [
        { pattern: /generativelanguage\.googleapis\.com/i, weight: 4 }
      ],
      models: [
        { pattern: /gemini-2\.0-flash/i, name: 'Gemini 2.0 Flash' },
        { pattern: /gemini-2\.0-pro/i, name: 'Gemini 2.0 Pro' },
        { pattern: /gemini-1\.5-pro/i, name: 'Gemini 1.5 Pro' },
        { pattern: /gemini-1\.5-flash/i, name: 'Gemini 1.5 Flash' },
        { pattern: /gemini-pro/i, name: 'Gemini Pro' },
        { pattern: /gemma-2|gemma2/i, name: 'Gemma 2' }
      ]
    }
  ],

  // ==========================================================================
  // LLM FRAMEWORKS - Orchestration and abstraction layers
  // ==========================================================================
  llm_frameworks: [
    {
      id: 'langchain.core',
      vendor: 'LangChain',
      product: 'LangChain',
      service: 'Core Framework',
      description: 'LangChain core library for LLM application development',
      tags: ['ai', 'text', 'framework', 'orchestration'],
      category: 'llm_frameworks',
      packages: {
        python: ['langchain', 'langchain-core'],
        node: ['langchain', '@langchain/core'],
        go: ['github.com/tmc/langchaingo'],
        java: ['dev.langchain4j:langchain4j']
      },
      codePatterns: {
        python: [
          { pattern: /from\s+langchain/i, weight: 4 },
          { pattern: /import\s+langchain/i, weight: 4 }
        ],
        javascript: [
          { pattern: /from\s+['"]langchain/i, weight: 4 },
          { pattern: /require\s*\(\s*['"]langchain/i, weight: 4 },
          { pattern: /from\s+['"]@langchain\//i, weight: 4 }
        ]
      }
    },
    {
      id: 'llamaindex.core',
      vendor: 'LlamaCloud',
      product: 'LlamaIndex',
      service: 'Core Framework',
      description: 'LlamaIndex (formerly LlamaIndex) for LLM application development',
      tags: ['ai', 'text', 'framework', 'orchestration', 'rag'],
      category: 'llm_frameworks',
      packages: {
        python: ['llama-index', 'llama-index-core'],
        node: ['llamaindex']
      },
      codePatterns: {
        python: [
          { pattern: /from\s+llama_index/i, weight: 4 },
          { pattern: /import\s+llama_index/i, weight: 4 }
        ]
      }
    }
  ],

  // ==========================================================================
  // LOCAL INFERENCE - Running models locally
  // ==========================================================================
  local_inference: [
    {
      id: 'llamacpp.python',
      vendor: 'Llama.cpp',
      product: 'llama-cpp-python',
      service: 'Local LLM Inference',
      description: 'Python bindings for llama.cpp - efficient local LLM inference',
      tags: ['ai', 'text', 'llm', 'local', 'inference', 'cpp'],
      category: 'local_inference',
      packages: {
        python: ['llama-cpp-python']
      }
    },
    {
      id: 'transformers.huggingface',
      vendor: 'HuggingFace',
      product: 'Transformers',
      service: 'Local Model Inference',
      description: 'HuggingFace Transformers library for running models locally',
      tags: ['ai', 'text', 'llm', 'local', 'inference', 'huggingface'],
      category: 'local_inference',
      packages: {
        python: ['transformers', 'huggingface-hub']
      },
      codePatterns: {
        python: [
          { pattern: /from\s+transformers\s+import/i, weight: 4 },
          { pattern: /import\s+transformers/i, weight: 4 },
          { pattern: /pipeline\(|AutoModel/i, weight: 3 }
        ]
      }
    },
    {
      id: 'vllm.inference',
      vendor: 'vLLM',
      product: 'vLLM',
      service: 'High-throughput LLM Serving',
      description: 'vLLM library for efficient LLM inference and serving',
      tags: ['ai', 'text', 'llm', 'local', 'inference', 'serving', 'gpu'],
      category: 'local_inference',
      packages: {
        python: ['vllm']
      }
    },
    {
      id: 'ollama.client',
      vendor: 'Ollama',
      product: 'Ollama',
      service: 'Local LLM Server',
      description: 'Ollama client for running and managing local LLMs',
      tags: ['ai', 'text', 'llm', 'local', 'inference', 'server'],
      category: 'local_inference',
      packages: {
        python: ['ollama'],
        node: ['ollama']
      }
    }
  ],

  // ==========================================================================
  // VECTOR STORES - Semantic search infrastructure
  // ==========================================================================
  vector_stores: [
    {
      id: 'chromadb.client',
      vendor: 'Chroma',
      product: 'ChromaDB',
      service: 'Vector Database',
      description: 'Open-source embedding database for AI applications',
      tags: ['ai', 'embeddings', 'vector', 'database', 'search'],
      category: 'vector_stores',
      packages: {
        python: ['chromadb'],
        node: ['chromadb']
      }
    },
    {
      id: 'pinecone.client',
      vendor: 'Pinecone',
      product: 'Pinecone',
      service: 'Vector Database',
      description: 'Managed vector database for AI applications',
      tags: ['ai', 'embeddings', 'vector', 'database', 'search', 'managed'],
      category: 'vector_stores',
      packages: {
        python: ['pinecone-client'],
        node: ['@pinecone-database/pinecone'],
        go: ['github.com/pinecone-io/go-pinecone']
      }
    },
    {
      id: 'weaviate.client',
      vendor: 'Weaviate',
      product: 'Weaviate',
      service: 'Vector Database',
      description: 'Open-source vector database with hybrid search capabilities',
      tags: ['ai', 'embeddings', 'vector', 'database', 'search', 'hybrid'],
      category: 'vector_stores',
      packages: {
        python: ['weaviate-client'],
        go: ['github.com/weaviate/weaviate-go-client']
      }
    },
    {
      id: 'qdrant.client',
      vendor: 'Qdrant',
      product: 'Qdrant',
      service: 'Vector Database',
      description: 'Open-source vector similarity search engine',
      tags: ['ai', 'embeddings', 'vector', 'database', 'search'],
      category: 'vector_stores',
      packages: {
        python: ['qdrant-client'],
        node: ['qdrant-client']
      }
    },
    {
      id: 'sentence.transformers',
      vendor: 'HuggingFace',
      product: 'Sentence Transformers',
      service: 'Text Embeddings',
      description: 'Library for computing dense vector representations for sentences',
      tags: ['ai', 'embeddings', 'text', 'transformers'],
      category: 'vector_stores',
      packages: {
        python: ['sentence-transformers']
      }
    }
  ],

  // ==========================================================================
  // AI AGENTS - Autonomous systems and multi-agent frameworks
  // ==========================================================================
  ai_agents: [
    {
      id: 'crewai.framework',
      vendor: 'CrewAI',
      product: 'CrewAI',
      service: 'Multi-Agent Framework',
      description: 'Framework for orchestrating role-playing AI agents',
      tags: ['ai', 'agents', 'multi-agent', 'orchestration'],
      category: 'ai_agents',
      packages: {
        python: ['crewai']
      },
      codePatterns: {
        python: [
          { pattern: /from\s+crewai\s+import/i, weight: 4 },
          { pattern: /import\s+crewai/i, weight: 4 },
          { pattern: /Crew\(|Agent\(|Task\(/i, weight: 3 }
        ]
      }
    },
    {
      id: 'autogen.microsoft',
      vendor: 'Microsoft',
      product: 'AutoGen',
      service: 'Multi-Agent Framework',
      description: 'Microsoft AutoGen framework for building multi-agent systems',
      tags: ['ai', 'agents', 'multi-agent', 'orchestration', 'microsoft'],
      category: 'ai_agents',
      packages: {
        python: ['autogen']
      },
      codePatterns: {
        python: [
          { pattern: /from\s+autogen\s+import/i, weight: 4 },
          { pattern: /import\s+autogen/i, weight: 4 },
          { pattern: /AutoGen\(|AssistantAgent\(|UserProxyAgent\(/i, weight: 3 }
        ]
      }
    }
  ],

  // ==========================================================================
  // MCP PROTOCOL - Model Context Protocol implementations
  // ==========================================================================
  mcp_protocol: [
    {
      id: 'mcp.sdk',
      vendor: 'Anthropic',
      product: 'Model Context Protocol',
      service: 'SDK',
      description: 'Model Context Protocol SDK and implementations',
      tags: ['protocol', 'mcp', 'tools', 'agents'],
      category: 'mcp_protocol',
      packages: {
        python: ['mcp', 'anthropic-mcp', 'mcp-server', 'mcp-client'],
        node: ['@modelcontextprotocol/sdk', '@anthropic-ai/mcp', 'mcp-framework']
      },
      codePatterns: {
        python: [
          { pattern: /from\s+mcp\s+import/i, weight: 4, category: 'protocol' },
          { pattern: /import\s+mcp/i, weight: 4, category: 'protocol' },
          { pattern: /mcp\.server|mcp\.client/i, weight: 5, category: 'protocol' },
          { pattern: /McpServer\(|McpClient\(/i, weight: 5, category: 'protocol' }
        ],
        javascript: [
          { pattern: /from\s+['"]@modelcontextprotocol/i, weight: 5, category: 'protocol' },
          { pattern: /require\s*\(['"]@modelcontextprotocol/i, weight: 5, category: 'protocol' },
          { pattern: /McpServer|McpClient/i, weight: 4, category: 'protocol' },
          { pattern: /StdioServerTransport|SSEServerTransport/i, weight: 4, category: 'protocol' }
        ]
      },
      configFiles: [
        'mcp.json',
        'mcp-config.json',
        'mcp-servers.json',
        'mcp_config.json',
        'mcp_servers.json',
        '.mcp/config.json',
        '.mcp/servers.json',
        'claude_desktop_config.json',
        '.cursor/mcp.json',
        'cursor-mcp.json'
      ],
      jsonPatterns: [
        { key: 'mcpServers', type: 'MCP Server Config' },
        { key: 'mcp-servers', type: 'MCP Server Config' },
        { key: 'modelContextProtocol', type: 'MCP Config' }
      ]
    }
  ],

  // ==========================================================================
  // A2A PROTOCOLS - Agent-to-Agent communication protocols
  // ==========================================================================
  a2a_protocols: [
    {
      id: 'agent.protocol',
      vendor: 'Agent Protocol',
      product: 'Agent Protocol',
      service: 'A2A Communication',
      description: 'Agent-to-Agent communication protocol for AI agents',
      tags: ['protocol', 'a2a', 'agents', 'communication'],
      category: 'a2a_protocols',
      packages: {
        python: ['agent-protocol', 'a2a', 'agent-communication-protocol', 'uagents'],
        node: ['agent-protocol', '@agent-protocol/client', '@agent-protocol/sdk']
      },
      codePatterns: {
        python: [
          { pattern: /agent-protocol|AgentProtocol/i, weight: 4, category: 'protocol' },
          { pattern: /from\s+agent_protocol/i, weight: 4, category: 'protocol' },
          { pattern: /TaskRequest|TaskResponse|AgentMessage/i, weight: 3, category: 'protocol' }
        ],
        javascript: [
          { pattern: /agent-protocol/i, weight: 4, category: 'protocol' },
          { pattern: /@agent-protocol\//i, weight: 4, category: 'protocol' }
        ]
      }
    }
  ],

  // ==========================================================================
  // PLUGIN SYSTEMS - Tool calling and function execution
  // ==========================================================================
  plugin_systems: [
    {
      id: 'langchain.tools',
      vendor: 'LangChain',
      product: 'LangChain Tools',
      service: 'Tool Integration',
      description: 'LangChain tools and function calling capabilities',
      tags: ['ai', 'tools', 'function-calling', 'plugins'],
      category: 'plugin_systems',
      codePatterns: {
        python: [
          { pattern: /tool\s*\(\s*["'].*["']\s*,\s*["'].*["']\s*\)/i, weight: 3 },
          { pattern: /\.register_tool\s*\(|\.add_tool\s*\(/i, weight: 4 },
          { pattern: /ToolMessage|CallToolResult/i, weight: 3 }
        ]
      }
    }
  ],

  // ==========================================================================
  // RAG DOCUMENT PROCESSING - Document loading and processing
  // ==========================================================================
  rag_document: [
    {
      id: 'unstructured.io',
      vendor: 'Unstructured',
      product: 'Unstructured',
      service: 'Document Processing',
      description: 'Open-source document processing library for RAG applications',
      tags: ['ai', 'documents', 'processing', 'rag', 'parsing'],
      category: 'rag_document',
      packages: {
        python: ['unstructured'],
        node: ['unstructured-client']
      }
    },
    {
      id: 'llamaparse.cloud',
      vendor: 'LlamaCloud',
      product: 'LlamaParse',
      service: 'Document Parsing',
      description: 'Advanced document parsing for LLM applications',
      tags: ['ai', 'documents', 'processing', 'rag', 'parsing', 'cloud'],
      category: 'rag_document',
      packages: {
        python: ['llama-parse']
      }
    }
  ],

  // ==========================================================================
  // PROMPT EVALUATION - Testing and evaluation tools
  // ==========================================================================
  prompt_eval: [
    {
      id: 'ragas.evaluation',
      vendor: 'Exploding Gradients',
      product: 'RAGAS',
      service: 'RAG Evaluation',
      description: 'Framework for evaluating RAG (Retrieval-Augmented Generation) systems',
      tags: ['ai', 'evaluation', 'rag', 'testing', 'metrics'],
      category: 'prompt_eval',
      packages: {
        python: ['ragas']
      }
    },
    {
      id: 'deepeval.testing',
      vendor: 'DeepEval',
      product: 'DeepEval',
      service: 'LLM Evaluation',
      description: 'Open-source evaluation framework for LLM applications',
      tags: ['ai', 'evaluation', 'testing', 'metrics'],
      category: 'prompt_eval',
      packages: {
        python: ['deepeval']
      }
    },
    {
      id: 'promptfoo.testing',
      vendor: 'PromptFoo',
      product: 'PromptFoo',
      service: 'Prompt Testing',
      description: 'Open-source tool for testing and evaluating LLM prompts',
      tags: ['ai', 'evaluation', 'prompts', 'testing'],
      category: 'prompt_eval',
      packages: {
        python: ['promptfoo'],
        node: ['promptfoo']
      }
    }
  ],

  // ==========================================================================
  // AI DEV TOOLS - IDE plugins and AI-assisted coding (low confidence)
  // ==========================================================================
  ai_dev_tools: [
    {
      id: 'anthropic.claude.code',
      vendor: 'Anthropic',
      product: 'Claude Code',
      service: 'AI-Assisted Coding',
      description: 'Anthropic Claude Code for AI-assisted development',
      tags: ['ai', 'development', 'coding', 'assistant', 'ide'],
      category: 'ai_dev_tools',
      packages: {
        node: ['@anthropic-ai/claude-code']
      },
      configFiles: [
        'CLAUDE.md',
        'claude.md',
        '.claude'
      ]
    },
    {
      id: 'cursor.ide',
      vendor: 'Cursor',
      product: 'Cursor IDE',
      service: 'AI-Assisted Coding',
      description: 'Cursor IDE with AI-assisted development features',
      tags: ['ai', 'development', 'coding', 'assistant', 'ide'],
      category: 'ai_dev_tools',
      configFiles: [
        '.cursor',
        '.cursor/rules',
        '.cursorrules',
        '.cursorignore',
        'cursor.json'
      ]
    },
    {
      id: 'github.copilot',
      vendor: 'GitHub',
      product: 'GitHub Copilot',
      service: 'AI Code Completion',
      description: 'GitHub Copilot AI coding assistant',
      tags: ['ai', 'development', 'coding', 'completion', 'ide'],
      category: 'ai_dev_tools',
      configFiles: [
        '.github/copilot',
        '.github/copilot-instructions.md',
        'copilot-instructions.md'
      ]
    }
  ]
};

// ============================================================================
// BACKWARD COMPATIBILITY - Generate existing constants from signatures
// ============================================================================
// Helper functions to generate the old constant structures from signatures
// ============================================================================

function generatePackageRegistry() {
  const registry = {
    llm_providers: {},
    llm_frameworks: {},
    local_inference: {},
    vector_stores: {},
    ai_agents: {},
    mcp_protocol: {},
    a2a_protocols: {},
    plugin_systems: {},
    rag_document: {},
    prompt_eval: {}
  };

  // Flatten all signatures and group by category
  const allSignatures = Object.values(AI_SIGNATURES).flat();

  for (const sig of allSignatures) {
    const category = sig.category;
    if (!registry[category]) continue;

    if (sig.packages) {
      for (const [lang, pkgs] of Object.entries(sig.packages)) {
        if (!registry[category][lang]) registry[category][lang] = [];
        registry[category][lang].push(...pkgs);
      }
    }
  }

  return registry;
}

function generateSDKPatterns() {
  const patterns = { python: [], javascript: [] };

  const allSignatures = Object.values(AI_SIGNATURES).flat();

  for (const sig of allSignatures) {
    if (sig.codePatterns) {
      for (const [lang, langPatterns] of Object.entries(sig.codePatterns)) {
        const targetLang = lang === 'javascript' ? 'javascript' : lang;
        if (!patterns[targetLang]) patterns[targetLang] = [];

        patterns[targetLang].push(...langPatterns.map(p => ({
          ...p,
          provider: sig.vendor,
          category: sig.category
        })));
      }
    }
  }

  return patterns;
}

function generateModelPatterns() {
  const patterns = [];

  const allSignatures = Object.values(AI_SIGNATURES).flat();

  for (const sig of allSignatures) {
    if (sig.models) {
      for (const model of sig.models) {
        patterns.push({
          pattern: model.pattern,
          provider: sig.vendor,
          model: model.name
        });
      }
    }
  }

  return patterns;
}

function generateAPIEndpoints() {
  const endpoints = [];

  const allSignatures = Object.values(AI_SIGNATURES).flat();

  for (const sig of allSignatures) {
    if (sig.apiEndpoints) {
      for (const endpoint of sig.apiEndpoints) {
        endpoints.push({
          pattern: endpoint.pattern,
          provider: sig.vendor,
          weight: endpoint.weight
        });
      }
    }
  }

  return endpoints;
}

function generateExtendedDependencies() {
  const extended = {
    python: [
      ...AI_PACKAGE_REGISTRY.llm_providers.python || [],
      ...AI_PACKAGE_REGISTRY.llm_frameworks.python || [],
      ...AI_PACKAGE_REGISTRY.local_inference.python || [],
      ...AI_PACKAGE_REGISTRY.vector_stores.python || [],
      ...AI_PACKAGE_REGISTRY.ai_agents?.python || [],
      ...AI_PACKAGE_REGISTRY.mcp_protocol?.python || [],
      ...AI_PACKAGE_REGISTRY.a2a_protocols?.python || [],
      ...AI_PACKAGE_REGISTRY.plugin_systems?.python || [],
      ...AI_PACKAGE_REGISTRY.rag_document?.python || [],
      ...AI_PACKAGE_REGISTRY.prompt_eval?.python || []
    ],
    node: [
      ...AI_PACKAGE_REGISTRY.llm_providers.node || [],
      ...AI_PACKAGE_REGISTRY.llm_frameworks.node || [],
      ...AI_PACKAGE_REGISTRY.local_inference.node || [],
      ...AI_PACKAGE_REGISTRY.vector_stores.node || [],
      ...AI_PACKAGE_REGISTRY.ai_agents?.node || [],
      ...AI_PACKAGE_REGISTRY.mcp_protocol?.node || [],
      ...AI_PACKAGE_REGISTRY.a2a_protocols?.node || [],
      ...AI_PACKAGE_REGISTRY.plugin_systems?.node || [],
      ...AI_PACKAGE_REGISTRY.rag_document?.node || [],
      ...AI_PACKAGE_REGISTRY.prompt_eval?.node || []
    ],
    go: [...AI_PACKAGE_REGISTRY.llm_providers.go || [], ...AI_PACKAGE_REGISTRY.llm_frameworks.go || []],
    java: [...AI_PACKAGE_REGISTRY.llm_providers.java || [], ...AI_PACKAGE_REGISTRY.llm_frameworks.java || []],
    rust: [
      ...AI_PACKAGE_REGISTRY.llm_providers.rust || [],
      ...AI_PACKAGE_REGISTRY.llm_frameworks.rust || [],
      ...AI_PACKAGE_REGISTRY.mcp_protocol?.rust || []
    ]
  };

  return extended;
}

function generateProtocolPatterns() {
  return {
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
}

function generateDevTools() {
  return {
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
}

// Generate backward-compatible constants
const AI_PACKAGE_REGISTRY = generatePackageRegistry();
const SDK_PATTERNS = generateSDKPatterns();
const MODEL_PATTERNS = generateModelPatterns();
const API_ENDPOINTS = generateAPIEndpoints();
const AI_EXTENDED_DEPENDENCIES = generateExtendedDependencies();
const AI_PROTOCOL_PATTERNS = generateProtocolPatterns();
const AI_DEV_TOOLS = generateDevTools();

// ============================================================================
// STATIC CONSTANTS - Not signature-based
const MANIFEST_FILES = {
    python: ['requirements.txt', 'pyproject.toml', 'Pipfile', 'Pipfile.lock', 'setup.py', 'poetry.lock'],
    node: ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
    go: ['go.mod', 'go.sum'],
    java: ['pom.xml', 'build.gradle', 'build.gradle.kts'],
    rust: ['Cargo.toml', 'Cargo.lock']
};



// CONFIG_PATTERNS removed - we don't scan for API keys anymore
// Reasons:
// 1. Good projects don't commit API keys (use env vars at runtime)
// 2. Code/dependencies are better AI indicators
// 3. Security: shouldn't log or expose secret references


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
    distributed_training: {
        dependencies: ['deepspeed', 'horovod', 'megatron', 'torch.distributed', 'ray[train]'],
        patterns: [
            // DeepSpeed
            { pattern: /deepspeed|DeepSpeed/i, framework: 'DeepSpeed', weight: 5 },
            { pattern: /from\s+deepspeed/i, framework: 'DeepSpeed', weight: 5 },
            { pattern: /import\s+deepspeed/i, framework: 'DeepSpeed', weight: 5 },
            // Horovod
            { pattern: /horovod|Horovod/i, framework: 'Horovod', weight: 5 },
            { pattern: /import\s+horovod/i, framework: 'Horovod', weight: 5 },
            // Megatron-LM
            { pattern: /megatron|Megatron/i, framework: 'Megatron-LM', weight: 5 },
            { pattern: /from\s+megatron/i, framework: 'Megatron-LM', weight: 5 },
            // PyTorch Distributed
            { pattern: /torch\.distributed|torch\.nn\.parallel/i, framework: 'PyTorch Distributed', weight: 4 },
            { pattern: /DistributedDataParallel|DDP/i, framework: 'PyTorch DDP', weight: 4 },
            { pattern: /FullyShardedDataParallel|FSDP/i, framework: 'PyTorch FSDP', weight: 4 },
            // Ray
            { pattern: /ray\.train|ray\[train\]/i, framework: 'Ray Train', weight: 4 },
            { pattern: /from\s+ray\.train/i, framework: 'Ray Train', weight: 4 },
            // Accelerate
            { pattern: /accelerate|Accelerate/i, framework: 'HuggingFace Accelerate', weight: 4 },
            { pattern: /from\s+accelerate/i, framework: 'HuggingFace Accelerate', weight: 4 }
        ]
    },
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
        dependencies: ['tensorrt', 'openvino', 'onnxruntime-gpu', 'onnxruntime', 'coreml', 'tflite', 'edgetpu', 'mps'],
        patterns: [
            // NVIDIA TensorRT
            { pattern: /tensorrt|trt\b/i, type: 'TensorRT', weight: 4 },
            { pattern: /torch_tensorrt|torch2trt/i, type: 'TensorRT', weight: 4 },
            // Intel OpenVINO
            { pattern: /openvino/i, type: 'OpenVINO', weight: 4 },
            { pattern: /openvino\.convert_model/i, type: 'OpenVINO', weight: 4 },
            // ONNX Runtime
            { pattern: /\b(onnxruntime|ort)\b/i, type: 'ONNX Runtime', weight: 4 },
            { pattern: /\bonnx\.export\b/i, type: 'ONNX Export', weight: 4 },
            // Apple CoreML
            { pattern: /coreml|core_ml/i, type: 'CoreML', weight: 4 },
            { pattern: /coremltools/i, type: 'CoreML Tools', weight: 4 },
            // TensorFlow Lite
            { pattern: /tflite|\.tflite/i, type: 'TensorFlow Lite', weight: 4 },
            { pattern: /tf\.lite|TFLiteConverter/i, type: 'TensorFlow Lite', weight: 4 },
            // Google Edge TPU
            { pattern: /edgetpu|edge_tpu/i, type: 'Edge TPU', weight: 4 },
            // Apple Metal Performance Shaders
            { pattern: /\bmps\b|metal.*performance/i, type: 'Metal Performance Shaders', weight: 3 },
            // Generic edge optimization
            { pattern: /quantize|quantization/i, type: 'Model Quantization', weight: 3 },
            { pattern: /prune|pruning/i, type: 'Model Pruning', weight: 3 }
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
    model_serving: {
        dependencies: ['torchserve', 'tensorflow-serving', 'tritonserver', 'bento', 'cortex', 'seldon-core', 'kserve'],
        patterns: [
            // TorchServe
            { pattern: /torchserve|torch\.serve/i, framework: 'TorchServe', weight: 5 },
            { pattern: /torch\.model_archiver/i, framework: 'TorchServe', weight: 4 },
            // TensorFlow Serving
            { pattern: /tensorflow.*serving|tf\.serving/i, framework: 'TensorFlow Serving', weight: 5 },
            { pattern: /saved_model|SavedModel/i, framework: 'TensorFlow Serving', weight: 3 },
            // Triton Inference Server
            { pattern: /triton|tritonserver/i, framework: 'Triton Inference Server', weight: 5 },
            { pattern: /tritonclient/i, framework: 'Triton Client', weight: 4 },
            // BentoML
            { pattern: /bentoml|bento/i, framework: 'BentoML', weight: 5 },
            { pattern: /@bentoml/i, framework: 'BentoML', weight: 4 },
            // Cortex
            { pattern: /cortex/i, framework: 'Cortex', weight: 4 },
            // Seldon
            { pattern: /seldon/i, framework: 'Seldon', weight: 4 },
            // KServe
            { pattern: /kserve/i, framework: 'KServe', weight: 4 },
            // Generic serving patterns
            { pattern: /model.*serving|inference.*server/i, framework: 'Model Serving', weight: 3 }
        ]
    },
    mlops: {
        dependencies: ['mlflow', 'wandb', 'tensorboard', 'clearml', 'neptune-client', 'comet-ml', 'aim', 'sacred'],
        patterns: [
            // Weights & Biases
            { pattern: /wandb\.init\s*\(\s*['"]([^'"]+)['"]/i, platform: 'Weights & Biases', weight: 5, extractProject: true },
            { pattern: /wandb\.init\s*\(\s*project\s*=\s*['"]([^'"]+)['"]/i, platform: 'Weights & Biases', weight: 5, extractProject: true },
            { pattern: /from\s+wandb/i, platform: 'Weights & Biases', weight: 4 },
            { pattern: /import\s+wandb/i, platform: 'Weights & Biases', weight: 4 },
            // MLflow
            { pattern: /mlflow\.start_run\s*\(\s*experiment_name\s*=\s*['"]([^'"]+)['"]/i, platform: 'MLflow', weight: 5, extractProject: true },
            { pattern: /mlflow\.set_experiment\s*\(\s*['"]([^'"]+)['"]/i, platform: 'MLflow', weight: 5, extractProject: true },
            { pattern: /from\s+mlflow/i, platform: 'MLflow', weight: 4 },
            { pattern: /import\s+mlflow/i, platform: 'MLflow', weight: 4 },
            // ClearML
            { pattern: /clearml\.Task\.init\s*\(\s*project_name\s*=\s*['"]([^'"]+)['"]/i, platform: 'ClearML', weight: 5, extractProject: true },
            { pattern: /from\s+clearml/i, platform: 'ClearML', weight: 4 },
            { pattern: /import\s+clearml/i, platform: 'ClearML', weight: 4 },
            // Comet ML
            { pattern: /comet_ml\.Experiment\s*\(\s*api_key\s*=\s*['"]([^'"]+)['"]/i, platform: 'Comet ML', weight: 4, extractApiKey: true },
            { pattern: /comet_ml\.Experiment\s*\(\s*project_name\s*=\s*['"]([^'"]+)['"]/i, platform: 'Comet ML', weight: 5, extractProject: true },
            { pattern: /from\s+comet_ml/i, platform: 'Comet ML', weight: 4 },
            { pattern: /import\s+comet_ml/i, platform: 'Comet ML', weight: 4 },
            // Neptune
            { pattern: /neptune\.init\s*\(\s*project\s*=\s*['"]([^'"]+)['"]/i, platform: 'Neptune', weight: 5, extractProject: true },
            { pattern: /from\s+neptune/i, platform: 'Neptune', weight: 4 },
            { pattern: /import\s+neptune/i, platform: 'Neptune', weight: 4 },
            // TensorBoard
            { pattern: /tensorboard/i, platform: 'TensorBoard', weight: 3 },
            // Aim
            { pattern: /from\s+aim\b/i, platform: 'Aim', weight: 4 },
            { pattern: /import\s+aim\b/i, platform: 'Aim', weight: 4 },
            // Sacred
            { pattern: /from\s+sacred/i, platform: 'Sacred', weight: 4 },
            { pattern: /import\s+sacred/i, platform: 'Sacred', weight: 4 }
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
        dependencies: ['datasets', 'huggingface-datasets', 'pandas', 'numpy', 'dask', 'ray', 'kaggle', 'kagglehub'],
        patterns: [
            // HuggingFace datasets
            { pattern: /datasets\.load_dataset\(['"]([^'"]+)['"]/i, tool: 'HuggingFace Datasets', weight: 5, extractDataset: true },
            { pattern: /load_dataset\(['"]([^'"]+)['"]/i, tool: 'HuggingFace Datasets', weight: 5, extractDataset: true },
            // Kaggle datasets
            { pattern: /kagglehub\.dataset_download\(['"]([^'"]+)['"]/i, tool: 'Kaggle Datasets', weight: 4, extractDataset: true },
            { pattern: /kaggle\.api\.dataset_download/i, tool: 'Kaggle API', weight: 4 },
            // Pandas loading
            { pattern: /pd\.read_csv\(['"]([^'"]*\.(csv|tsv))['"]/i, tool: 'Pandas CSV', weight: 3, extractDataset: true },
            { pattern: /pd\.read_json\(['"]([^'"]*\.json)['"]/i, tool: 'Pandas JSON', weight: 3, extractDataset: true },
            { pattern: /pd\.read_parquet\(['"]([^'"]*\.parquet)['"]/i, tool: 'Pandas Parquet', weight: 3, extractDataset: true },
            // NumPy loading
            { pattern: /np\.load\(['"]([^'"]*\.npy)['"]/i, tool: 'NumPy', weight: 2, extractDataset: true },
            { pattern: /np\.loadtxt\(['"]([^'"]*\.txt)['"]/i, tool: 'NumPy', weight: 2, extractDataset: true }
        ]
    },
    preprocessing: {
        dependencies: ['scikit-learn', 'sklearn', 'nltk', 'spacy', 'transformers', 'torchvision', 'albumentations'],
        patterns: [
            { pattern: /from\s+sklearn\.preprocessing/i, tool: 'scikit-learn preprocessing', weight: 3 },
            { pattern: /AutoTokenizer|Tokenizer/i, tool: 'Tokenization', weight: 4 },
            { pattern: /transforms\.|Compose\(/i, tool: 'Data augmentation', weight: 3 },
            { pattern: /ImageDataGenerator|\baugment\b/i, tool: 'Image augmentation', weight: 3 }
        ]
    },
    feature_engineering: {
        patterns: [
            // Tokenization
            { pattern: /AutoTokenizer|Tokenizer/i, tool: 'Tokenization', weight: 4 },
            { pattern: /nltk\.word_tokenize|nltk\.sent_tokenize/i, tool: 'NLTK Tokenization', weight: 3 },
            { pattern: /spacy\.load.*tokenize/i, tool: 'spaCy Tokenization', weight: 3 },
            // Normalization
            { pattern: /StandardScaler|MinMaxScaler|Normalizer/i, tool: 'Feature Scaling', weight: 3 },
            { pattern: /LabelEncoder|OneHotEncoder/i, tool: 'Categorical Encoding', weight: 3 },
            { pattern: /TfidfVectorizer|CountVectorizer/i, tool: 'Text Vectorization', weight: 3 },
            // Feature Selection
            { pattern: /SelectKBest|SelectPercentile|RFE/i, tool: 'Feature Selection', weight: 3 },
            { pattern: /PCA|TSNE|UMAP|TruncatedSVD/i, tool: 'Dimensionality Reduction', weight: 3 },
            { pattern: /FeatureExtractor|feature_extraction/i, tool: 'Feature Extraction', weight: 3 },
            // Text Processing
            { pattern: /Stemmer|Lemmatizer/i, tool: 'Text Normalization', weight: 3 },
            { pattern: /stopwords|StopWords/i, tool: 'Stopword Removal', weight: 3 }
        ]
    },
    data_versioning: {
        files: ['dvc.yaml', '.dvc/', 'data_version.txt', 'pachyderm.json'],
        dependencies: ['dvc', 'pachyderm', 'dvc[s3]', 'dvc[gdrive]'],
        patterns: [
            { pattern: /dvc\s+(add|commit|push|pull)/i, tool: 'DVC', weight: 4 },
            { pattern: /pachctl/i, tool: 'Pachyderm', weight: 4 },
            { pattern: /from\s+dvc/i, tool: 'DVC Python', weight: 4 },
            { pattern: /import\s+pachyderm/i, tool: 'Pachyderm Python', weight: 4 }
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

// ============================================================================
// FINE-TUNING TECHNIQUES PATTERNS
// ============================================================================
const FINE_TUNING_PATTERNS = {
    dependencies: ['peft', 'lora', 'qlora', 'adapters', 'bitsandbytes', 'accelerate'],
    patterns: [
        // Parameter-Efficient Fine-Tuning (PEFT)
        { pattern: /peft|PEFT/i, technique: 'PEFT', weight: 5 },
        { pattern: /from\s+peft/i, technique: 'PEFT', weight: 5 },
        // LoRA (Low-Rank Adaptation)
        { pattern: /lora|LoRA/i, technique: 'LoRA', weight: 5 },
        { pattern: /LoraConfig|LoraModel/i, technique: 'LoRA', weight: 5 },
        // QLoRA (Quantized LoRA)
        { pattern: /qlora|QLoRA/i, technique: 'QLoRA', weight: 5 },
        // Adapters
        { pattern: /adapter|Adapter/i, technique: 'Adapters', weight: 4 },
        { pattern: /AdapterConfig|add_adapter/i, technique: 'Adapters', weight: 4 },
        // Bit and Bytes (quantization for QLoRA)
        { pattern: /bitsandbytes|BitsAndBytes/i, technique: 'Quantization', weight: 4 },
        { pattern: /from\s+bitsandbytes/i, technique: 'Quantization', weight: 4 },
        // Accelerate (for distributed training/fine-tuning)
        { pattern: /accelerate|Accelerate/i, technique: 'Accelerate', weight: 3 },
        { pattern: /from\s+accelerate/i, technique: 'Accelerate', weight: 3 },
        // Generic fine-tuning patterns
        { pattern: /fine.*tun|finetun/i, technique: 'Fine-tuning', weight: 3 },
        { pattern: /train.*model|model.*train/i, technique: 'Model Training', weight: 2 },
        { pattern: /checkpoint|Checkpoint/i, technique: 'Checkpointing', weight: 2 }
    ]
};

// ============================================================================
// BIAS & FAIRNESS ASSESSMENT PATTERNS
// ============================================================================
const BIAS_FAIRNESS_PATTERNS = {
    dependencies: ['aif360', 'fairlearn', 'fairness-indicators', 'responsible-ai-toolbox', 'fairml'],
    patterns: [
        // AI Fairness 360 (AIF360)
        { pattern: /aif360|aif-360/i, tool: 'AI Fairness 360', weight: 4 },
        { pattern: /from\s+aif360/i, tool: 'AI Fairness 360', weight: 4 },
        // Fairlearn
        { pattern: /fairlearn/i, tool: 'Fairlearn', weight: 4 },
        { pattern: /from\s+fairlearn/i, tool: 'Fairlearn', weight: 4 },
        // TensorFlow Fairness Indicators
        { pattern: /fairness.*indicators|fairness_indicators/i, tool: 'Fairness Indicators', weight: 4 },
        { pattern: /tfma.*fairness/i, tool: 'TensorFlow Model Analysis Fairness', weight: 4 },
        // Responsible AI Toolbox
        { pattern: /responsible.*ai.*toolbox|rrai/i, tool: 'Responsible AI Toolbox', weight: 4 },
        { pattern: /responsibleai/i, tool: 'Responsible AI Toolbox', weight: 4 },
        // FairML
        { pattern: /\bfairml\b/i, tool: 'FairML', weight: 3 },
        // Generic bias/fairness patterns
        { pattern: /demographic.*parity|equal.*opportunity/i, tool: 'Fairness Metrics', weight: 3 },
        { pattern: /bias.*detection|bias.*assessment/i, tool: 'Bias Detection', weight: 3 },
        { pattern: /fairness.*score|fairness.*metric/i, tool: 'Fairness Evaluation', weight: 3 },
        { pattern: /disparate.*impact|adverse.*impact/i, tool: 'Impact Assessment', weight: 3 }
    ]
};

// ============================================================================
// MODEL MONITORING PATTERNS
// ============================================================================
const MONITORING_PATTERNS = {
    dependencies: ['evidently', 'whylogs', 'arize', 'fiddler', 'alibi-detect', 'deepchecks'],
    patterns: [
        // Evidently AI
        { pattern: /\bevidently\b|evidently\.ai/i, tool: 'Evidently AI', weight: 4 },
        { pattern: /from\s+evidently/i, tool: 'Evidently AI', weight: 4 },
        // WhyLogs
        { pattern: /whylogs|why-logs/i, tool: 'WhyLogs', weight: 4 },
        { pattern: /from\s+whylogs/i, tool: 'WhyLogs', weight: 4 },
        // Arize AI
        { pattern: /\barize\b/i, tool: 'Arize AI', weight: 4 },
        { pattern: /from\s+arize/i, tool: 'Arize AI', weight: 4 },
        // Fiddler AI
        { pattern: /\bfiddler\b|fiddler\.ai/i, tool: 'Fiddler AI', weight: 4 },
        { pattern: /from\s+fiddler/i, tool: 'Fiddler AI', weight: 4 },
        // Alibi Detect
        { pattern: /alibi.*detect|alibi_detect/i, tool: 'Alibi Detect', weight: 4 },
        { pattern: /from\s+alibi_detect/i, tool: 'Alibi Detect', weight: 4 },
        // DeepChecks
        { pattern: /deepchecks/i, tool: 'DeepChecks', weight: 4 },
        { pattern: /from\s+deepchecks/i, tool: 'DeepChecks', weight: 4 },
        // Generic monitoring patterns
        { pattern: /drift.*detection|data.*drift/i, tool: 'Drift Detection', weight: 3 },
        { pattern: /model.*monitoring|performance.*monitoring/i, tool: 'Model Monitoring', weight: 3 },
        { pattern: /anomaly.*detection/i, tool: 'Anomaly Detection', weight: 3 }
    ]
};

// ============================================================================
// HYPERPARAMETER OPTIMIZATION PATTERNS
// ============================================================================
const HPO_PATTERNS = {
    dependencies: ['optuna', 'ray[tune]', 'hyperopt', 'nevergrad', 'scikit-optimize', 'bayesian-optimization'],
    patterns: [
        // Optuna
        { pattern: /optuna\.create_study\s*\(/i, framework: 'Optuna', weight: 5 },
        { pattern: /optuna\.Trial/i, framework: 'Optuna', weight: 4 },
        { pattern: /from\s+optuna/i, framework: 'Optuna', weight: 4 },
        { pattern: /import\s+optuna/i, framework: 'Optuna', weight: 4 },
        // Ray Tune
        { pattern: /ray\.tune\.run\s*\(/i, framework: 'Ray Tune', weight: 5 },
        { pattern: /ray\.tune\.report\s*\(/i, framework: 'Ray Tune', weight: 4 },
        { pattern: /from\s+ray\s+import\s+tune/i, framework: 'Ray Tune', weight: 4 },
        { pattern: /import\s+ray/i, framework: 'Ray Tune', weight: 3 },
        // Hyperopt
        { pattern: /hyperopt\.fmin\s*\(/i, framework: 'Hyperopt', weight: 5 },
        { pattern: /hyperopt\.Trials/i, framework: 'Hyperopt', weight: 4 },
        { pattern: /from\s+hyperopt/i, framework: 'Hyperopt', weight: 4 },
        { pattern: /import\s+hyperopt/i, framework: 'Hyperopt', weight: 4 },
        // Nevergrad
        { pattern: /nevergrad\.Instrumentation/i, framework: 'Nevergrad', weight: 4 },
        { pattern: /nevergrad\.Optimizer/i, framework: 'Nevergrad', weight: 4 },
        { pattern: /from\s+nevergrad/i, framework: 'Nevergrad', weight: 4 },
        { pattern: /import\s+nevergrad/i, framework: 'Nevergrad', weight: 4 },
        // Scikit-Optimize
        { pattern: /skopt\.gp_minimize/i, framework: 'Scikit-Optimize', weight: 4 },
        { pattern: /from\s+skopt/i, framework: 'Scikit-Optimize', weight: 4 },
        { pattern: /import\s+skopt/i, framework: 'Scikit-Optimize', weight: 4 },
        // Generic HPO patterns
        { pattern: /grid_search|GridSearchCV/i, framework: 'Grid Search', weight: 3 },
        { pattern: /random_search|RandomizedSearchCV/i, framework: 'Random Search', weight: 3 },
        { pattern: /bayesian.*optimization/i, framework: 'Bayesian Optimization', weight: 3 }
    ]
};

// ============================================================================
// EU AI ACT RISK CLASSIFICATION
// ============================================================================
const EU_AI_ACT_RISK_INDICATORS = {
    // High-risk AI systems (Annex III)
    highRisk: {
        patterns: [
            // Biometric identification and categorization
            { pattern: /facial.*recognition|face.*recognition/i, risk: 'high', category: 'biometric', reason: 'Biometric identification system' },
            { pattern: /emotion.*recognition|mood.*detection/i, risk: 'limited', category: 'biometric', reason: 'Emotion recognition system' },
            // Critical infrastructure
            { pattern: /critical.*infrastructure|infrastructure.*management/i, risk: 'high', category: 'infrastructure', reason: 'Critical infrastructure management' },
            { pattern: /power.*grid|energy.*system/i, risk: 'high', category: 'infrastructure', reason: 'Energy infrastructure' },
            { pattern: /transport.*management|traffic.*control/i, risk: 'high', category: 'infrastructure', reason: 'Transport management' },
            { pattern: /water.*management|drinking.*water/i, risk: 'high', category: 'infrastructure', reason: 'Water management' },
            // Education and vocational training
            { pattern: /education.*assessment|student.*evaluation/i, risk: 'high', category: 'education', reason: 'Educational assessment system' },
            { pattern: /vocational.*training|career.*guidance/i, risk: 'high', category: 'education', reason: 'Vocational training system' },
            // Employment and workers management
            { pattern: /employment.*decision|hiring.*decision/i, risk: 'high', category: 'employment', reason: 'Employment decision system' },
            { pattern: /worker.*management|employee.*evaluation/i, risk: 'high', category: 'employment', reason: 'Worker management system' },
            // Access to essential services
            { pattern: /credit.*scoring|loan.*approval/i, risk: 'high', category: 'finance', reason: 'Credit scoring system' },
            { pattern: /insurance.*pricing|risk.*assessment/i, risk: 'high', category: 'finance', reason: 'Insurance assessment' },
            // Law enforcement
            { pattern: /law.*enforcement|crime.*prediction/i, risk: 'high', category: 'law_enforcement', reason: 'Law enforcement system' },
            { pattern: /migration.*control|border.*control/i, risk: 'high', category: 'law_enforcement', reason: 'Migration control' },
            // Democratic processes
            { pattern: /voting.*system|election.*monitoring/i, risk: 'high', category: 'democracy', reason: 'Democratic process system' }
        ]
    },
    // Limited-risk AI systems
    limitedRisk: {
        patterns: [
            { pattern: /chatbot|conversational.*ai/i, risk: 'limited', category: 'chatbot', reason: 'Chatbot or conversational AI' },
            { pattern: /emotion.*recognition|mood.*detection/i, risk: 'limited', category: 'emotion', reason: 'Emotion recognition' },
            { pattern: /biometric.*categorization/i, risk: 'limited', category: 'biometric', reason: 'Biometric categorization' }
        ]
    },
    // Minimal-risk AI systems (default)
    minimalRisk: {
        patterns: [
            { pattern: /spam.*filter|content.*moderation/i, risk: 'minimal', category: 'content', reason: 'Content moderation' },
            { pattern: /recommendation.*system/i, risk: 'minimal', category: 'recommendation', reason: 'Recommendation system' },
            { pattern: /image.*generation|text.*generation/i, risk: 'minimal', category: 'generation', reason: 'Generative AI' }
        ]
    }
};

// ============================================================================
// NIST AI RMF COMPLIANCE INDICATORS
// ============================================================================
const NIST_AI_RMF_COMPLIANCE = {
    // GOVERN function - Governance and organizational structures
    govern: {
        indicators: [
            { pattern: /model.*card|MODEL_CARD/i, weight: 1, category: 'documentation' },
            { pattern: /readme|README/i, weight: 1, category: 'documentation' },
            { pattern: /security|SECURITY/i, weight: 1, category: 'documentation' },
            { pattern: /ethical|ETHICS/i, weight: 1, category: 'documentation' },
            { pattern: /bias|BIAS/i, weight: 1, category: 'documentation' },
            { pattern: /fairness|FAIRNESS/i, weight: 1, category: 'documentation' }
        ]
    },
    // MAP function - Mapping and inventory
    map: {
        indicators: [
            { pattern: /sbom|SBOM|bill.*of.*materials/i, weight: 2, category: 'inventory' },
            { pattern: /dependency|DEPENDENCY/i, weight: 1, category: 'inventory' },
            { pattern: /model.*provenance|data.*lineage/i, weight: 2, category: 'inventory' },
            { pattern: /training.*data|dataset/i, weight: 1, category: 'inventory' }
        ]
    },
    // MEASURE function - Measuring performance and effectiveness
    measure: {
        indicators: [
            { pattern: /evaluation|benchmark|metric/i, weight: 2, category: 'measurement' },
            { pattern: /performance.*test|validation/i, weight: 1, category: 'measurement' },
            { pattern: /bias.*assessment|fairness.*evaluation/i, weight: 2, category: 'measurement' },
            { pattern: /monitoring|drift.*detection/i, weight: 1, category: 'measurement' }
        ]
    },
    // MANAGE function - Managing AI risks
    manage: {
        indicators: [
            { pattern: /risk.*assessment|risk.*management/i, weight: 2, category: 'risk_management' },
            { pattern: /incident.*response|crisis.*management/i, weight: 1, category: 'risk_management' },
            { pattern: /transparency|explainability/i, weight: 2, category: 'risk_management' },
            { pattern: /accountability|oversight/i, weight: 1, category: 'risk_management' }
        ]
    }
};

// ============================================================================
// EXPORTS - For Node.js testing compatibility
// ============================================================================
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        GITHUB_API_BASE,
        HUGGINGFACE_API_BASE,
        AI_SIGNATURES,
        AI_PACKAGE_REGISTRY,
        SDK_PATTERNS,
        MODEL_PATTERNS,
        API_ENDPOINTS,
        AI_EXTENDED_DEPENDENCIES,
        AI_PROTOCOL_PATTERNS,
        AI_DEV_TOOLS,
        MANIFEST_FILES,
        PROMPT_INDICATORS,
        CI_PATTERNS,
        MODEL_FILE_PATTERNS,
        HARDWARE_PATTERNS,
        INFRASTRUCTURE_PATTERNS,
        DOCUMENTATION_FILES,
        DATA_PIPELINE_PATTERNS,
        RISK_KEYWORDS,
        // Helper functions for testing
        generatePackageRegistry,
        generateSDKPatterns,
        generateModelPatterns,
        generateAPIEndpoints,
        generateExtendedDependencies,
        generateProtocolPatterns,
        generateDevTools
    };
}

