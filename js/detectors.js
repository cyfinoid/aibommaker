// AI/LLM Detection functions
async function metadataDetector({ repoMeta }) {
    console.log('[Detector: Metadata] Starting metadata analysis...');
    const findings = [];
    const keywords = ['llm', 'gpt', 'langchain', 'llamaindex', 'rag', 'chatbot', 'ai assistant', 
                     'openai', 'anthropic', 'claude', 'gemini', 'generative ai'];
    
    const description = (repoMeta.description || '').toLowerCase();
    const topics = (repoMeta.topics || []).map(t => t.toLowerCase());
    const foundKeywords = new Set();
    const evidence = [];
    
    console.log(`[Detector: Metadata] Checking ${keywords.length} keywords against description and ${topics.length} topics`);
    
    for (const keyword of keywords) {
        if (description.includes(keyword)) {
            foundKeywords.add(keyword);
            evidence.push({ file: 'Repository Description', snippet: `Contains "${keyword}"` });
        }
    }
    
    for (const topic of topics) {
        for (const keyword of keywords) {
            if (topic.includes(keyword)) {
                foundKeywords.add(keyword);
                evidence.push({ file: 'Repository Topics', snippet: `Topic: ${topic}` });
            }
        }
    }
    
    if (foundKeywords.size > 0) {
        console.log(`[Detector: Metadata] ✓ Found ${foundKeywords.size} AI keywords:`, Array.from(foundKeywords));
        findings.push({
            id: 'metadata-ai-keywords',
            title: 'AI/LLM Keywords in Metadata',
            category: 'metadata',
            severity: 'low',
            weight: Math.min(foundKeywords.size, 3),
            description: `Found ${foundKeywords.size} AI/LLM keywords: ${Array.from(foundKeywords).join(', ')}`,
            evidence: evidence.slice(0, 5)
        });
    } else {
        console.log('[Detector: Metadata] No AI keywords found in metadata');
    }
    
    console.log(`[Detector: Metadata] Complete. Findings: ${findings.length}`);
    return findings;
}

async function dependenciesDetector({ tree, getFileContent }) {
    console.log('[Detector: Dependencies] Starting dependency analysis...');
    const findings = [];
    const manifestFiles = tree.filter(entry => {
        const fileName = entry.path.split('/').pop();
        return Object.values(MANIFEST_FILES).flat().includes(fileName);
    });
    
    console.log(`[Detector: Dependencies] Found ${manifestFiles.length} manifest files to analyze:`, manifestFiles.map(f => f.path));
    
    for (const manifest of manifestFiles) {
        console.log(`[Detector: Dependencies] Analyzing ${manifest.path}...`);
        const content = await getFileContent(manifest.path);
        if (!content) {
            console.log(`[Detector: Dependencies] Could not read ${manifest.path}`);
            continue;
        }
        
        const ecosystem = detectEcosystem(manifest.path);
        if (!ecosystem) {
            console.log(`[Detector: Dependencies] Unknown ecosystem for ${manifest.path}`);
            continue;
        }
        
        console.log(`[Detector: Dependencies] Detected ecosystem: ${ecosystem}`);
        const llmDeps = LLM_DEPENDENCIES[ecosystem] || [];
        let foundDeps = [];
        
        if (manifest.path.endsWith('package.json')) {
            foundDeps = findInPackageJson(content, llmDeps);
        } else if (manifest.path.endsWith('requirements.txt')) {
            foundDeps = findInRequirements(content, llmDeps);
        } else if (manifest.path.match(/pyproject\.toml|Pipfile/)) {
            foundDeps = findInPyproject(content, llmDeps);
        }
        
        if (foundDeps.length > 0) {
            console.log(`[Detector: Dependencies] ✓ Found ${foundDeps.length} LLM dependencies in ${manifest.path}:`, foundDeps);
            
            // Create individual findings for each dependency (machine-readable)
            foundDeps.forEach(dep => {
                findings.push({
                    id: `dep-${ecosystem}-${dep.name.replace(/[^a-zA-Z0-9]/g, '-')}`,
                    title: `Dependency: ${dep.name}`,
                    category: 'dependencies',
                    severity: 'high',
                    weight: 5,
                    description: `LLM-related dependency: ${dep.name}${dep.version ? ` (version: ${dep.version})` : ''}`,
                    evidence: [{
                        file: manifest.path,
                        line: dep.line,
                        snippet: dep.snippet || dep.name
                    }],
                    dependencyInfo: {
                        name: dep.name,
                        version: dep.version || 'unknown',
                        ecosystem,
                        manifestFile: manifest.path
                    }
                });
            });
        } else {
            console.log(`[Detector: Dependencies] No LLM dependencies found in ${manifest.path}`);
        }
    }
    
    console.log(`[Detector: Dependencies] Complete. Findings: ${findings.length}`);
    return findings;
}

function detectEcosystem(path) {
    if (path.match(/package\.json|yarn\.lock|pnpm-lock/)) return 'node';
    if (path.match(/requirements\.txt|pyproject\.toml|Pipfile/)) return 'python';
    return null;
}

function findInPackageJson(content, llmDeps) {
    try {
        const pkg = JSON.parse(content);
        const lines = content.split('\n');
        const results = [];
        
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
        const matchingDeps = Object.keys(allDeps).filter(dep => {
            const depLower = dep.toLowerCase();
            return llmDeps.some(llmDep => {
                const llmDepLower = llmDep.toLowerCase();
                if (depLower === llmDepLower) return true;
                const pattern = new RegExp(`(^|[^a-z])${llmDepLower}([^a-z]|$)`, 'i');
                return pattern.test(dep);
            });
        });
        
        // Find line numbers for each dependency
        matchingDeps.forEach(dep => {
            const version = allDeps[dep];
            let lineNum = 0;
            
            for (let i = 0; i < lines.length; i++) {
                if (lines[i].includes(`"${dep}"`)) {
                    lineNum = i + 1;
                    break;
                }
            }
            
            results.push({
                name: dep,
                version,
                line: lineNum,
                snippet: `"${dep}": "${version}"`
            });
        });
        
        return results;
    } catch (e) {
        return [];
    }
}

function findInRequirements(content, llmDeps) {
    const lines = content.split('\n');
    const deps = [];
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        
        // Match: package-name==version or package-name>=version or just package-name
        const match = trimmed.match(/^([a-zA-Z0-9\-_.]+)([>=<~!]+(.+))?/);
        if (match) {
            const depName = match[1];
            const versionSpec = match[2] || '';
            const depLower = depName.toLowerCase();
            
            // Use exact match or word boundary match
            const isLLMDep = llmDeps.some(llmDep => {
                const llmDepLower = llmDep.toLowerCase();
                if (depLower === llmDepLower) return true;
                // Match at word boundaries (e.g., "langchain-openai" matches "langchain")
                const pattern = new RegExp(`(^|[^a-z])${llmDepLower}([^a-z]|$)`, 'i');
                return pattern.test(depName);
            });
            
            if (isLLMDep) {
                // Sanitize snippet to remove any potential sensitive information
                const sanitizedSnippet = trimmed
                    .replace(/(['"])[A-Za-z0-9+/=_-]{20,}(['"])/g, '$1[REDACTED]$2')
                    .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)(['"]).*?(['"])/gi, '$1$2$3[REDACTED]$4')
                    .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)([^\s'"#]+)/gi, '$1$2[REDACTED]');
                deps.push({
                    name: depName,
                    version: versionSpec ? versionSpec.replace(/^[>=<~!]+/, '') : 'unspecified',
                    line: i + 1,
                    snippet: sanitizedSnippet
                });
            }
        }
    }
    return deps;
}

function findInPyproject(content, llmDeps) {
    const lines = content.split('\n');
    const deps = [];
    const seen = new Set();
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const depPattern = /["']([a-zA-Z0-9\-_.]+)["']/g;
        let match;
        
        while ((match = depPattern.exec(line)) !== null) {
            const depName = match[1];
            const depLower = depName.toLowerCase();
            
            // Skip if already found
            if (seen.has(depLower)) continue;
            
            // Use exact match or word boundary match
            const isLLMDep = llmDeps.some(llmDep => {
                const llmDepLower = llmDep.toLowerCase();
                if (depLower === llmDepLower) return true;
                // Match at word boundaries
                const pattern = new RegExp(`(^|[^a-z])${llmDepLower}([^a-z]|$)`, 'i');
                return pattern.test(depName);
            });
            
            if (isLLMDep) {
                seen.add(depLower);
                // Sanitize snippet to remove any potential sensitive information
                const sanitizedSnippet = line.trim()
                    .replace(/(['"])[A-Za-z0-9+/=_-]{20,}(['"])/g, '$1[REDACTED]$2')
                    .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)(['"]).*?(['"])/gi, '$1$2$3[REDACTED]$4')
                    .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)([^\s'"#]+)/gi, '$1$2[REDACTED]');
                deps.push({
                    name: depName,
                    version: 'unspecified',
                    line: i + 1,
                    snippet: sanitizedSnippet
                });
            }
        }
    }
    return deps;
}

async function codeDetector({ tree, getFileContent, owner, repo, token, resumeState, repoMeta }) {
    console.log('[Detector: Code] Starting code analysis...');
    const findings = [];
    let aiFilesFound = []; // Track files where AI usage was found
    
    // Try GitHub Search API first (more efficient if token is provided)
    if (token) {
        console.log('[Detector: Code] Using GitHub Search API for efficient scanning...');
        const languages = repoMeta?.languages || [];
        const searchResult = await searchCodeViaAPI(owner, repo, token, resumeState, languages);
        
        if (searchResult) {
            findings.push(...searchResult.findings);
            console.log(`[Detector: Code] Search API found ${searchResult.findings.length} findings so far`);
            
            // Extract files where AI was found for later detailed scanning
            searchResult.findings.forEach(finding => {
                finding.evidence?.forEach(ev => {
                    if (ev.file && !aiFilesFound.includes(ev.file)) {
                        aiFilesFound.push(ev.file);
                    }
                });
            });
            
            console.log(`[Detector: Code] Identified ${aiFilesFound.length} files with AI usage for detailed scanning`);
            
            // If paused due to rate limit, return findings with resume state
            if (searchResult.paused) {
                return {
                    findings,
                    paused: true,
                    resumeState: searchResult.resumeState,
                    aiFilesFound // Pass this to other detectors
                };
            }
            
            // All searches complete
            console.log('[Detector: Code] ✓ All searches completed');
            return { findings, paused: false, aiFilesFound };
        }
        console.log('[Detector: Code] Search API not available, falling back to file scanning...');
    }
    
    // Fallback: Traditional file scanning
    const CODE_EXTENSIONS = ['.py', '.js', '.ts', '.jsx', '.tsx'];
    const codeFiles = tree.filter(entry => {
        const ext = entry.path.match(/\.[^.]+$/)?.[0] || '';
        return CODE_EXTENSIONS.includes(ext) && (!entry.size || entry.size < 500000);
    }).slice(0, 200);
    
    console.log(`[Detector: Code] Found ${codeFiles.length} code files to scan (limited to 200, <500KB each)`);
    
    const sdkFindings = new Map();
    const apiFindings = new Map();
    let filesScanned = 0;
    
    for (const file of codeFiles) {
        filesScanned++;
        if (filesScanned % 20 === 0) {
            console.log(`[Detector: Code] Progress: ${filesScanned}/${codeFiles.length} files scanned...`);
        }
        
        const content = await getFileContent(file.path);
        if (!content) continue;
        
        const ext = file.path.match(/\.[^.]+$/)?.[0] || '';
        const language = ext === '.py' ? 'python' : 'javascript';
        const patterns = SDK_PATTERNS[language] || [];
        
        for (const { pattern, provider, weight } of patterns) {
            if (pattern.test(content)) {
                const key = `${provider}-${language}`;
                if (!sdkFindings.has(key)) {
                    sdkFindings.set(key, { provider, weight, files: [] });
                }
                const lines = content.split('\n').filter(line => pattern.test(line));
                // Redact any sensitive information from code snippets
                const redactedSnippet = lines.slice(0, 2).join('\n')
                    .replace(/(['"])[A-Za-z0-9+/=_-]{20,}(['"])/g, '$1[REDACTED]$2')
                    .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)(['"]).*?(['"])/gi, '$1$2$3[REDACTED]$4')
                    .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)([^\s'"]+)/gi, '$1$2[REDACTED]');
                sdkFindings.get(key).files.push({ file: file.path, snippet: redactedSnippet });
            }
        }
        
        for (const { pattern, provider, weight } of API_ENDPOINTS) {
            if (pattern.test(content)) {
                const key = `api-${provider}`;
                if (!apiFindings.has(key)) {
                    apiFindings.set(key, { provider, weight, files: [] });
                }
                const lines = content.split('\n').filter(line => pattern.test(line));
                // Redact any sensitive information from code snippets
                const redactedSnippet = lines.slice(0, 2).join('\n')
                    .replace(/(['"])[A-Za-z0-9+/=_-]{20,}(['"])/g, '$1[REDACTED]$2')
                    .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)(['"]).*?(['"])/gi, '$1$2$3[REDACTED]$4')
                    .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)([^\s'"]+)/gi, '$1$2[REDACTED]');
                apiFindings.get(key).files.push({ file: file.path, snippet: redactedSnippet });
            }
        }
    }
    
    console.log(`[Detector: Code] Scanned ${filesScanned} files`);
    console.log(`[Detector: Code] Found ${sdkFindings.size} SDK patterns, ${apiFindings.size} API endpoint patterns`);
    
    for (const [key, data] of sdkFindings) {
        console.log(`[Detector: Code] ✓ ${data.provider} SDK detected in ${data.files.length} files`);
        findings.push({
            id: `code-sdk-${key}`,
            title: `${data.provider} SDK Usage Detected`,
            category: 'code',
            severity: 'high',
            weight: data.weight,
            description: `Found ${data.provider} SDK usage in ${data.files.length} file(s)`,
            evidence: data.files.slice(0, 5).map(f => ({ file: f.file, snippet: f.snippet.substring(0, 200) }))
        });
    }
    
    for (const [key, data] of apiFindings) {
        console.log(`[Detector: Code] ✓ ${data.provider} API endpoints detected in ${data.files.length} files`);
        findings.push({
            id: `code-api-${key}`,
            title: `${data.provider} API Endpoint Detected`,
            category: 'code',
            severity: 'medium',
            weight: data.weight,
            description: `Found API calls to ${data.provider} in ${data.files.length} file(s)`,
            evidence: data.files.slice(0, 5).map(f => ({ file: f.file, snippet: f.snippet.substring(0, 200) }))
        });
    }
    
    console.log(`[Detector: Code] Complete. Findings: ${findings.length}`);
    return { findings, paused: false, aiFilesFound };
}

async function searchCodeViaAPI(owner, repo, token, resumeState = null, languages = []) {
    const findings = resumeState?.findings || [];
    const sdkFindings = resumeState?.sdkFindings || new Map();
    
    // Build file extension filter based on detected languages
    let codeExtensions = '';
    
    if (languages.length > 0) {
        const extensionMap = {
            'JavaScript': ['js', 'jsx', 'mjs', 'cjs'],
            'TypeScript': ['ts', 'tsx'],
            'Python': ['py', 'pyw'],
            'Java': ['java'],
            'Go': ['go'],
            'Rust': ['rs'],
            'Ruby': ['rb'],
            'PHP': ['php'],
            'C': ['c', 'h'],
            'C++': ['cpp', 'cc', 'cxx', 'hpp', 'hxx'],
            'C#': ['cs'],
            'Kotlin': ['kt', 'kts'],
            'Scala': ['scala'],
            'Swift': ['swift']
        };
        
        const extensions = new Set();
        languages.forEach(lang => {
            const exts = extensionMap[lang];
            if (exts) {
                exts.forEach(ext => extensions.add(`extension:${ext}`));
            }
        });
        
        if (extensions.size > 0) {
            codeExtensions = Array.from(extensions).join(' ');
            console.log(`[Code Search] Using language-specific extensions: ${codeExtensions}`);
        }
    }
    
    // Default to common extensions if no languages detected
    if (!codeExtensions) {
        codeExtensions = 'extension:py extension:js extension:ts extension:jsx extension:tsx extension:java extension:go';
        console.log(`[Code Search] Using default extensions: ${codeExtensions}`);
    }
    
    // Search queries for different LLM SDKs (MAX 10 due to Code Search API rate limit)
    // Add file extension filter to focus on actual code files
    const searches = [
        { query: `from openai import ${codeExtensions}`, provider: 'OpenAI' },
        { query: `openai.chat.completions ${codeExtensions}`, provider: 'OpenAI' },
        { query: `from anthropic import ${codeExtensions}`, provider: 'Anthropic' },
        { query: `@anthropic-ai/sdk ${codeExtensions}`, provider: 'Anthropic' },
        { query: `from langchain ${codeExtensions}`, provider: 'LangChain' },
        { query: `ChatOpenAI ${codeExtensions}`, provider: 'OpenAI' },
        { query: `google.generativeai ${codeExtensions}`, provider: 'Google' },
        { query: `api.openai.com ${codeExtensions}`, provider: 'OpenAI' },
        { query: `api.anthropic.com ${codeExtensions}`, provider: 'Anthropic' },
        { query: `/v1/chat/completions ${codeExtensions}`, provider: 'OpenAI-compatible' }
    ];
    
    const startIdx = resumeState?.lastSearchIndex || 0;
    console.log(`[Code Search] Starting from search ${startIdx}/${searches.length} (API limit: 10 req/min)`);
    
    let lastRateLimit = resumeState?.lastRateLimit || { remaining: 10, limit: 10 };
    let hitRateLimit = false;
    let lastSearchIndex = startIdx;
    
    for (let i = startIdx; i < searches.length; i++) {
        const { query, provider } = searches[i];
        lastSearchIndex = i;
        
        console.log(`[Code Search] [${i + 1}/${searches.length}] Searching for: "${query}"`);
        
        const result = await searchCodeInRepo(owner, repo, query, token);
        
        if (!result) {
            // Check if it was a rate limit issue
            if (result === false) { // Rate limit hit
                console.warn(`[Code Search] ⚠️  Rate limit exhausted at search ${i + 1}`);
                console.log(`[Code Search] 🔄 Will resume after other detectors complete...`);
                hitRateLimit = true;
                
                // Return partial results and resume state
                return {
                    findings: convertSearchToFindings(sdkFindings),
                    paused: true,
                    resumeState: {
                        sdkFindings,
                        lastSearchIndex: i,
                        lastRateLimit,
                        findings
                    }
                };
            }
            console.log(`[Code Search] No results or error for: "${query}"`);
            continue;
        }
        
        // Update rate limit tracking
        if (result.rateLimit) {
            lastRateLimit = result.rateLimit;
            console.log(`[Code Search] Rate limit: ${lastRateLimit.remaining}/${lastRateLimit.limit} remaining`);
            
            // If we hit 0, pause and defer remaining searches
            if (lastRateLimit.remaining === 0) {
                console.warn(`[Code Search] ⚠️  Rate limit exhausted (0 remaining)`);
                console.log(`[Code Search] 🔄 Deferring remaining ${searches.length - i - 1} searches...`);
                hitRateLimit = true;
                
                // Return partial results
                return {
                    findings: convertSearchToFindings(sdkFindings),
                    paused: true,
                    resumeState: {
                        sdkFindings,
                        lastSearchIndex: i + 1,
                        lastRateLimit,
                        findings
                    }
                };
            }
            
            // Warn if running low
            if (lastRateLimit.remaining <= 2) {
                console.warn(`[Code Search] ⚠️  Running low (${lastRateLimit.remaining} remaining)`);
            }
        }
        
        const key = `${provider}-search`;
        if (!sdkFindings.has(key)) {
            sdkFindings.set(key, { provider, files: new Set() });
        }
        
        result.items.forEach(item => {
            sdkFindings.get(key).files.add(item.path);
        });
        
        console.log(`[Code Search] Found ${result.items.length} results for ${provider}`);
    }
    
    console.log(`[Code Search] ✓ Completed all ${searches.length} searches`);
    console.log(`[Code Search] Final rate limit: ${lastRateLimit.remaining}/${lastRateLimit.limit} remaining`);
    
    return {
        findings: convertSearchToFindings(sdkFindings),
        paused: false
    };
}

function convertSearchToFindings(sdkFindings) {
    const findings = [];
    for (const [key, data] of sdkFindings) {
        // Skip findings with zero files found
        if (data.files.size === 0) {
            console.log(`[Code Search] Skipping ${data.provider} SDK - no files found`);
            continue;
        }
        
        findings.push({
            id: `code-sdk-search-${key}`,
            title: `${data.provider} SDK Usage Detected (via Search API)`,
            category: 'code',
            severity: 'high',
            weight: 5,
            description: `Found ${data.provider} SDK usage in ${data.files.size} file(s) using GitHub Search API`,
            evidence: Array.from(data.files).slice(0, 5).map(file => ({
                file,
                snippet: 'Found via GitHub Code Search'
            })),
            filesFound: data.files.size // Track for filtering
        });
    }
    return findings;
}

async function configDetector({ tree, getFileContent }) {
    console.log('[Detector: Config] Starting configuration analysis...');
    const findings = [];
    
    // Expand config file detection
    const CONFIG_FILES = ['.env', '.env.example', '.env.sample', '.env.local', 
                          'config.yml', 'config.yaml', 'docker-compose.yml',
                          'settings.json', 'settings.yaml', 'app.config'];
    
    const configFiles = tree.filter(entry => {
        const fileName = entry.path.split('/').pop();
        const path = entry.path.toLowerCase();
        return CONFIG_FILES.includes(fileName) ||
               path.match(/config\/.*\.(yml|yaml|json|toml)$/) ||
               fileName === 'config.py' ||
               fileName === 'config.js' ||
               fileName === 'constants.py' ||
               fileName === 'constants.js';
    });
    
    console.log(`[Detector: Config] Found ${configFiles.length} config files to scan for model references`);
    
    // NOTE: We intentionally do NOT scan for API keys because:
    // 1. Good projects don't commit API keys (they use env vars at runtime)
    // 2. Code patterns and dependencies are better AI/LLM indicators
    // 3. We shouldn't log or expose secret references for security reasons
    
    const modelNameFindings = new Map();
    
    for (const file of configFiles) {
        console.log(`[Detector: Config] Scanning ${file.path}...`);
        const content = await getFileContent(file.path);
        if (!content) continue;
        
        const lines = content.split('\n');
        
        // Check for model names in config (NOT API keys)
        for (const { pattern, provider, model } of MODEL_PATTERNS) {
            for (let i = 0; i < lines.length; i++) {
                if (pattern.test(lines[i])) {
                    const key = `model-${provider}-${model}`;
                    if (!modelNameFindings.has(key)) {
                        modelNameFindings.set(key, { provider, model, files: [] });
                    }
                    
                    // Redact sensitive information from snippet (in case API keys are on same line)
                    const redactedSnippet = lines[i].trim()
                        .replace(/(['"])[A-Za-z0-9+/=_-]{20,}(['"])/g, '$1[REDACTED]$2')
                        .replace(/(key|token|secret|password)(\s*[=:]\s*)(['"]).*?(['"])/gi, '$1$2$3[REDACTED]$4')
                        .replace(/(key|token|secret|password)(\s*[=:]\s*)([^\s'"]+)/gi, '$1$2[REDACTED]')
                        .substring(0, 100);
                    
                    modelNameFindings.get(key).files.push({ 
                        file: file.path,
                        line: i + 1,
                        snippet: redactedSnippet
                    });
                    
                    console.log(`[Detector: Config] 🎯 Found ${provider} model "${model}" in config: ${file.path}:${i + 1}`);
                    break; // One per file is enough for config
                }
            }
        }
    }
    
    // Create findings for model names (API key findings removed - see note above)
    for (const [key, data] of modelNameFindings) {
        console.log(`[Detector: Config] ✓ Found ${data.provider} model "${data.model}" in ${data.files.length} config files`);
        findings.push({
            id: `config-${key}`,
            title: `${data.provider} Model in Configuration: ${data.model}`,
            category: 'config',
            severity: 'medium',
            weight: 4,
            description: `Found ${data.provider} model "${data.model}" configured in ${data.files.length} file(s)`,
            evidence: data.files.slice(0, 5), // Already has line, snippet
            modelInfo: {
                provider: data.provider,
                modelName: data.model,
                locations: data.files, // Already has file, line, snippet
                files: data.files.map(f => f.file) // For backward compatibility
            }
        });
    }
    
    console.log(`[Detector: Config] Complete. Findings: ${findings.length}`);
    return findings;
}

async function ciDetector({ tree, getFileContent }) {
    console.log('[Detector: CI/CD] Starting CI/CD analysis...');
    const findings = [];
    const ciFiles = tree.filter(entry => entry.path.includes('.github/workflows'));
    
    console.log(`[Detector: CI/CD] Found ${ciFiles.length} workflow files`);
    
    for (const file of ciFiles) {
        const content = await getFileContent(file.path);
        if (!content) continue;
        
        for (const { pattern, description } of CI_PATTERNS) {
            if (pattern.test(content)) {
                console.log(`[Detector: CI/CD] ✓ Found ${description} in ${file.path}`);
                findings.push({
                    id: `ci-action-${file.path.replace(/\//g, '-')}`,
                    title: `AI Tool in CI/CD: ${description}`,
                    category: 'ci',
                    severity: 'medium',
                    weight: 4,
                    description: `Found ${description} in CI/CD pipeline`,
                    evidence: [{ file: file.path, snippet: 'AI tool detected in workflow' }]
                });
            }
        }
    }
    
    console.log(`[Detector: CI/CD] Complete. Findings: ${findings.length}`);
    return findings;
}

async function modelsDetector({ tree }) {
    console.log('[Detector: Models] Starting model file detection...');
    const findings = [];
    const modelFiles = new Map();
    
    for (const entry of tree) {
        const fileName = entry.path.split('/').pop();
        const ext = fileName.match(/\.[^.]+$/)?.[0] || '';
        
        for (const pattern of MODEL_FILE_PATTERNS) {
            let isMatch = false;
            let description = pattern.description;
            
            if (pattern.extension && ext === pattern.extension) {
                isMatch = !pattern.pathMatch || pattern.pathMatch.test(entry.path);
            }
            if (pattern.filename && fileName === pattern.filename) {
                isMatch = !pattern.pathMatch || pattern.pathMatch.test(entry.path);
            }
            
            if (isMatch) {
                const key = pattern.extension || pattern.filename;
                if (!modelFiles.has(key)) {
                    modelFiles.set(key, { description, files: [] });
                }
                modelFiles.get(key).files.push({ file: entry.path, size: entry.size || 0 });
            }
        }
    }
    
    for (const [key, data] of modelFiles) {
        console.log(`[Detector: Models] ✓ Found ${data.files.length} ${data.description} files`);
        findings.push({
            id: `models-${key.replace(/[^a-zA-Z0-9]/g, '-')}`,
            title: `Local Model Files: ${data.description}`,
            category: 'models',
            severity: 'high',
            weight: Math.min(data.files.length + 4, 8),
            description: `Found ${data.files.length} ${data.description} file(s)`,
            evidence: data.files.slice(0, 10).map(f => ({ file: f.file, snippet: `File size: ${f.size} bytes` }))
        });
    }
    
    console.log(`[Detector: Models] Complete. Findings: ${findings.length}`);
    return findings;
}

/**
 * Validate if a string is a legitimate AI model name
 * Filters out MIME types, framework imports, utilities, and other false positives
 * @param {string} name - The potential model name to validate
 * @param {string} provider - The provider (e.g., 'HuggingFace', 'OpenAI')
 * @returns {boolean} True if valid model name, false otherwise
 */
function isValidModelName(name, provider) {
    if (!name || typeof name !== 'string') return false;
    
    // For non-HuggingFace providers, assume pattern matching is accurate enough
    if (provider !== 'HuggingFace') return true;
    
    const lowerName = name.toLowerCase();
    
    // Filter out MIME types
    const mimeTypePrefixes = ['application/', 'image/', 'text/', 'font/', 'audio/', 'video/', 'multipart/'];
    if (mimeTypePrefixes.some(prefix => lowerName.startsWith(prefix))) {
        return false;
    }
    
    // Filter out framework/library imports
    const frameworkPatterns = [
        /^next\//,           // Next.js
        /^react\//,          // React
        /^vue\//,            // Vue
        /^angular\//,        // Angular
        /^@angular\//,       // Angular scoped
        /^lodash\//,         // Lodash utilities
        /^jquery\//,         // jQuery
        /^bootstrap\//,      // Bootstrap
        /^tailwind\//,       // Tailwind
    ];
    
    if (frameworkPatterns.some(pattern => pattern.test(lowerName))) {
        return false;
    }
    
    // Filter out CSS classes and styling (e.g., text-white/80)
    if (/^(text|bg|border|shadow|rounded|flex|grid|gap|p|m|w|h)-/.test(lowerName)) {
        return false;
    }
    
    // Filter out invalid/placeholder names
    const invalidNames = ['n/a', 'none', 'null', 'undefined', 'todo', 'fixme', 'tbd'];
    if (invalidNames.includes(lowerName)) {
        return false;
    }
    
    // Filter out file paths (should have reasonable org and model names)
    const parts = name.split('/');
    if (parts.length !== 2) return false;
    
    const [org, model] = parts;
    
    // Organization name should be reasonable (3-50 chars, alphanumeric with some special chars)
    if (org.length < 2 || org.length > 50 || !/^[a-zA-Z0-9]/.test(org)) {
        return false;
    }
    
    // Model name should be reasonable (2-100 chars)
    if (model.length < 2 || model.length > 100) {
        return false;
    }
    
    // Should not contain URL-like patterns
    if (name.includes('://') || name.includes('www.') || name.includes('.com') || name.includes('.org')) {
        return false;
    }
    
    // Must not end with file extensions
    if (/\.(js|ts|jsx|tsx|py|java|go|css|html|json|xml|yml|yaml)$/i.test(name)) {
        return false;
    }
    
    return true;
}

/**
 * Detect which AI providers are actually used based on findings
 * @param {Array} findings - All findings from previous detectors
 * @returns {Set} Set of provider names (OpenAI, Anthropic, Google, HuggingFace, etc.)
 */
function detectProvidersInUse(findings) {
    const providers = new Set();
    
    for (const finding of findings) {
        const desc = finding.description?.toLowerCase() || '';
        const title = finding.title?.toLowerCase() || '';
        const text = desc + ' ' + title;
        
        // Check for explicit SDK/library usage
        if (text.includes('openai') && !text.includes('langchain')) {
            providers.add('OpenAI');
        }
        if (text.includes('anthropic')) {
            providers.add('Anthropic');
        }
        if (text.includes('google') || text.includes('gemini') || text.includes('generativeai')) {
            providers.add('Google');
        }
        if (text.includes('huggingface') || text.includes('transformers') || text.includes('diffusers')) {
            providers.add('HuggingFace');
        }
        if (text.includes('cohere')) {
            providers.add('Cohere');
        }
        if (text.includes('mistral')) {
            providers.add('Mistral');
        }
        
        // Check dependency names
        if (finding.dependencyInfo) {
            const depName = finding.dependencyInfo.name.toLowerCase();
            if (depName.includes('openai')) providers.add('OpenAI');
            if (depName.includes('anthropic')) providers.add('Anthropic');
            if (depName.includes('google') || depName.includes('generativeai')) providers.add('Google');
            if (depName.includes('transformers') || depName.includes('diffusers') || depName.includes('huggingface')) {
                providers.add('HuggingFace');
            }
            if (depName.includes('cohere')) providers.add('Cohere');
            if (depName.includes('mistral')) providers.add('Mistral');
        }
    }
    
    return providers;
}

/**
 * Get file extensions to scan based on repository languages
 * @param {Array} languages - Languages detected in the repository
 * @returns {Array} Array of file extensions to scan
 */
function getCodeExtensionsForLanguages(languages) {
    const extensionMap = {
        'JavaScript': ['.js', '.jsx', '.mjs', '.cjs'],
        'TypeScript': ['.ts', '.tsx'],
        'Python': ['.py', '.pyw'],
        'Java': ['.java'],
        'Go': ['.go'],
        'Rust': ['.rs'],
        'Ruby': ['.rb'],
        'PHP': ['.php'],
        'C': ['.c', '.h'],
        'C++': ['.cpp', '.cc', '.cxx', '.hpp', '.hxx'],
        'C#': ['.cs'],
        'Kotlin': ['.kt', '.kts'],
        'Scala': ['.scala'],
        'Swift': ['.swift'],
        'Objective-C': ['.m', '.mm', '.h'],
        'Shell': ['.sh', '.bash'],
        'R': ['.r', '.R']
    };
    
    const extensions = new Set();
    
    // Add extensions for detected languages
    languages.forEach(lang => {
        const exts = extensionMap[lang];
        if (exts) {
            exts.forEach(ext => extensions.add(ext));
        }
    });
    
    // If no languages detected or recognized, use common defaults
    if (extensions.size === 0) {
        console.log('[Detector: AI Models] No recognized languages, using default extensions');
        return ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go'];
    }
    
    const extArray = Array.from(extensions);
    console.log(`[Detector: AI Models] Scanning extensions based on detected languages: ${extArray.join(', ')}`);
    return extArray;
}

async function modelsIdentifierDetector({ tree, getFileContent, owner, repo, token, aiFilesFound, repoMeta, allFindings }) {
    console.log('[Detector: AI Models] Starting AI model identification...');
    const findings = [];
    const modelsFound = new Map();
    
    // Get file extensions to scan based on repository languages
    const languages = repoMeta?.languages || [];
    const codeExtensions = getCodeExtensionsForLanguages(languages);
    console.log(`[Detector: AI Models] Repository languages: ${languages.join(', ')}`);
    
    // Detect which AI providers are actually used based on code/dependencies findings
    const providersUsed = detectProvidersInUse(allFindings || []);
    console.log(`[Detector: AI Models] Detected providers in use: ${Array.from(providersUsed).join(', ') || 'None detected, will infer from patterns'}`);
    
    const shouldCheckHuggingFace = providersUsed.size === 0 || providersUsed.has('HuggingFace');
    console.log(`[Detector: AI Models] Will query HuggingFace API: ${shouldCheckHuggingFace}`);
    
    // Patterns to identify specific model usage
    const modelPatterns = [
        // OpenAI models - LLM
        { pattern: /["']?(gpt-4o-mini)["']?/gi, provider: 'OpenAI', model: 'gpt-4o-mini', type: 'text-generation' },
        { pattern: /["']?(gpt-4o)["']?/gi, provider: 'OpenAI', model: 'gpt-4o', type: 'text-generation' },
        { pattern: /["']?(gpt-4-turbo)["']?/gi, provider: 'OpenAI', model: 'gpt-4-turbo', type: 'text-generation' },
        { pattern: /["']?(gpt-4)["']?/gi, provider: 'OpenAI', model: 'gpt-4', type: 'text-generation' },
        { pattern: /["']?(gpt-3\.5-turbo)["']?/gi, provider: 'OpenAI', model: 'gpt-3.5-turbo', type: 'text-generation' },
        { pattern: /["']?(o1-preview)["']?/gi, provider: 'OpenAI', model: 'o1-preview', type: 'text-generation' },
        { pattern: /["']?(o1-mini)["']?/gi, provider: 'OpenAI', model: 'o1-mini', type: 'text-generation' },
        
        // OpenAI models - Embeddings
        { pattern: /["']?(text-embedding-3-large)["']?/gi, provider: 'OpenAI', model: 'text-embedding-3-large', type: 'embeddings' },
        { pattern: /["']?(text-embedding-3-small)["']?/gi, provider: 'OpenAI', model: 'text-embedding-3-small', type: 'embeddings' },
        { pattern: /["']?(text-embedding-ada-002)["']?/gi, provider: 'OpenAI', model: 'text-embedding-ada-002', type: 'embeddings' },
        
        // OpenAI models - Image Generation
        { pattern: /["']?(dall-e-3)["']?/gi, provider: 'OpenAI', model: 'dall-e-3', type: 'text-to-image' },
        { pattern: /["']?(dall-e-2)["']?/gi, provider: 'OpenAI', model: 'dall-e-2', type: 'text-to-image' },
        
        // Anthropic models - LLM
        { pattern: /["']?(claude-3-5-sonnet-\d+)["']?/gi, provider: 'Anthropic', model: 'claude-3.5-sonnet', type: 'text-generation' },
        { pattern: /["']?(claude-3-opus-\d+)["']?/gi, provider: 'Anthropic', model: 'claude-3-opus', type: 'text-generation' },
        { pattern: /["']?(claude-3-sonnet-\d+)["']?/gi, provider: 'Anthropic', model: 'claude-3-sonnet', type: 'text-generation' },
        { pattern: /["']?(claude-3-haiku-\d+)["']?/gi, provider: 'Anthropic', model: 'claude-3-haiku', type: 'text-generation' },
        
        // Google AI models - LLM (Gemini)
        { pattern: /["']?(gemini-1\.5-pro-\d+)["']?/gi, provider: 'Google', model: 'gemini-1.5-pro', type: 'text-generation' },
        { pattern: /["']?(gemini-1\.5-flash-\d+)["']?/gi, provider: 'Google', model: 'gemini-1.5-flash', type: 'text-generation' },
        { pattern: /["']?(gemini-1\.5-pro)["']?/gi, provider: 'Google', model: 'gemini-1.5-pro', type: 'text-generation' },
        { pattern: /["']?(gemini-1\.5-flash)["']?/gi, provider: 'Google', model: 'gemini-1.5-flash', type: 'text-generation' },
        { pattern: /["']?(gemini-pro)["']?/gi, provider: 'Google', model: 'gemini-pro', type: 'text-generation' },
        { pattern: /["']?(gemini-2\.0-flash-exp)["']?/gi, provider: 'Google', model: 'gemini-2.0-flash-exp', type: 'text-generation' },
        
        // Google AI models - Embeddings (models/embedding-001 format)
        { pattern: /["']?(models\/embedding-001)["']?/gi, provider: 'Google', model: 'models/embedding-001', type: 'embeddings' },
        { pattern: /["']?(models\/text-embedding-004)["']?/gi, provider: 'Google', model: 'models/text-embedding-004', type: 'embeddings' },
        { pattern: /["']?(text-embedding-004)["']?/gi, provider: 'Google', model: 'text-embedding-004', type: 'embeddings' },
        
        // HuggingFace models (pattern: organization/model-name)
        // Only match if it's actually from HuggingFace context
        // Exclude known Google models that use org/model format
        { pattern: /["']([a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+)["']/gi, provider: 'HuggingFace', model: 'extract', type: 'unknown' },
        
        // Mistral models
        { pattern: /["']?(mistral-large)["']?/gi, provider: 'Mistral', model: 'mistral-large', type: 'text-generation' },
        { pattern: /["']?(mixtral-8x7b)["']?/gi, provider: 'Mistral', model: 'mixtral-8x7b', type: 'text-generation' },
        
        // Cohere models
        { pattern: /["']?(command-r-plus)["']?/gi, provider: 'Cohere', model: 'command-r-plus', type: 'text-generation' },
        { pattern: /["']?(command-r)["']?/gi, provider: 'Cohere', model: 'command-r', type: 'text-generation' }
    ];
    
    // Define exclusion list for non-code files
    const EXCLUDE_EXTENSIONS = ['.md', '.txt', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.doc', '.docx'];
    
    const isCodeFile = (path) => {
        const ext = path.match(/\.[^.]+$/)?.[0]?.toLowerCase() || '';
        return codeExtensions.includes(ext) && !EXCLUDE_EXTENSIONS.includes(ext);
    };
    
    // Priority 1: Files where AI usage was already detected (from code search)
    const priorityFiles = [];
    if (aiFilesFound && aiFilesFound.length > 0) {
        console.log(`[Detector: AI Models] Priority scanning ${aiFilesFound.length} files with confirmed AI usage`);
        aiFilesFound.forEach(path => {
            // Only include actual code files, not documentation
            if (isCodeFile(path)) {
                priorityFiles.push(path);
            } else {
                console.log(`[Detector: AI Models] Skipping non-code file: ${path}`);
            }
        });
    }
    
    // Priority 2: Config files that might contain model names (but not documentation)
    const configFiles = tree.filter(entry => {
        const path = entry.path.toLowerCase();
        const fileName = entry.path.split('/').pop().toLowerCase();
        
        // Exclude documentation directories
        if (path.includes('/docs/') || path.includes('/documentation/') || 
            path.includes('/examples/') || path.includes('/tutorials/')) {
            return false;
        }
        
        return fileName.match(/^(config|settings|\.env|constants)/) ||
               path.includes('/config/') ||
               fileName.match(/\.(yaml|yml|json|toml|env)$/) && 
               (path.includes('model') || path.includes('llm') || path.includes('ai'));
    });
    
    console.log(`[Detector: AI Models] Found ${configFiles.length} config files to scan for model references`);
    configFiles.forEach(cf => priorityFiles.push(cf.path));
    
    // Priority 3: Regular code files (already filtered by isCodeFile above)
    const codeFiles = tree.filter(entry => {
        return isCodeFile(entry.path) &&
               (!entry.size || entry.size < 500000) &&
               !priorityFiles.includes(entry.path); // Don't duplicate
    }).slice(0, 50); // Reduced since we're prioritizing AI files
    
    const allFilesToScan = [
        ...priorityFiles.map(path => ({ path, priority: true })),
        ...codeFiles.map(entry => ({ path: entry.path, priority: false }))
    ];
    
    console.log(`[Detector: AI Models] Total files to scan: ${allFilesToScan.length} (${priorityFiles.length} priority)`);
    
    let filesScanned = 0;
    for (const { path, priority } of allFilesToScan) {
        filesScanned++;
        
        if (filesScanned % 10 === 0 || priority) {
            console.log(`[Detector: AI Models] Scanning ${priority ? '[PRIORITY] ' : ''}${path} (${filesScanned}/${allFilesToScan.length})`);
        }
        
        const content = await getFileContent(path);
        if (!content) {
            if (priority) {
                console.log(`[Detector: AI Models] ⚠️  Could not fetch priority file: ${path}`);
            }
            continue;
        }
        
        // Split content into lines for line number tracking
        const lines = content.split('\n');
        
        // Scan for model patterns
        for (const { pattern, provider, model, type } of modelPatterns) {
            const regex = new RegExp(pattern.source, pattern.flags);
            let match;
            
            while ((match = regex.exec(content)) !== null) {
                let modelName = model === 'extract' ? match[1] : model;
                
                // Special case: Exclude Google's models/* format from HuggingFace detector
                if (provider === 'HuggingFace' && modelName.startsWith('models/')) {
                    continue; // This is a Google model, not HuggingFace
                }
                
                // Validate model name to filter out false positives
                if (!isValidModelName(modelName, provider)) {
                    continue; // Skip invalid model names
                }
                
                // Calculate line number by counting newlines before match
                const lineNum = content.substring(0, match.index).split('\n').length;
                const lineContent = lines[lineNum - 1] || '';
                
                // Normalize Google model names: prefer "models/embedding-001" format
                let normalizedModelName = modelName;
                if (provider === 'Google' && !modelName.startsWith('models/') && 
                    (modelName.includes('embedding') || modelName.includes('text-embedding'))) {
                    normalizedModelName = `models/${modelName}`;
                }
                
                const key = `${provider}-${normalizedModelName}`;
                
                if (!modelsFound.has(key)) {
                    modelsFound.set(key, {
                        provider,
                        modelName: normalizedModelName, // Use normalized name
                        modelType: type, // text-generation, embeddings, text-to-image, etc.
                        locations: [], // Change from files to locations (includes line numbers)
                        isHuggingFace: provider === 'HuggingFace'
                    });
                    
                    if (priority) {
                        const typeInfo = type !== 'unknown' ? ` [${type}]` : '';
                        console.log(`[Detector: AI Models] 🎯 Found ${provider} model "${normalizedModelName}"${typeInfo} in priority file: ${path}:${lineNum}`);
                    }
                }
                
                // Store location with line number (avoid duplicates)
                const existingLoc = modelsFound.get(key).locations.find(loc => loc.file === path && loc.line === lineNum);
                if (!existingLoc) {
                    // Redact sensitive information from snippet
                    const redactedSnippet = lineContent.trim()
                        .replace(/(['"])[A-Za-z0-9+/=_-]{20,}(['"])/g, '$1[REDACTED]$2')
                        .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)(['"]).*?(['"])/gi, '$1$2$3[REDACTED]$4')
                        .replace(/(key|token|secret|password|api[_-]?key)(\s*[=:]\s*)([^\s'"]+)/gi, '$1$2[REDACTED]')
                        .substring(0, 100); // Limit snippet length
                    modelsFound.get(key).locations.push({
                        file: path,
                        line: lineNum,
                        snippet: redactedSnippet
                    });
                }
            }
        }
    }
    
    console.log(`[Detector: AI Models] Found ${modelsFound.size} distinct AI models`);
    
    // Track duplicate/related models
    const modelRelationships = new Map(); // modelName (normalized) -> [keys]
    
    for (const [key, data] of modelsFound) {
        // Normalize model name for duplicate detection (lowercase, remove provider prefix)
        let normalized = data.modelName.toLowerCase();
        // Remove provider prefix if present (e.g., "openai/" -> "")
        normalized = normalized.replace(/^[^\/]+\//, '');
        
        if (!modelRelationships.has(normalized)) {
            modelRelationships.set(normalized, []);
        }
        modelRelationships.get(normalized).push({
            key,
            provider: data.provider,
            fullName: data.modelName
        });
    }
    
    // Mark related models
    for (const [key, data] of modelsFound) {
        let normalized = data.modelName.toLowerCase().replace(/^[^\/]+\//, '');
        const related = modelRelationships.get(normalized);
        
        if (related && related.length > 1) {
            // This model has duplicates from other sources
            data.relatedModels = related
                .filter(r => r.key !== key) // Exclude self
                .map(r => ({
                    provider: r.provider,
                    modelName: r.fullName
                }));
            
            // Add detection source for clarity
            data.detectionSource = data.provider === 'HuggingFace' 
                ? 'HuggingFace Pattern Match' 
                : data.isHuggingFace 
                    ? 'HuggingFace API'
                    : `${data.provider} Official`;
        }
    }
    
    // Fetch HuggingFace model details only for actual HF models
    for (const [key, data] of modelsFound) {
        if (data.isHuggingFace && shouldCheckHuggingFace) {
            console.log(`[Detector: AI Models] Fetching details for HuggingFace model: ${data.modelName}`);
            const hfInfo = await fetchHuggingFaceModelInfo(data.modelName);
            if (hfInfo) {
                data.hfDetails = hfInfo;
                // Update modelType from HuggingFace if available
                if (hfInfo.verified && hfInfo.pipeline_tag) {
                    data.modelType = hfInfo.pipeline_tag;
                }
            }
        } else if (data.isHuggingFace && !shouldCheckHuggingFace) {
            console.log(`[Detector: AI Models] Skipping HuggingFace API check for ${data.modelName} (no HuggingFace libraries detected)`);
        }
        
        // Build description based on provider and model type
        let description;
        const typeLabel = data.modelType && data.modelType !== 'unknown' 
            ? ` (${data.modelType})` 
            : '';
        
        if (data.isHuggingFace && data.hfDetails) {
            if (data.hfDetails.verified) {
                description = `HuggingFace model: ${data.modelName}${typeLabel} - ${data.hfDetails.downloads?.toLocaleString()} downloads, License: ${data.hfDetails.license || 'Unknown'}`;
            } else {
                description = `HuggingFace model: ${data.modelName}${typeLabel} (unverified - API unavailable)`;
            }
        } else if (data.provider === 'Google') {
            description = `Google AI model: ${data.modelName}${typeLabel}`;
        } else if (data.provider === 'OpenAI') {
            description = `OpenAI model: ${data.modelName}${typeLabel}`;
        } else if (data.provider === 'Anthropic') {
            description = `Anthropic model: ${data.modelName}${typeLabel}`;
        } else {
            description = `${data.provider} model: ${data.modelName}${typeLabel}`;
        }
        
        // Create evidence with line numbers
        const evidence = data.locations.slice(0, 5).map(loc => ({
            file: loc.file,
            line: loc.line,
            snippet: loc.snippet
        }));
        
        // Only add HuggingFace model card info if verified
        if (data.hfDetails && data.hfDetails.verified) {
            evidence.push({
                file: 'HuggingFace Model Card',
                snippet: JSON.stringify({
                    model: data.hfDetails.id,
                    downloads: data.hfDetails.downloads,
                    likes: data.hfDetails.likes,
                    license: data.hfDetails.license,
                    tags: data.hfDetails.tags?.slice(0, 5).join(', '),
                    pipeline: data.hfDetails.pipeline_tag
                }, null, 2)
            });
        }
        
        findings.push({
            id: `model-${key}`,
            title: `AI Model Identified: ${data.modelName}`,
            category: 'models',
            severity: 'high',
            weight: 5,
            description,
            evidence,
            modelInfo: {
                provider: data.provider,
                modelName: data.modelName,
                modelType: data.modelType, // text-generation, embeddings, text-to-image, etc.
                locations: data.locations, // Use locations with line numbers
                files: data.locations.map(loc => loc.file), // Also keep files array for backward compatibility
                ...(data.hfDetails && { huggingface: data.hfDetails }),
                ...(data.detectionSource && { detectionSource: data.detectionSource }),
                ...(data.relatedModels && { relatedModels: data.relatedModels })
            }
        });
        
        const typeInfo = data.modelType && data.modelType !== 'unknown' ? ` [${data.modelType}]` : '';
        console.log(`[Detector: AI Models] ✓ ${data.provider} model "${data.modelName}"${typeInfo} found in ${data.locations.length} location(s)`);
    }
    
    console.log(`[Detector: AI Models] Complete. Findings: ${findings.length}`);
    return findings;
}

async function promptsDetector({ tree, getFileContent }) {
    console.log('[Detector: Prompts] Starting prompt template detection...');
    const findings = [];
    const PROMPT_PATHS = ['prompts', 'templates', 'llm', 'ai'];
    const promptFiles = tree.filter(entry => 
        PROMPT_PATHS.some(p => entry.path.toLowerCase().includes(p)) && 
        entry.path.match(/\.(txt|md|json|yaml)$/)
    );
    
    console.log(`[Detector: Prompts] Found ${promptFiles.length} potential prompt files`);
    
    const foundPrompts = [];
    for (const file of promptFiles.slice(0, 20)) {
        const content = await getFileContent(file.path);
        if (!content) continue;
        
        const foundIndicators = PROMPT_INDICATORS.filter(ind => 
            content.toLowerCase().includes(ind.toLowerCase())
        );
        
        if (foundIndicators.length > 0) {
            foundPrompts.push({ file: file.path, indicators: foundIndicators });
        }
    }
    
    const promptDirs = new Set();
    for (const entry of tree) {
        for (const promptPath of PROMPT_PATHS) {
            if (entry.path.toLowerCase().includes(promptPath)) {
                const dirMatch = entry.path.match(new RegExp(`.*${promptPath}[^/]*`, 'i'));
                if (dirMatch) promptDirs.add(dirMatch[0]);
            }
        }
    }
    
    if (promptDirs.size > 0) {
        console.log(`[Detector: Prompts] ✓ Found ${promptDirs.size} prompt/AI directories`);
        findings.push({
            id: 'prompts-directories',
            title: 'Prompt/AI Directories Detected',
            category: 'prompts',
            severity: 'medium',
            weight: Math.min(promptDirs.size + 1, 4),
            description: `Found ${promptDirs.size} directory/directories with prompt templates`,
            evidence: Array.from(promptDirs).slice(0, 5).map(dir => ({ 
                file: dir, snippet: 'Directory contains AI/prompt-related files' 
            }))
        });
    }
    
    if (foundPrompts.length > 0) {
        console.log(`[Detector: Prompts] ✓ Found ${foundPrompts.length} files with prompt indicators`);
        findings.push({
            id: 'prompts-templates',
            title: 'Prompt Templates Found',
            category: 'prompts',
            severity: 'medium',
            weight: Math.min(foundPrompts.length + 1, 5),
            description: `Found ${foundPrompts.length} file(s) with prompt templates`,
            evidence: foundPrompts.slice(0, 5).map(p => ({ 
                file: p.file, snippet: `Indicators: ${p.indicators.join(', ')}` 
            }))
        });
    }
    
    console.log(`[Detector: Prompts] Complete. Findings: ${findings.length}`);
    return findings;
}

// ============================================================================
// SCORING
// ============================================================================
