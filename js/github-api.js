// GitHub API functions
function parseRepoInput(input) {
    input = input.trim();
    const urlPattern = /github\.com\/([^\/]+)\/([^\/]+)/;
    const urlMatch = input.match(urlPattern);
    
    if (urlMatch) {
        return { owner: urlMatch[1], repo: urlMatch[2].replace(/\.git$/, '') };
    }
    
    const parts = input.split('/');
    if (parts.length >= 2) {
        return { owner: parts[0], repo: parts[1] };
    }
    
    throw new Error('Invalid repository format. Use "owner/repo" or GitHub URL.');
}

async function fetchRepoMeta(owner, repo, token = null) {
    console.log(`[GitHub API] Fetching metadata for ${owner}/${repo}`);
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
        console.log('[GitHub API] Using provided token for authentication');
    } else {
        console.warn('[GitHub API] No token provided - rate limits will be lower');
    }
    
    const response = await fetch(`${GITHUB_API_BASE}/repos/${owner}/${repo}`, { headers });
    
    if (!response.ok) {
        if (response.status === 404) throw new Error('Repository not found.');
        if (response.status === 429 || response.status === 403) {
            const resetTime = response.headers.get('X-RateLimit-Reset');
            if (resetTime) {
                const resetDate = new Date(parseInt(resetTime) * 1000);
                const waitSeconds = Math.ceil((resetDate - new Date()) / 1000);
                if (waitSeconds > 0) {
                    throw new Error(`Rate limit exceeded. Waiting ${waitSeconds} seconds... Please provide a GitHub token to avoid rate limits.`);
                }
            }
            throw new Error('Rate limit exceeded. Please provide a GitHub token.');
        }
        throw new Error(`GitHub API error: ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`[GitHub API] Repository found: ${data.full_name}`);
    console.log(`[GitHub API] Default branch: ${data.default_branch}`);
    console.log(`[GitHub API] Stars: ${data.stargazers_count}, Forks: ${data.forks_count}`);
    
    const langResponse = await fetch(data.languages_url, { headers });
    const languages = langResponse.ok ? await langResponse.json() : {};
    
    const result = {
        name: data.name,
        fullName: data.full_name,
        description: data.description || '',
        htmlUrl: data.html_url,
        defaultBranch: data.default_branch,
        topics: data.topics || [],
        languages: Object.keys(languages),
        owner: data.owner.login
    };
    
    console.log(`[GitHub API] Languages detected: ${result.languages.join(', ') || 'None'}`);
    console.log(`[GitHub API] Topics: ${result.topics.join(', ') || 'None'}`);
    
    return result;
}

async function fetchRepoTree(owner, repo, ref, token = null) {
    console.log(`[GitHub API] Fetching file tree for ${owner}/${repo}@${ref}`);
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    
    const startTime = performance.now();
    const response = await fetch(
        `${GITHUB_API_BASE}/repos/${owner}/${repo}/git/trees/${ref}?recursive=1`,
        { headers }
    );
    
    if (!response.ok) {
        console.error('[GitHub API] Failed to fetch tree:', response.status, response.statusText);
        throw new Error('Failed to fetch repository tree');
    }
    
    const data = await response.json();
    const files = data.tree.filter(entry => entry.type === 'blob');
    const elapsed = (performance.now() - startTime).toFixed(2);
    
    console.log(`[GitHub API] Tree fetched in ${elapsed}ms`);
    console.log(`[GitHub API] Total entries: ${data.tree.length}, Files: ${files.length}`);
    
    const totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);
    console.log(`[GitHub API] Total file size: ${(totalSize / 1024 / 1024).toFixed(2)} MB`);
    
    return files.map(entry => ({
        path: entry.path,
        type: entry.type,
        size: entry.size,
        sha: entry.sha
    }));
}

async function searchCodeInRepo(owner, repo, query, token = null) {
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    
    try {
        const searchQuery = encodeURIComponent(`${query} repo:${owner}/${repo}`);
        // Request text_matches to get line numbers and code snippets
        const response = await fetch(
            `${GITHUB_API_BASE}/search/code?q=${searchQuery}&per_page=100`,
            { 
                headers: {
                    ...headers,
                    'Accept': 'application/vnd.github.v3.text-match+json' // Request text matches
                }
            }
        );
        
        // Check rate limit headers
        const remaining = parseInt(response.headers.get('X-RateLimit-Remaining') || '0');
        const limit = parseInt(response.headers.get('X-RateLimit-Limit') || '10');
        const resetTime = response.headers.get('X-RateLimit-Reset');
        
        console.log(`[GitHub Search API] Rate limit: ${remaining}/${limit} remaining`);
        
        if (!response.ok) {
            if (response.status === 403 || response.status === 429) {
                console.warn(`[GitHub Search API] ⚠️  Rate limited!`);
                
                // Don't wait here - return false to signal rate limit hit
                console.warn(`[GitHub Search API] Rate limit hit, deferring to allow other detectors to run`);
                return false; // Special return value to signal rate limit
            }
            console.warn(`[GitHub Search API] Request failed: ${response.status}`);
            return null;
        }
        
        const data = await response.json();
        
        // Enhance items with line numbers and snippets from text_matches
        // Note: GitHub Search API fragments don't include line numbers, so we extract snippets
        // and will fetch file content later if line numbers are needed
        const enhancedItems = (data.items || []).map((item) => {
            let snippet = null;
            const matchedText = item.text_matches && item.text_matches.length > 0 
                ? (item.text_matches[0].matches && item.text_matches[0].matches.length > 0 
                    ? item.text_matches[0].matches[0].text 
                    : null)
                : null;
            
            // Extract code snippet from fragment
            if (item.text_matches && item.text_matches.length > 0) {
                const match = item.text_matches[0];
                const fragment = match.fragment || '';
                
                if (fragment) {
                    const lines = fragment.split('\n');
                    
                    // Find the line containing the matched text
                    for (let i = 0; i < lines.length; i++) {
                        const line = lines[i].trim();
                        // Skip empty lines and line number markers
                        if (!line || line.match(/^\d+:$/)) continue;
                        
                        // If this line contains the matched text, use it
                        if (matchedText && line.includes(matchedText)) {
                            snippet = line;
                            break;
                        }
                    }
                    
                    // If no match found, use the first substantial line
                    if (!snippet) {
                        snippet = lines.find(l => {
                            const trimmed = l.trim();
                            return trimmed && !trimmed.match(/^\d+:$/) && trimmed.length > 5;
                        })?.trim();
                    }
                    
                    // Last resort: use fragment directly (truncated)
                    if (!snippet) {
                        snippet = fragment.replace(/\n/g, ' ').substring(0, 150).trim();
                    }
                }
            }
            
            // Use matched text as fallback snippet
            if (!snippet && matchedText) {
                snippet = matchedText;
            }
            
            return {
                ...item,
                line_number: null, // Will be fetched later if needed
                snippet: snippet
            };
        });
        
        // Return both results and rate limit info
        return {
            items: enhancedItems,
            rateLimit: {
                remaining,
                limit,
                resetTime: resetTime ? new Date(parseInt(resetTime) * 1000) : null
            }
        };
    } catch (error) {
        console.error('[GitHub Search API] Error:', error);
        return null;
    }
}

async function fetchGitHubSBOM(owner, repo, token) {
    console.log(`[GitHub SBOM API] Fetching SBOM for ${owner}/${repo}`);
    const headers = { 
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    
    try {
        const response = await fetch(
            `${GITHUB_API_BASE}/repos/${owner}/${repo}/dependency-graph/sbom`,
            { headers }
        );
        
        if (!response.ok) {
            if (response.status === 404) {
                console.log('[GitHub SBOM API] Dependency graph not available for this repository');
            } else if (response.status === 403) {
                console.log('[GitHub SBOM API] Insufficient permissions - dependency graph may be disabled');
            } else if (response.status === 401) {
                console.log('[GitHub SBOM API] Authentication required');
            } else {
                console.log(`[GitHub SBOM API] Error ${response.status}: ${response.statusText}`);
            }
            return null;
        }
        
        const data = await response.json();
        const packageCount = data.sbom?.packages?.length || 0;
        console.log(`[GitHub SBOM API] ✓ SBOM retrieved successfully: ${packageCount} packages found`);
        return data;
    } catch (error) {
        console.error('[GitHub SBOM API] Exception:', error.message);
        return null;
    }
}

async function fetchHuggingFaceModelInfo(modelId) {
    console.log(`[HuggingFace API] Fetching model info for: ${modelId}`);
    try {
        const response = await fetch(`${HUGGINGFACE_API_BASE}/models/${modelId}`);
        
        if (!response.ok) {
            if (response.status === 429) {
                console.warn(`[HuggingFace API] ⚠️  Rate limit hit for: ${modelId} (429 Too Many Requests)`);
                const resetHeader = response.headers.get('X-RateLimit-Reset');
                if (resetHeader) {
                    console.warn(`[HuggingFace API] Rate limit resets at: ${new Date(parseInt(resetHeader) * 1000).toLocaleTimeString()}`);
                }
            } else if (response.status === 401 || response.status === 403) {
                console.warn(`[HuggingFace API] ⚠️  Authentication required for: ${modelId} (${response.status}) - continuing without verification`);
            } else if (response.status === 404) {
                console.warn(`[HuggingFace API] ⚠️  Model not found: ${modelId} (404 Not Found) - may not be a HuggingFace model`);
            } else {
                console.warn(`[HuggingFace API] ⚠️  HTTP ${response.status} for: ${modelId}`);
            }
            // Return a minimal object indicating the model wasn't verified
            return { verified: false, id: modelId, status: response.status };
        }
        
        const data = await response.json();
        console.log(`[HuggingFace API] ✓ Found model: ${data.id}`);
        
        return {
            verified: true,
            id: data.id,
            author: data.author,
            downloads: data.downloads || 0,
            likes: data.likes || 0,
            tags: data.tags || [],
            pipeline_tag: data.pipeline_tag,
            library_name: data.library_name,
            license: data.cardData?.license,
            modelSize: data.safetensors?.total || null
        };
    } catch (error) {
        console.warn(`[HuggingFace API] ⚠️  Exception fetching ${modelId}:`, error.message);
        // Return unverified rather than null so the model can still be included
        return { verified: false, id: modelId };
    }
}

function createFileContentFetcher(owner, repo, ref, token = null) {
    const cache = new Map();
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    let rateLimitWaitUntil = 0;
    
    return async function getFileContent(path) {
        if (cache.has(path)) return cache.get(path);
        
        // Check if we need to wait for rate limit
        const now = Date.now();
        if (rateLimitWaitUntil > now) {
            const waitMs = rateLimitWaitUntil - now;
            await new Promise(resolve => setTimeout(resolve, waitMs));
        }
        
        try {
            const response = await fetch(
                `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}?ref=${ref}`,
                { headers }
            );
            
            // Handle rate limiting
            if (response.status === 429 || response.status === 403) {
                const resetTime = response.headers.get('X-RateLimit-Reset');
                const remaining = response.headers.get('X-RateLimit-Remaining');
                console.warn(`[Rate Limit] Hit rate limit on ${path}`);
                console.warn(`[Rate Limit] Remaining: ${remaining || 'unknown'}`);
                
                if (resetTime) {
                    rateLimitWaitUntil = parseInt(resetTime) * 1000;
                    const waitMs = rateLimitWaitUntil - Date.now();
                    if (waitMs > 0 && waitMs < 60000) { // Wait up to 60 seconds
                        console.log(`[Rate Limit] Waiting ${Math.ceil(waitMs/1000)} seconds before retry...`);
                        await new Promise(resolve => setTimeout(resolve, waitMs));
                        console.log(`[Rate Limit] Retrying ${path}...`);
                        // Retry
                        return getFileContent(path);
                    } else {
                        console.error(`[Rate Limit] Wait time too long (${Math.ceil(waitMs/1000)}s), skipping file`);
                    }
                }
                cache.set(path, null);
                return null;
            }
            
            if (!response.ok) {
                cache.set(path, null);
                return null;
            }
            
            const data = await response.json();
            if (data.content) {
                const content = atob(data.content.replace(/\n/g, ''));
                cache.set(path, content);
                return content;
            }
            
            cache.set(path, null);
            return null;
        } catch (error) {
            cache.set(path, null);
            return null;
        }
    };
}

// ============================================================================
// DETECTORS
// ============================================================================

