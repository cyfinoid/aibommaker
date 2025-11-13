// Utility helper functions

/**
 * Generate a cryptographically secure UUID v4
 * Uses Web Crypto API instead of Math.random() for security
 */
function generateUUID() {
    // Use crypto.randomUUID() if available (modern browsers)
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    
    // Fallback: Use crypto.getRandomValues() for older browsers
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/**
 * Generate a cryptographically secure SPDX ID
 * Uses Web Crypto API instead of Math.random()
 */
function generateSPDXId() {
    const array = new Uint8Array(12);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(36)).join('').substring(0, 15);
}

function escapeXml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Parse HuggingFace ModelCard YAML frontmatter from README.md
 * Extracts structured metadata from YAML frontmatter (between --- markers)
 * @param {string} content - README.md content with optional YAML frontmatter
 * @returns {Object} Parsed YAML data as object
 */
function parseModelCardYAML(content) {
    if (!content || typeof content !== 'string') {
        return {};
    }
    
    // Check for YAML frontmatter (between --- markers)
    const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n/);
    if (!frontmatterMatch) {
        return {};
    }
    
    const yamlContent = frontmatterMatch[1];
    const parsed = {};
    
    // Simple YAML parser for common ModelCard fields
    // Handle key-value pairs, arrays, and nested objects
    const lines = yamlContent.split('\n');
    let currentKey = null;
    let currentValue = [];
    let inArray = false;
    let inObject = false;
    let objectDepth = 0;
    
    for (const line of lines) {
        const trimmed = line.trim();
        
        // Skip empty lines and comments
        if (!trimmed || trimmed.startsWith('#')) {
            continue;
        }
        
        // Check for array item continuation
        if (inArray && trimmed.startsWith('-')) {
            const item = trimmed.substring(1).trim().replace(/^["']|["']$/g, '');
            if (currentKey) {
                if (!Array.isArray(parsed[currentKey])) {
                    parsed[currentKey] = [];
                }
                parsed[currentKey].push(item);
            }
            continue;
        }
        
        // Check for object start/end
        if (trimmed.includes(':')) {
            const colonIndex = trimmed.indexOf(':');
            const key = trimmed.substring(0, colonIndex).trim();
            let value = trimmed.substring(colonIndex + 1).trim();
            
            // Close previous array/object
            if (currentKey && inArray) {
                inArray = false;
            }
            if (currentKey && inObject && objectDepth === 0) {
                inObject = false;
            }
            
            // Handle value
            if (value.startsWith('[')) {
                // Array value
                inArray = true;
                currentKey = key;
                const arrayContent = value.match(/\[(.*?)\]/)?.[1] || '';
                if (arrayContent.trim()) {
                    parsed[key] = arrayContent.split(',').map(v => v.trim().replace(/^["']|["']$/g, ''));
                } else {
                    parsed[key] = [];
                }
            } else if (value.startsWith('{')) {
                // Object value (simple case)
                inObject = true;
                objectDepth = 1;
                currentKey = key;
                parsed[key] = {};
            } else if (value === '' || value === '|' || value === '>') {
                // Multi-line value
                currentKey = key;
                currentValue = [];
                parsed[key] = '';
            } else {
                // Simple value
                value = value.replace(/^["']|["']$/g, '');
                parsed[key] = value === 'null' ? null : value;
                currentKey = null;
            }
        } else if (currentKey && (inArray || currentValue.length > 0)) {
            // Continuation of multi-line value
            const cleanLine = trimmed.replace(/^[-|>]\s*/, '').trim();
            if (inArray) {
                if (!Array.isArray(parsed[currentKey])) {
                    parsed[currentKey] = [];
                }
                parsed[currentKey].push(cleanLine.replace(/^["']|["']$/g, ''));
            } else {
                currentValue.push(cleanLine);
                parsed[currentKey] = currentValue.join('\n');
            }
        }
    }
    
    return parsed;
}

/**
 * Extract eval_results from ModelCard and convert to performanceMetrics format
 * @param {Array|Object} evalResults - Evaluation results from ModelCard
 * @returns {Array} Array of performance metrics in CycloneDX format
 */
function parseEvalResults(evalResults) {
    if (!evalResults) {
        return [];
    }
    
    const metrics = [];
    
    // Handle array of eval results
    if (Array.isArray(evalResults)) {
        for (const result of evalResults) {
            if (typeof result === 'object' && result !== null) {
                // Handle EvalResult objects with metric_type and metric_value
                if (result.metric_type && result.metric_value !== undefined) {
                    metrics.push({
                        type: result.metric_type,
                        value: String(result.metric_value)
                    });
                } else {
                    // Handle key-value pairs
                    for (const [key, value] of Object.entries(result)) {
                        if (value !== null && value !== undefined) {
                            metrics.push({
                                type: key,
                                value: String(value)
                            });
                        }
                    }
                }
            }
        }
    } else if (typeof evalResults === 'object') {
        // Handle object with metric keys
        for (const [key, value] of Object.entries(evalResults)) {
            if (value !== null && value !== undefined) {
                metrics.push({
                    type: key,
                    value: String(value)
                });
            }
        }
    }
    
    return metrics;
}
