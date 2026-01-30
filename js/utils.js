// Utility helper functions

/**
 * Generate a cryptographically secure UUID v4
 * Uses Web Crypto API instead of Math.random() for security
 */
function generateUUID() {
  // Use crypto.randomUUID() if available (modern browsers)
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }

  // Fallback: Use crypto.getRandomValues() for older browsers
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
    const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
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
  return Array.from(array, (byte) => byte.toString(36))
    .join("")
    .substring(0, 15);
}

function escapeXml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Parse HuggingFace ModelCard YAML frontmatter from README.md
 * Extracts structured metadata from YAML frontmatter (between --- markers)
 * @param {string} content - README.md content with optional YAML frontmatter
 * @returns {Object} Parsed YAML data as object
 */
function parseModelCardYAML(content) {
  if (!content || typeof content !== "string") {
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
  const lines = yamlContent.split("\n");
  let currentKey = null;
  let currentValue = [];
  let inArray = false;
  let inObject = false;
  let objectDepth = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    // Check for array item continuation
    if (inArray && trimmed.startsWith("-")) {
      const item = trimmed
        .substring(1)
        .trim()
        .replace(/^["']|["']$/g, "");
      if (currentKey) {
        if (!Array.isArray(parsed[currentKey])) {
          parsed[currentKey] = [];
        }
        parsed[currentKey].push(item);
      }
      continue;
    }

    // Check for object start/end
    if (trimmed.includes(":")) {
      const colonIndex = trimmed.indexOf(":");
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
      if (value.startsWith("[")) {
        // Array value
        inArray = true;
        currentKey = key;
        const arrayContent = value.match(/\[(.*?)\]/)?.[1] || "";
        if (arrayContent.trim()) {
          parsed[key] = arrayContent
            .split(",")
            .map((v) => v.trim().replace(/^["']|["']$/g, ""));
        } else {
          parsed[key] = [];
        }
      } else if (value.startsWith("{")) {
        // Object value (simple case)
        inObject = true;
        objectDepth = 1;
        currentKey = key;
        parsed[key] = {};
      } else if (value === "" || value === "|" || value === ">") {
        // Multi-line value
        currentKey = key;
        currentValue = [];
        parsed[key] = "";
      } else {
        // Simple value
        value = value.replace(/^["']|["']$/g, "");
        parsed[key] = value === "null" ? null : value;
        currentKey = null;
      }
    } else if (currentKey && (inArray || currentValue.length > 0)) {
      // Continuation of multi-line value
      const cleanLine = trimmed.replace(/^[-|>]\s*/, "").trim();
      if (inArray) {
        if (!Array.isArray(parsed[currentKey])) {
          parsed[currentKey] = [];
        }
        parsed[currentKey].push(cleanLine.replace(/^["']|["']$/g, ""));
      } else {
        currentValue.push(cleanLine);
        parsed[currentKey] = currentValue.join("\n");
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
      if (typeof result === "object" && result !== null) {
        // Handle EvalResult objects with metric_type and metric_value
        if (result.metric_type && result.metric_value !== undefined) {
          metrics.push({
            type: result.metric_type,
            value: String(result.metric_value),
          });
        } else {
          // Handle key-value pairs
          for (const [key, value] of Object.entries(result)) {
            if (value !== null && value !== undefined) {
              metrics.push({
                type: key,
                value: String(value),
              });
            }
          }
        }
      }
    }
  } else if (typeof evalResults === "object") {
    // Handle object with metric keys
    for (const [key, value] of Object.entries(evalResults)) {
      if (value !== null && value !== undefined) {
        metrics.push({
          type: key,
          value: String(value),
        });
      }
    }
  }

  return metrics;
}

// ============================================================================
// ENHANCED FALSE POSITIVE DETECTION (inspired by ai-spotter)
// ============================================================================

/**
 * Check if a line is a comment or string literal
 * @param {string} line - The line to check
 * @returns {boolean} True if line is a comment or string literal
 */
function isCommentOrStringLiteral(line) {
  const trimmed = line.trim();

  // Skip comments
  if (
    trimmed.startsWith("#") ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("/*") ||
    trimmed.startsWith("*")
  ) {
    return true;
  }

  // Skip shebangs
  if (trimmed.startsWith("#!/")) {
    return true;
  }

  // Skip lines that are mostly JSON/string content (quoted strings)
  if (
    (trimmed.startsWith('"') || trimmed.startsWith("'")) &&
    trimmed.length > 50
  ) {
    // Check if it ends with matching quote
    const quote = trimmed[0];
    if (trimmed.endsWith(quote)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a pattern match is likely a false positive
 * @param {string} line - The line containing pattern match
 * @param {string} patternMatch - The matched text
 * @returns {boolean} True if this is likely a false positive
 */
function isFalsePositivePattern(line, patternMatch) {
  const lineLower = line.toLowerCase();
  const matchLower = patternMatch.toLowerCase();

  // Skip common false positive patterns
  const falsePositiveIndicators = [
    "api/",
    "admin/",
    "http://",
    "https://", // API endpoints
    "application/",
    "content-type", // HTTP headers
    "true/false",
    "n/a",
    "none",
    "null",
    "undefined", // Common values
    "#!/usr/bin", // Shebangs
    "merchant/payment",
    "payment/", // Business domain terms
    "timezone(",
    "pytz.", // Timezone libraries
    'f"https://',
    "f'https://", // F-strings with URLs
    "example.com",
    "test.com",
    "localhost", // Test endpoints
  ];

  for (const indicator of falsePositiveIndicators) {
    if (lineLower.includes(indicator)) {
      return true;
    }
  }

  // Skip if pattern is in a URL path
  if (lineLower.includes("/api/") || lineLower.includes("/admin/")) {
    return true;
  }

  // Skip if it's just a variable assignment with pattern
  if (line.includes("=") && lineLower.includes(matchLower)) {
    const keywords = ["model", "client", "api_key", "token", "llm", "ai"];
    if (!keywords.some((keyword) => lineLower.includes(keyword))) {
      return true;
    }
  }

  // LangChain-specific false positives
  if (matchLower.includes("agent")) {
    const langChainFalsePositives = [
      "possalesagent",
      "salesagent",
      "ekycagent",
      "parseuseragent",
      "useragent",
      "switchtopossalesagent",
      "checkifpossalesagent",
      "ispossalesagent",
      "ispospartnerowneraccount",
      "user-agent",
      "useragentparser",
    ];
    if (langChainFalsePositives.some((fp) => lineLower.includes(fp))) {
      return true;
    }
  }

  // Ollama-specific false positives
  if (
    matchLower.includes("ollama") ||
    ["llama", "mistral", "phi"].some((word) => matchLower.includes(word))
  ) {
    const ollamaFalsePositives = [
      "philippine",
      "philippines",
      "geographical",
      "graphical",
      "graphic",
      "graphinterval",
      "graphintervals",
      "graphpanel",
      "graphicone",
      "sidebar_graphic",
      "sidebar graphic",
      "adbe vector graphic",
      "view graphical data",
      "graphicalexplanation",
      "graphical-explain",
      "gallabox",
      "onetaphide",
      "onetaphidereason",
    ];
    if (ollamaFalsePositives.some((fp) => lineLower.includes(fp))) {
      return true;
    }
  }

  return false;
}

/**
 * Check if content should be skipped (binary file, too large, etc.)
 * @param {string} content - File content to check
 * @param {number} maxSizeKB - Maximum size in KB (default: 1000)
 * @returns {boolean} True if file should be skipped
 */
function shouldSkipContent(content, maxSizeKB = 1000) {
  if (!content) {
    return true;
  }

  // Check file size
  const sizeKB = content.length / 1024;
  if (sizeKB > maxSizeKB) {
    return true;
  }

  // Check for binary content (null bytes)
  if (content.includes("\x00")) {
    return true;
  }

  // Check if more than 30% are non-printable (excluding common whitespace)
  const nonPrintable = content.split("").filter((char) => {
    const code = char.charCodeAt(0);
    return code < 32 && code !== 9 && code !== 10 && code !== 13;
  }).length;

  if (content.length > 0 && nonPrintable / content.length > 0.3) {
    return true;
  }

  return false;
}

/**
 * Build GitHub URL with line anchor for evidence
 * @param {string} owner - Repository owner
 * @param {string} repo - Repository name
 * @param {string} path - File path
 * @param {number} line - Line number (optional)
 * @param {string} branch - Branch name (default: main)
 * @returns {string} GitHub URL with line anchor
 */
function buildGitHubUrl(owner, repo, path, line = null, branch = "main") {
  let url = `https://github.com/${owner}/${repo}/blob/${branch}/${path}`;
  if (line) {
    url += `#L${line}`;
  }
  return url;
}

/**
 * Determine severity level based on finding type and weight
 * @param {string} category - Finding category
 * @param {number} weight - Finding weight
 * @returns {string} Severity level: 'critical', 'warning', 'info'
 */
function determineSeverity(category, weight) {
  // Config findings are generally lower severity
  if (category === "config") {
    return "info";
  }

  // Dependency findings with high weight
  if (category === "dependencies" && weight >= 5) {
    return "critical";
  }

  // Code findings with medium-high weight
  if (category === "code" && weight >= 4) {
    return "warning";
  }

  // Default to info
  return "info";
}

/**
 * Group findings by detection type (dependency, code, config, endpoint)
 * @param {Array} findings - Array of findings
 * @returns {Object} Grouped findings by type
 */
function groupFindingsByType(findings) {
  const grouped = {
    dependency: [],
    code: [],
    config: [],
    endpoint: [],
    model: [],
    ci: [],
    protocol: [],
    hardware: [],
    infrastructure: [],
    governance: [],
  };

  for (const finding of findings) {
    // Map category to detection type
    let type = "code"; // default
    if (finding.category === "dependencies") {
      type = "dependency";
    } else if (finding.category === "config") {
      type = "config";
    } else if (
      (finding.title && finding.title.includes("API Endpoint")) ||
      (finding.title && finding.title.toLowerCase().includes("api"))
    ) {
      type = "endpoint";
    } else if (finding.category === "models") {
      type = "model";
    } else if (finding.category === "ci") {
      type = "ci";
    } else if (finding.category === "protocol") {
      type = "protocol";
    } else if (finding.category === "hardware") {
      type = "hardware";
    } else if (finding.category === "infrastructure") {
      type = "infrastructure";
    } else if (finding.category === "governance") {
      type = "governance";
    }

    if (grouped[type]) {
      grouped[type].push(finding);
    }
  }

  return grouped;
}
