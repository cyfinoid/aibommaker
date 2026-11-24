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

/**
 * Build a structured model card from HuggingFace API details, used when the
 * remote model card README has no parseable YAML frontmatter. Only verified
 * API data is included — nothing is fabricated (no intended-use or
 * limitations text if the API didn't provide it). Shape matches the local
 * model card JSONs so downstream consumers (UI panel, BOM generators) treat
 * both identically.
 * @param {Object} hfDetails fetchHuggingFaceModelInfo() result
 * @param {string} [modelName] Fallback model identifier
 * @returns {Object|null} Structured model card, or null when not verified
 */
/**
 * Extract version / quantization / parameter-size facts embedded in a model
 * identifier (e.g. "meta-llama-v3-q4" → version 3, quantization q4;
 * "llama-3.1-70b-instruct" → version 3.1, parameter-size 70b). These are
 * declared in the source identifier itself, not invented.
 *
 * Conservative rules to avoid false grabs:
 * - quantization:  q4, q4_k_m, q8_0, int8, fp16, f16 … (dash/dot-bounded)
 * - parameter size: 70b, 8b, 1.5b, 350m (dash/colon-bounded)
 * - version: v-prefixed numbers (v3, v2.1) or dot-bounded numerics (3.5)
 *   — bare integers (the "3" in qwen3) are NOT taken as versions
 * @param {string} modelName
 * @returns {Object|null} {version?, quantization?, parameterSize?}
 */
function extractModelNameVersionInfo(modelName) {
  if (!modelName || typeof modelName !== "string") {
    return null;
  }
  const info = {};

  const q = modelName.match(/(?:^|[-_.])((?:q\d(?:(?:_[a-z0-9]+)+)?|int[48]|fp(?:16|32)|f(?:16|32)))(?=$|[-_.])/i);
  if (q) {
    info.quantization = q[1].toLowerCase();
  }

  const p = modelName.match(/(?:^|[-_.:])(\d+(?:\.\d+)?)([bm])(?=$|[-_.:])/i);
  if (p) {
    info.parameterSize = `${p[1]}${p[2].toLowerCase()}`;
  }

  let v = modelName.match(/(?:^|[-_.])v(\d+(?:\.\d+)*)(?=$|[-_.])/i);
  if (!v) {
    // Dash/dot-bounded dotted numbers (…-3.5-…)
    v = modelName.match(/(?:^|[-_.])(\d+\.\d+)(?=$|[-_.])/i);
  }
  if (!v) {
    // Letter-attached dotted numbers (qwen2.5-coder)
    const attached = modelName.match(/([a-z])(\d+\.\d+)(?=$|[-_.])/i);
    if (attached) {
      info.version = attached[2];
    }
  }
  if (!v && !info.version) {
    // Dash-bounded bare integer with a following segment (claude-3-sonnet,
    // meta-llama-3-70b) — bare attached integers (qwen3) are NOT versions
    v = modelName.match(/(?:^|[-_])(\d+)(?=-[-a-z0-9])/i);
  }
  if (v && !info.version) {
    info.version = v[1];
  }

  return Object.keys(info).length > 0 ? info : null;
}

/**
 * Build a dataset enrichment record from a HuggingFace datasets-API payload
 * (GET /api/datasets/<id>). License comes from the card license first, then
 * the `license:` tag; description only when the hub provides one — nothing
 * is fabricated. Returns null for unresolvable payloads.
 * @param {Object} apiData Raw API payload
 * @returns {Object|null} {id, license?, description?, lastModified?, downloads?}
 */
function buildDatasetEnrichmentFromHuggingFace(apiData) {
  if (!apiData || !apiData.id) {
    return null;
  }

  const enrichment = { id: apiData.id };
  const licenseTag = (apiData.tags || [])
    .find((t) => typeof t === "string" && t.startsWith("license:"));
  const license = apiData.cardData?.license
    || (licenseTag ? licenseTag.slice("license:".length) : null);
  if (license) {
    enrichment.license = license;
  }
  const description = apiData.description || apiData.cardData?.description || null;
  if (description) {
    enrichment.description = description;
  }
  if (apiData.lastModified) {
    enrichment.lastModified = apiData.lastModified;
  }
  if (apiData.downloads != null) {
    enrichment.downloads = apiData.downloads;
  }
  return enrichment;
}

/**
 * True when a candidate `org/model` slug was extracted from a module
 * import/require statement. Models are never importable modules — an
 * import specifier like `import { hideBin } from 'yargs/helpers'` is an
 * npm module path, not a HuggingFace model reference. Rejecting these
 * locally avoids both false positives and unnecessary HF API calls.
 * @param {string} lineContent The matched source line
 * @param {string} modelName Candidate model name
 * @returns {boolean}
 */
function isNpmImportSpecifier(lineContent, modelName) {
  if (!modelName || !modelName.includes("/")) {
    return false;
  }
  if (!lineContent || typeof lineContent !== "string") {
    return false;
  }
  // import x from 'pkg/sub' · import 'pkg/sub' · export * from 'pkg/sub'
  // · Python: from pkg.sub import x · require('pkg/sub')
  const lineImport = /^\s*(?:import\b|from\s+[\w.]+\s+import\b|export\b)/.test(lineContent);
  const requireCall = /require\s*\(\s*["'][^"']+["']\s*\)/.test(lineContent);
  return lineImport || requireCall;
}

function buildModelCardDataFromHuggingFace(hfDetails, modelName) {
  if (!hfDetails || !hfDetails.verified) {
    return null;
  }
  const card = {
    modelName: hfDetails.id || modelName,
    provider: 'HuggingFace',
    source: 'huggingface-api',
    origin: 'open-source-hub'
  };

  // Task / type straight from the API — omit rather than guess
  if (hfDetails.pipeline_tag) {
    card.modelType = hfDetails.pipeline_tag;
  }

  // Capability tags (HF tags mix capabilities with license/dataset/paper
  // metadata — the latter are not capabilities)
  const METADATA_TAG_PREFIXES = ['license:', 'dataset:', 'arxiv:', 'doi:', 'url:', 'region:', 'spaces:', 'mediatype:', 'base_model:'];
  const capabilities = (hfDetails.tags || [])
    .filter((t) => typeof t === 'string' && t.trim() && !METADATA_TAG_PREFIXES.some((p) => t.startsWith(p)));
  if (capabilities.length > 0) {
    card.capabilities = capabilities;
  }

  // Architecture facts from config.json
  const contextWindow = hfDetails.modelParameters?.contextWindow;
  const architecture = hfDetails.architectures?.[0];
  if (contextWindow || architecture) {
    card.architecture = {};
    if (architecture) card.architecture.type = architecture;
    if (contextWindow) card.architecture.contextLength = contextWindow;
  }

  // License + hub provenance
  if (hfDetails.license) {
    card.access = { license: hfDetails.license, origin: 'open-source-hub' };
  }

  // Model summary from the card when the API surfaced one
  if (hfDetails.cardData?.model_summary) {
    card.description = hfDetails.cardData.model_summary;
  }

  // Reference link back to the hub model page
  const modelId = hfDetails.id || modelName;
  if (modelId) {
    card.references = { modelPage: `https://huggingface.co/${modelId}` };
  }

  return card;
}

/**
 * Format a model-card field for display.
 *
 * Local model card JSONs store some fields as structured objects rather than
 * plain strings, e.g.:
 *   intendedUse: { primaryUses: [...], outOfScope: [...] }
 *   limitations: { knownLimitations: [...] }
 *   trainingData: { description: "..." }
 * Interpolating such an object into a template literal renders "[object
 * Object]", so callers must run it through this formatter first. A plain
 * string field (or a `note` string on the object) is returned as-is.
 *
 * @param {*} value Raw field value from the model card JSON
 * @param {Object} [labels] Optional label per object key, e.g.
 *   { outOfScope: 'Out of scope' }. Empty label = no prefix. Keys listed in
 *   `labels` are rendered in insertion order; nested string arrays are joined
 *   with '; '.
 * @returns {string} Human-readable text, or '' when nothing readable exists
 */
function formatModelCardField(value, labels = {}) {
  if (value === null || value === undefined) {
    return '';
  }

  if (typeof value === 'string') {
    return value.trim();
  }

  if (Array.isArray(value)) {
    return value
      .filter((item) => typeof item === 'string' && item.trim())
      .map((item) => item.trim())
      .join('; ');
  }

  if (typeof value === 'object') {
    // Prefer a free-form note string if the card carries one.
    if (typeof value.note === 'string' && value.note.trim()) {
      return value.note.trim();
    }

    const parts = [];
    for (const [key, label] of Object.entries(labels)) {
      const nested = value[key];
      if (typeof nested === 'string' && nested.trim()) {
        parts.push(label ? `${label}: ${nested.trim()}` : nested.trim());
      } else if (Array.isArray(nested) && nested.length) {
        const items = nested
          .filter((item) => typeof item === 'string' && item.trim())
          .map((item) => item.trim())
          .join('; ');
        if (items) {
          parts.push(label ? `${label}: ${items}` : items);
        }
      }
    }

    // Fallback: first readable string on the object (unknown card shapes).
    if (parts.length === 0) {
      for (const nested of Object.values(value)) {
        if (typeof nested === 'string' && nested.trim()) {
          parts.push(nested.trim());
          break;
        }
      }
    }

    return parts.join('. ');
  }

  return String(value);
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

// ============================================================================
// CONTEXTUAL MODEL EXTRACTION (inspired by cisco aibom + akumar0205 AIBOM)
// ============================================================================
// These helpers capture model references that literal model-name matching
// misses: kwargs like `model="gpt-4o"`, module constants like
// `MODEL_NAME = "gpt-4o"`, and env-default dataflow like
// `os.environ.get("MODEL", "gpt-4o")`. Unknown/new model ids become visible
// without needing a literal pattern update for every release.
// ============================================================================

/**
 * Check if an extracted string is plausibly a model id (not a version,
 * URL, path, deployment literal, or placeholder).
 * Follows cisco aibom's deployment-literal rejection heuristics.
 * @param {string} value - Candidate model id
 * @returns {boolean} True if the value looks like a model id
 */
function isPlausibleModelId(value) {
  if (!value || typeof value !== "string") return false;
  const v = value.trim();

  // Length bounds: 3-80 chars (cisco uses similar bounds)
  if (v.length < 3 || v.length > 80) return false;

  // Charset: model ids are alphanumeric with . _ / : - separators
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$/.test(v)) return false;

  // Must contain at least one letter (reject pure numbers/versions)
  if (!/[a-zA-Z]/.test(v)) return false;

  const lower = v.toLowerCase();

  // Reject URLs, IPs, ports, templates, file extensions
  if (v.includes("://")) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}/.test(v)) return false; // IPv4
  if (/^[0-9]+(\.[0-9]+)+$/.test(v)) return false; // bare version
  if (lower.includes("{{") || lower.includes("}}")) return false; // templates
  if (lower.startsWith("localhost") || lower.startsWith("127.0.0.1")) return false;
  if (lower === "latest" || lower === "unknown" || lower === "none") return false;
  if (lower === "null" || lower === "true" || lower === "false") return false;
  if (/\.(png|jpg|jpeg|gif|svg|css|html|json|yml|yaml|txt|md|pdf|csv)$/i.test(v)) return false;

  // Reject well-known non-model config keys (akumar0205 misleading_config fixture):
  // values like "pytest" for model_trainer, "openai" for provider etc.
  const nonModelValues = [
    "pytest", "provider", "openai", "anthropic", "azure", "aws", "gcp",
    "google", "huggingface", "azureml", "vertexai", "bedrock", "ollama",
    "config", "default", "template", "placeholder", "example", "sample",
    "test", "change-me", "changeme", "your-model", "your_model", "xxx",
  ];
  if (nonModelValues.includes(lower)) return false;

  return true;
}

/**
 * Normalize a Bedrock-style model id to its public model name.
 * e.g. "us.anthropic.claude-3-5-sonnet-20241022-v2:0" -> "claude-3-5-sonnet"
 * Follows cisco aibom's Bedrock ARN flattening (model_detector.py alias logic).
 * @param {string} raw - Raw Bedrock model id
 * @returns {string|null} Normalized model id, or null if not normalizable
 */
function normalizeBedrockModelId(raw) {
  if (!raw || typeof raw !== "string") return null;
  let id = raw.trim();

  // Strip inference-profile / regional prefixes: us., eu., apac., us-gov.
  id = id.replace(/^(?:us|eu|apac|us-gov)\./i, "");

  // Strip provider prefixes: anthropic., amazon., meta., ai21., cohere., deepseek.
  const providerMatch = id.match(/^(anthropic|amazon|meta|ai21|cohere|deepseek|mistral)\.(.+)$/i);
  if (providerMatch) {
    id = providerMatch[2];
  } else if (/^[a-z0-9-]+\.[a-z]/i.test(id)) {
    // Unknown provider prefix (e.g. "openai.gpt-...") - strip it too
    id = id.replace(/^[a-z0-9-]+\./i, "");
  }

  // Strip version suffix: -v1:0 / -v2:0 / :0
  id = id.replace(/(-v\d+)?(:\d+)?$/i, "");

  // Strip trailing date suffix: -20241022 (keeps id resolvable against literal lists)
  id = id.replace(/-\d{8}$/i, "");

  return isPlausibleModelId(id) ? id : null;
}

/**
 * Convert Jupyter notebook JSON content to plain source text so code/model
 * detectors can scan .ipynb files. Returns empty string for invalid notebooks.
 * @param {string} content - Raw .ipynb file content (JSON)
 * @returns {string} Joined cell source code
 */
function stripNotebookCells(content) {
  if (!content || typeof content !== "string") return "";
  let notebook;
  try {
    notebook = JSON.parse(content);
  } catch (e) {
    return "";
  }
  if (!notebook || !Array.isArray(notebook.cells)) return "";

  const sources = [];
  for (const cell of notebook.cells) {
    const src = cell?.source;
    if (Array.isArray(src)) {
      sources.push(src.join(""));
    } else if (typeof src === "string") {
      sources.push(src);
    }
  }
  return sources.join("\n");
}

// Provider hints for constructor-based attribution of extracted model refs.
// Maps constructor/class names to provider names (order: most specific first).
const MODEL_CTOR_PROVIDER_HINTS = [
  { pattern: /ChatOpenAI|AzureChatOpenAI/, provider: "OpenAI" },
  { pattern: /ChatAnthropic/, provider: "Anthropic" },
  { pattern: /ChatGoogleGenerativeAI|GenerativeModel|ChatVertexAI/, provider: "Google" },
  { pattern: /ChatBedrock|BedrockRuntime|BedrockEmbeddings/, provider: "AWS Bedrock" },
  { pattern: /ChatGroq|Groq\(/, provider: "Groq" },
  { pattern: /ChatMistralAI|Mistral\(/, provider: "Mistral" },
  { pattern: /ChatCohere|Cohere\(/, provider: "Cohere" },
  { pattern: /ChatOllama|Ollama\(|OllamaEmbeddings/, provider: "Ollama" },
  { pattern: /HuggingFacePipeline|HuggingFaceEndpoint|HuggingFaceHub/, provider: "HuggingFace" },
  { pattern: /AzureOpenAI/, provider: "OpenAI" },
  { pattern: /OpenAI(?:Client)?\(/, provider: "OpenAI" },
  { pattern: /Anthropic\(/, provider: "Anthropic" },
];

/**
 * Guess the provider from the constructor/class name used on the same line
 * as a model reference.
 * @param {string} line - The line containing the model reference
 * @returns {string|null} Provider name, or null if unknown
 */
function inferProviderFromLine(line) {
  for (const hint of MODEL_CTOR_PROVIDER_HINTS) {
    if (hint.pattern.test(line)) return hint.provider;
  }
  return null;
}

/**
 * Extract model references from code using context (kwargs, constants,
 * env-with-default) instead of hardcoded model-name literals.
 * Returns candidates validated by isPlausibleModelId, deduplicated,
 * with optional provider attribution from constructor context.
 *
 * @param {string} content - File content to scan
 * @param {Set} providersUsed - Set of providers already detected in the repo
 *   (used to gate the "unknown provider" bucket; optional)
 * @returns {Array<{model: string, provider: string|null, method: string, line: number}>}
 */
function extractContextualModelRefs(content, providersUsed = null) {
  if (!content || typeof content !== "string") return [];
  const results = [];
  const seen = new Set();
  const lines = content.split("\n");

  // Pass 1: collect constant-name -> model-id map for variable resolution.
  // Python/JS module constants: MODEL_NAME = "gpt-4o", model_id = "claude-..."
  const constMap = new Map();
  const constPattern = /^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_][A-Za-z0-9_]*(?:[A-Z_]{2,}|[Mm]odel[A-Za-z0-9_]*))\s*=\s*["']([^"']{3,80})["']/;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(constPattern);
    if (m && isPlausibleModelId(m[2])) {
      // Only track variables that look model-related by name
      if (/model/i.test(m[1]) || /^[A-Z_]*_MODEL/.test(m[1])) {
        constMap.set(m[1], { model: m[2], line: i + 1 });
      }
    }
  }

  const addResult = (model, provider, method, line) => {
    if (!isPlausibleModelId(model)) return;
    const key = `${provider || "?"}-${model}`;
    if (seen.has(key)) return;
    // Skip if this exact model id was assigned from a tracked constant
    // (avoid double-counting declaration + usage when provider is unknown)
    seen.add(key);
    results.push({ model, provider: provider || null, method, line });
  };

  const kwargPattern = /[{,(\s](model|model_name|model_id|deployment_name)\s*[:=]\s*["']([^"']{3,80})["']/g;
  const kwargVarPattern = /[{,(\s](model|model_name|model_id|deployment_name)\s*[:=]\s*([A-Za-z_][A-Za-z0-9_.]*)\s*[,)}]/g;
  const envDefaultPatterns = [
    /(?:os\.environ\.get|os\.getenv)\(\s*["'][^"']+["']\s*,\s*["']([^"']{3,80})["']\s*\)/g,
    /process\.env\.[A-Za-z_]+\s*(?:\?\?|\|\|)\s*["']([^"']{3,80})["']/g,
    /process\.env\.[A-Za-z_]+\s*\?\s*[^:]+:\s*["']([^"']{3,80})["']/g,
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments and long string-literal-only lines (existing FP heuristics)
    if (isCommentOrStringLiteral(line)) continue;
    if (line.length > 10000) continue; // ReDoS guard (mirrors ai-spotter)

    const providerHint = inferProviderFromLine(line);

    // 1. Direct kwarg literals: model="gpt-4o"
    kwargPattern.lastIndex = 0;
    let m;
    while ((m = kwargPattern.exec(line)) !== null) {
      addResult(m[2], providerHint, `kwarg-${m[1]}`, i + 1);
    }

    // 2. Kwarg referencing a tracked constant: model=DEFAULT_MODEL
    kwargVarPattern.lastIndex = 0;
    while ((m = kwargVarPattern.exec(line)) !== null) {
      const varName = m[2].split(".").pop(); // allow config.model references
      const resolved = constMap.get(varName);
      if (resolved) {
        addResult(resolved.model, providerHint, `constant-${varName}`, i + 1);
      }
    }

    // 3. Env-with-default dataflow (both os.environ.get and process.env forms)
    for (const pattern of envDefaultPatterns) {
      pattern.lastIndex = 0;
      while ((m = pattern.exec(line)) !== null) {
        addResult(m[1], providerHint, "env-default", i + 1);
      }
    }
  }

  // 4. Assignments of tracked constants themselves (module-level MODEL_NAME = "...")
  for (const [varName, info] of constMap) {
    const provider = inferProviderFromName(varName);
    addResult(info.model, provider, `assignment-${varName}`, info.line);
  }

  // When the repo's providers are known, drop refs attributed to providers we
  // did not detect. Refs with provider === null (unattributed) are kept on
  // purpose: discovering unknown models is exactly what this pass is for -
  // the caller merges them into existing entries or marks them "Unknown".
  if (providersUsed && providersUsed.size > 0) {
    return results.filter((r) => r.provider === null || providersUsed.has(r.provider));
  }
  return results;
}

/**
 * Guess provider from a constant variable name (e.g. OPENAI_MODEL -> OpenAI).
 * @param {string} varName - Variable name
 * @returns {string|null} Provider name or null
 */
function inferProviderFromName(varName) {
  const name = varName.toLowerCase();
  if (name.includes("openai")) return "OpenAI";
  if (name.includes("anthropic") || name.includes("claude")) return "Anthropic";
  if (name.includes("gemini") || name.includes("google") || name.includes("vertex")) return "Google";
  if (name.includes("bedrock") || name.includes("aws")) return "AWS Bedrock";
  if (name.includes("ollama")) return "Ollama";
  if (name.includes("groq")) return "Groq";
  if (name.includes("mistral")) return "Mistral";
  if (name.includes("cohere")) return "Cohere";
  if (name.includes("azure")) return "OpenAI";
  return null;
}
