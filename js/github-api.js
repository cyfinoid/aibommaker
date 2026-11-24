// GitHub API functions

// Owner/repo slugs are interpolated into API URLs, evidence links, and the
// generated BOM documents, so accept only the characters GitHub itself
// allows instead of trusting whatever the URL happened to contain.
// Owners: letters/digits, then letters/digits/hyphens. Repos: letters/
// digits/hyphens/underscores/dots (".github" is a real repo name).
const REPO_OWNER_RE = /^[A-Za-z0-9][A-Za-z0-9-]*$/;
const REPO_NAME_RE = /^[A-Za-z0-9._-]+$/;

const REPO_INPUT_ERROR = 'Invalid repository format. Use "owner/repo" or GitHub URL.';

function parseRepoInput(input) {
  input = String(input || "").trim();
  if (!input) {
    throw new Error(REPO_INPUT_ERROR);
  }

  // Validate and normalize the extracted slugs. Shared by every accepted
  // input form so no variant can bypass the charset check.
  const finish = (owner, repo) => {
    owner = owner.replace(/\.git$/, "");
    repo = repo.replace(/\.git$/, "");
    if (
      !REPO_OWNER_RE.test(owner) ||
      !REPO_NAME_RE.test(repo) ||
      repo === "." ||
      repo === ".."
    ) {
      throw new Error(REPO_INPUT_ERROR);
    }
    return { owner, repo };
  };

  // Bare-host paste forms ("github.com/owner/repo", "www.github.com/…")
  // were accepted by the old substring matcher; keep them working by
  // pinning the scheme and reusing the URL path below.
  if (/^(?:www\.)?github\.com\/.+/i.test(input)) {
    input = `https://${input}`;
  } else if (/^https?:\/(?!\/)/i.test(input)) {
    // Single-slash scheme typo ("https:/github.com/…") — repair it.
    input = input.replace(/^(https?):\/(?!\/)/i, "$1://");
  }

  // URL forms (https://github.com/o/r, //github.com/o/r,
  // git@github.com:o/r, ssh://git@github.com/o/r.git). Parse the URL and
  // validate its HOST exactly — matching "github.com" as a substring would
  // accept "https://evil.example/github.com/a/b" or
  // "https://github.com.evil.example/a/b".
  if (input.includes("://") || input.startsWith("git@") || input.startsWith("//")) {
    if (input.startsWith("git@")) {
      // scp-like SSH syntax (git@github.com:owner/repo.git) is not
      // URL-parseable; normalize it into ssh:// form first.
      const ssh = input.match(/^git@([^/:]+):\/?([^\/]+)\/(.+)$/);
      if (!ssh) {
        throw new Error(REPO_INPUT_ERROR);
      }
      input = `ssh://git@${ssh[1]}/${ssh[2]}/${ssh[3]}`;
    } else if (input.startsWith("//")) {
      // Protocol-relative URL — pin the scheme so `new URL` can parse it.
      input = `https:${input}`;
    }
    let url;
    try {
      url = new URL(input);
    } catch {
      throw new Error(REPO_INPUT_ERROR);
    }

    const host = url.hostname.toLowerCase();
    if (host !== "github.com" && host !== "www.github.com") {
      throw new Error("Only github.com repository URLs are supported.");
    }

    const segments = url.pathname.split("/").filter(Boolean);
    if (segments.length < 2) {
      throw new Error(REPO_INPUT_ERROR);
    }
    return finish(segments[0], segments[1]);
  }

  // Shorthand "owner/repo" (extra segments such as /tree/main are ignored).
  const parts = input.split("/").filter(Boolean);
  if (parts.length >= 2) {
    return finish(parts[0], parts[1]);
  }

  throw new Error(REPO_INPUT_ERROR);
}

async function fetchRepoMeta(owner, repo, token = null) {
  console.log(`[GitHub API] Fetching metadata for ${owner}/${repo}`);
  const headers = { Accept: "application/vnd.github.v3+json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
    console.log("[GitHub API] Using provided token for authentication");
  } else {
    console.warn("[GitHub API] No token provided - rate limits will be lower");
  }

  const response = await fetch(`${GITHUB_API_BASE}/repos/${owner}/${repo}`, {
    headers,
  });

  if (!response.ok) {
    if (response.status === 404) throw new Error("Repository not found.");
    if (response.status === 429 || response.status === 403) {
      const resetTime = response.headers.get("X-RateLimit-Reset");
      if (resetTime) {
        const resetDate = new Date(parseInt(resetTime) * 1000);
        const waitSeconds = Math.ceil((resetDate - new Date()) / 1000);
        if (waitSeconds > 0) {
          throw new Error(
            `Rate limit exceeded. Waiting ${waitSeconds} seconds... Please provide a GitHub token to avoid rate limits.`,
          );
        }
      }
      throw new Error("Rate limit exceeded. Please provide a GitHub token.");
    }
    throw new Error(`GitHub API error: ${response.status}`);
  }

  const data = await response.json();
  console.log(`[GitHub API] Repository found: ${data.full_name}`);
  console.log(`[GitHub API] Default branch: ${data.default_branch}`);
  console.log(
    `[GitHub API] Stars: ${data.stargazers_count}, Forks: ${data.forks_count}`,
  );

  const langResponse = await fetch(data.languages_url, { headers });
  const languages = langResponse.ok ? await langResponse.json() : {};

  const result = {
    name: data.name,
    fullName: data.full_name,
    description: data.description || "",
    htmlUrl: data.html_url,
    defaultBranch: data.default_branch,
    topics: data.topics || [],
    languages: Object.keys(languages),
    owner: data.owner.login,
    pushedAt: data.pushed_at,
  };

  console.log(
    `[GitHub API] Languages detected: ${result.languages.join(", ") || "None"}`,
  );
  console.log(`[GitHub API] Topics: ${result.topics.join(", ") || "None"}`);

  return result;
}

// Set by fetchRepoTree; true when GitHub truncated the last tree response.
// Checked by the analyzer to surface an "incomplete scan" warning.
let lastTreeFetchTruncated = false;

function wasLastTreeTruncated() {
  return lastTreeFetchTruncated;
}

async function fetchRepoTree(owner, repo, ref, token = null) {
  console.log(`[GitHub API] Fetching file tree for ${owner}/${repo}@${ref}`);
  const headers = { Accept: "application/vnd.github.v3+json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  // NOTE: We use recursive=1 to get the full file tree because:
  // 1. We need to check for documentation files (README.md, SECURITY.md) that may be in subdirectories
  // 2. AI-specific config files (model configs, YAML files) may be anywhere in the repo
  // 3. The tree is fetched once and reused across all detectors, making it efficient
  // 4. This enables targeted scanning of specific file types without multiple API calls
  const startTime = performance.now();
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${owner}/${repo}/git/trees/${ref}?recursive=1`,
    { headers },
  );

  if (!response.ok) {
    console.error(
      "[GitHub API] Failed to fetch tree:",
      response.status,
      response.statusText,
    );
    throw new Error("Failed to fetch repository tree");
  }

  const data = await response.json();
  const files = data.tree.filter((entry) => entry.type === "blob");
  const elapsed = (performance.now() - startTime).toFixed(2);

  console.log(`[GitHub API] Tree fetched in ${elapsed}ms`);
  console.log(
    `[GitHub API] Total entries: ${data.tree.length}, Files: ${files.length}`,
  );

  // GitHub truncates very large trees silently - surface this so users know
  // that results may be incomplete (gap: previously this flag was ignored)
  if (data.truncated) {
    console.warn(
      "[GitHub API] ⚠️  Tree response was TRUNCATED by GitHub - some files are missing from the scan",
    );
  }
  lastTreeFetchTruncated = Boolean(data.truncated);

  const totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);
  console.log(
    `[GitHub API] Total file size: ${(totalSize / 1024 / 1024).toFixed(2)} MB`,
  );

  return files.map((entry) => ({
    path: entry.path,
    type: entry.type,
    size: entry.size,
    sha: entry.sha,
  }));
}

async function searchCodeInRepo(owner, repo, query, token = null) {
  const headers = { Accept: "application/vnd.github.v3+json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const searchQuery = encodeURIComponent(`${query} repo:${owner}/${repo}`);
    // Request text_matches to get line numbers and code snippets
    const response = await fetch(
      `${GITHUB_API_BASE}/search/code?q=${searchQuery}&per_page=100`,
      {
        headers: {
          ...headers,
          Accept: "application/vnd.github.v3.text-match+json", // Request text matches
        },
      },
    );

    // Check rate limit headers
    const remaining = parseInt(
      response.headers.get("X-RateLimit-Remaining") || "0",
    );
    const limit = parseInt(response.headers.get("X-RateLimit-Limit") || "10");
    const resetTime = response.headers.get("X-RateLimit-Reset");

    console.log(
      `[GitHub Search API] Rate limit: ${remaining}/${limit} remaining`,
    );

    if (!response.ok) {
      if (response.status === 403 || response.status === 429) {
        console.warn(`[GitHub Search API] ⚠️  Rate limited!`);

        // Don't wait here - return false to signal rate limit hit
        console.warn(
          `[GitHub Search API] Rate limit hit, deferring to allow other detectors to run`,
        );
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
      const matchedText =
        item.text_matches && item.text_matches.length > 0
          ? item.text_matches[0].matches &&
            item.text_matches[0].matches.length > 0
            ? item.text_matches[0].matches[0].text
            : null
          : null;

      // Extract code snippet from fragment
      if (item.text_matches && item.text_matches.length > 0) {
        const match = item.text_matches[0];
        const fragment = match.fragment || "";

        if (fragment) {
          const lines = fragment.split("\n");

          // Find the line containing the matched text
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            // Skip empty lines and line number markers
            if (!line || line.match(/^\d+:$/)) continue;

            // Validate: line must actually contain the matched text (case-insensitive)
            // AND it should be at the start of the line for better precision
            if (
              matchedText &&
              line.toLowerCase().includes(matchedText.toLowerCase())
            ) {
              // Additional validation: prefer import/def/class statements
              if (line.match(/^(from|import|class|def|const|let|var)\s/)) {
                snippet = line;
                break;
              }
            }
          }

          // If no match found, use the first substantial line
          if (!snippet) {
            snippet = lines
              .find((l) => {
                const trimmed = l.trim();
                return (
                  trimmed && !trimmed.match(/^\d+:$/) && trimmed.length > 5
                );
              })
              ?.trim();
          }

          // Last resort: use fragment directly (truncated)
          if (!snippet) {
            snippet = fragment.replace(/\n/g, " ").substring(0, 150).trim();
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
        snippet: snippet,
      };
    });

    // Return both results and rate limit info
    return {
      items: enhancedItems,
      rateLimit: {
        remaining,
        limit,
        resetTime: resetTime ? new Date(parseInt(resetTime) * 1000) : null,
      },
    };
  } catch (error) {
    console.error("[GitHub Search API] Error:", error);
    return null;
  }
}

async function fetchGitHubSBOM(owner, repo, token) {
  console.log(`[GitHub SBOM API] Fetching SBOM for ${owner}/${repo}`);
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(
      `${GITHUB_API_BASE}/repos/${owner}/${repo}/dependency-graph/sbom`,
      { headers },
    );

    if (!response.ok) {
      if (response.status === 404) {
        console.log(
          "[GitHub SBOM API] Dependency graph not available for this repository",
        );
      } else if (response.status === 403) {
        console.log(
          "[GitHub SBOM API] Insufficient permissions - dependency graph may be disabled",
        );
      } else if (response.status === 401) {
        console.log("[GitHub SBOM API] Authentication required");
      } else {
        console.log(
          `[GitHub SBOM API] Error ${response.status}: ${response.statusText}`,
        );
      }
      return null;
    }

    const data = await response.json();
    const packageCount = data.sbom?.packages?.length || 0;
    console.log(
      `[GitHub SBOM API] ✓ SBOM retrieved successfully: ${packageCount} packages found`,
    );
    return data;
  } catch (error) {
    console.error("[GitHub SBOM API] Exception:", error.message);
    return null;
  }
}

async function fetchHuggingFaceModelInfo(modelId) {
  console.log(`[HuggingFace API] Fetching model info for: ${modelId}`);
  try {
    const response = await fetch(`${HUGGINGFACE_API_BASE}/models/${modelId}`);

    if (!response.ok) {
      if (response.status === 429) {
        console.warn(
          `[HuggingFace API] ⚠️  Rate limit hit for: ${modelId} (429 Too Many Requests)`,
        );
        const resetHeader = response.headers.get("X-RateLimit-Reset");
        if (resetHeader) {
          console.warn(
            `[HuggingFace API] Rate limit resets at: ${new Date(parseInt(resetHeader) * 1000).toLocaleTimeString()}`,
          );
        }
      } else if (response.status === 401 || response.status === 403) {
        console.warn(
          `[HuggingFace API] ⚠️  Authentication required for: ${modelId} (${response.status}) - continuing without verification`,
        );
      } else if (response.status === 404) {
        console.warn(
          `[HuggingFace API] ⚠️  Model not found: ${modelId} (404 Not Found) - may not be a HuggingFace model`,
        );
      } else {
        console.warn(
          `[HuggingFace API] ⚠️  HTTP ${response.status} for: ${modelId}`,
        );
      }
      // Return a minimal object indicating the model wasn't verified
      return { verified: false, id: modelId, status: response.status };
    }

    const data = await response.json();
    console.log(`[HuggingFace API] ✓ Found model: ${data.id}`);

    // Fetch additional data: config.json and ModelCard README
    let configData = null;
    let modelCardContent = null;
    let evalResults = null;

    try {
      // Fetch config.json for model architecture details
      const configResponse = await fetch(
        `https://huggingface.co/${modelId}/resolve/main/config.json`,
      );
      if (configResponse.ok) {
        configData = await configResponse.json();
        console.log(`[HuggingFace API] ✓ Fetched config.json for ${modelId}`);
      }
    } catch (e) {
      console.log(
        `[HuggingFace API] Could not fetch config.json for ${modelId}: ${e.message}`,
      );
    }

    try {
      // Fetch README.md for ModelCard YAML frontmatter
      const readmeResponse = await fetch(
        `https://huggingface.co/${modelId}/resolve/main/README.md`,
      );
      if (readmeResponse.ok) {
        modelCardContent = await readmeResponse.text();
        console.log(`[HuggingFace API] ✓ Fetched README.md for ${modelId}`);
      }
    } catch (e) {
      console.log(
        `[HuggingFace API] Could not fetch README.md for ${modelId}: ${e.message}`,
      );
    }

    // Extract eval_results from cardData if available
    if (data.cardData?.eval_results) {
      evalResults = data.cardData.eval_results;
    }

    // Extract cardData fields
    const cardData = data.cardData || {};

    // Extract model parameters from config.json
    const modelParameters = {};
    if (configData) {
      modelParameters.num_parameters =
        configData.num_parameters ||
        configData.n_parameters ||
        configData.total_params ||
        null;
      modelParameters.vocab_size = configData.vocab_size || null;
      modelParameters.contextWindow =
        configData.max_position_embeddings ||
        configData.max_seq_len ||
        configData.max_seq_length ||
        null;
      modelParameters.hidden_size =
        configData.hidden_size ||
        configData.d_model ||
        configData.n_embd ||
        null;
      modelParameters.num_layers =
        configData.num_layers ||
        configData.n_layer ||
        configData.num_hidden_layers ||
        null;
      modelParameters.num_attention_heads =
        configData.num_attention_heads ||
        configData.n_head ||
        configData.num_heads ||
        null;
    }

    try {
      // Fetch tokenizer_config.json for tokenizer identity (G7 #29)
      const tokenizerResponse = await fetch(
        `https://huggingface.co/${modelId}/resolve/main/tokenizer_config.json`,
      );
      if (tokenizerResponse.ok) {
        const tokenizerData = await tokenizerResponse.json();
        if (tokenizerData.tokenizer_class) {
          modelParameters.tokenizerClass = tokenizerData.tokenizer_class;
          console.log(`[HuggingFace API] ✓ Fetched tokenizer_class for ${modelId}`);
        }
      }
    } catch (e) {
      console.log(`[HuggingFace API] Could not fetch tokenizer_config.json for ${modelId}: ${e.message}`);
    }

    return {
      verified: true,
      id: data.id,
      sha: data.sha,
      lastModified: data.lastModified,
      author: data.author,
      downloads: data.downloads || 0,
      likes: data.likes || 0,
      tags: data.tags || [],
      pipeline_tag: data.pipeline_tag,
      library_name: data.library_name,
      license: cardData.license || data.cardData?.license,
      modelSize: data.safetensors?.total || null,
      // Enhanced fields
      cardData: {
        license: cardData.license,
        language: cardData.language,
        base_model: cardData.base_model,
        datasets: cardData.datasets,
        model_summary: cardData.model_summary || cardData.description,
        model_type: cardData.model_type,
        eval_results: evalResults,
      },
      config: configData,
      modelCardContent: modelCardContent,
      // Extract metadata
      primaryPurpose: data.pipeline_tag || "text-generation",
      suppliedBy: data.author || modelId.split("/")[0],
      typeOfModel:
        configData?.model_type || cardData.model_type || "transformer",
      architectures: configData?.architectures || [],
      safetensors: data.safetensors,
      // Model parameters extracted from config
      modelParameters: modelParameters,
    };
  } catch (error) {
    console.warn(
      `[HuggingFace API] ⚠️  Exception fetching ${modelId}:`,
      error.message,
    );
    // Return unverified rather than null so the model can still be included
    return { verified: false, id: modelId };
  }
}

async function fetchHuggingFaceDatasetInfo(datasetId) {
  console.log(`[HuggingFace API] Fetching dataset info for: ${datasetId}`);
  try {
    const response = await fetch(`${HUGGINGFACE_API_BASE}/datasets/${datasetId}`);
    if (!response.ok) {
      console.warn(
        `[HuggingFace API] ⚠️  Dataset not enriched: ${datasetId} (HTTP ${response.status})`,
      );
      return { verified: false, id: datasetId, status: response.status };
    }

    const data = await response.json();
    console.log(`[HuggingFace API] ✓ Found dataset: ${data.id}`);
    return {
      verified: true,
      id: data.id || datasetId,
      enrichment: buildDatasetEnrichmentFromHuggingFace(data)
    };
  } catch (error) {
    console.warn(`[HuggingFace API] ⚠️  Exception fetching dataset ${datasetId}:`, error.message);
    return { verified: false, id: datasetId };
  }
}

function createFileContentFetcher(owner, repo, ref, token = null) {
  const cache = new Map();
  const headers = { Accept: "application/vnd.github.v3+json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let rateLimitWaitUntil = 0;

  return async function getFileContent(path) {
    if (cache.has(path)) return cache.get(path);

    // Check if we need to wait for rate limit
    const now = Date.now();
    if (rateLimitWaitUntil > now) {
      const waitMs = rateLimitWaitUntil - now;
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }

    try {
      const response = await fetch(
        `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}?ref=${ref}`,
        { headers },
      );

      // Handle rate limiting
      if (response.status === 429 || response.status === 403) {
        const resetTime = response.headers.get("X-RateLimit-Reset");
        const remaining = response.headers.get("X-RateLimit-Remaining");
        console.warn(`[Rate Limit] Hit rate limit on ${path}`);
        console.warn(`[Rate Limit] Remaining: ${remaining || "unknown"}`);

        if (resetTime) {
          rateLimitWaitUntil = parseInt(resetTime) * 1000;
          const waitMs = rateLimitWaitUntil - Date.now();
          if (waitMs > 0 && waitMs < 60000) {
            // Wait up to 60 seconds
            console.log(
              `[Rate Limit] Waiting ${Math.ceil(waitMs / 1000)} seconds before retry...`,
            );
            await new Promise((resolve) => setTimeout(resolve, waitMs));
            console.log(`[Rate Limit] Retrying ${path}...`);
            // Retry
            return getFileContent(path);
          } else {
            console.error(
              `[Rate Limit] Wait time too long (${Math.ceil(waitMs / 1000)}s), skipping file`,
            );
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
        const content = atob(data.content.replace(/\n/g, ""));
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
