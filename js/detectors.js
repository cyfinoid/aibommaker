// ============================================================================
// AI/LLM DETECTION FUNCTIONS
// ============================================================================
// Detection Strategy:
// 1. Dependencies: SBOM API first (GitHub Dependency Graph)
//    - Falls back to manual parsing only if SBOM API fails (404, disabled, etc.)
// 2. Code: GitHub Search API for patterns, fallback to file scanning
// 3. Models: Pattern matching in code files with HuggingFace API verification
// 4. Config/CI/Prompts: File-based detection with pattern matching
// ============================================================================

async function metadataDetector({ repoMeta }) {
  console.log("[Detector: Metadata] Starting metadata analysis...");
  const findings = [];
  const keywords = [
    "llm",
    "gpt",
    "langchain",
    "llamaindex",
    "rag",
    "chatbot",
    "ai assistant",
    "openai",
    "anthropic",
    "claude",
    "gemini",
    "generative ai",
  ];

  const description = (repoMeta.description || "").toLowerCase();
  const topics = (repoMeta.topics || []).map((t) => t.toLowerCase());
  const foundKeywords = new Set();

  console.log(
    `[Detector: Metadata] Checking ${keywords.length} keywords against description and ${topics.length} topics`,
  );

  for (const keyword of keywords) {
    if (description.includes(keyword)) {
      foundKeywords.add(keyword);
    }
  }

  for (const topic of topics) {
    for (const keyword of keywords) {
      if (topic.includes(keyword)) {
        foundKeywords.add(keyword);
      }
    }
  }

  if (foundKeywords.size > 0) {
    console.log(
      `[Detector: Metadata] ℹ️  Found ${foundKeywords.size} AI keywords in metadata:`,
      Array.from(foundKeywords),
    );
    console.log(
      `[Detector: Metadata] Note: Metadata keywords are logged but not included as AIBOM findings`,
    );
    console.log(
      `[Detector: Metadata] Reason: Repository metadata is already captured in BOM metadata, keywords don't represent actual components`,
    );
    // Don't create a finding - metadata is interesting for analysis but not a component
  } else {
    console.log("[Detector: Metadata] No AI keywords found in metadata");
  }

  console.log(`[Detector: Metadata] Complete. Findings: ${findings.length}`);
  return findings;
}

async function dependenciesDetector({
  tree,
  getFileContent,
  owner,
  repo,
  token,
}) {
  console.log("[Detector: Dependencies] Starting dependency analysis...");
  const findings = [];

  // STEP 1: Try GitHub's SBOM API first
  console.log(
    "[Detector: Dependencies] Attempting to fetch SBOM from GitHub Dependency Graph API...",
  );
  const sbomResult = await fetchGitHubSBOM(owner, repo, token);

  if (sbomResult && sbomResult.sbom) {
    console.log(
      "[Detector: Dependencies] ✓ Successfully fetched SBOM from GitHub",
    );
    const llmDeps = extractLLMDependenciesFromSBOM(sbomResult.sbom);

    if (llmDeps.length > 0) {
      console.log(
        `[Detector: Dependencies] ✓ Found ${llmDeps.length} LLM dependencies via SBOM API`,
      );
      const sbomUrl = `https://github.com/${owner}/${repo}/network/dependencies`;
      llmDeps.forEach((dep) => {
        findings.push({
          id: `dep-${dep.ecosystem}-${dep.name.replace(/[^a-zA-Z0-9]/g, "-")}`,
          title: `Dependency: ${dep.name}`,
          category: "dependencies",
          severity: "high",
          weight: 5,
          description: `LLM-related dependency: ${dep.name}${dep.version ? ` (version: ${dep.version})` : ""}`,
          evidence: [
            {
              file: "GitHub Dependency Graph (SBOM)",
              snippet: `SPDX Package: ${dep.name}@${dep.version}`,
              url: sbomUrl,
            },
          ],
          dependencyInfo: {
            name: dep.name,
            version: dep.version || "unknown",
            ecosystem: dep.ecosystem,
            source: "github-sbom-api",
            spdxId: dep.spdxId,
            license: dep.license,
          },
        });
      });

      console.log(
        `[Detector: Dependencies] Complete (via SBOM API). Findings: ${findings.length}`,
      );
      // Return findings with SBOM metadata for downstream optimization
      return {
        findings,
        sbomAvailable: true,
        dependencies: llmDeps, // Pass the full list for targeted code search
      };
    } else {
      console.log(
        "[Detector: Dependencies] SBOM retrieved but no LLM dependencies found, falling back to manual parsing...",
      );
    }
  } else {
    console.log(
      "[Detector: Dependencies] ⚠️  SBOM API unavailable (dependency graph may not be enabled), falling back to manual parsing...",
    );
  }

  // STEP 2: Fallback to manual manifest file parsing
  console.log(
    "[Detector: Dependencies] Using manual manifest file parsing approach...",
  );
  const manifestFiles = tree.filter((entry) => {
    const fileName = entry.path.split("/").pop();
    return Object.values(MANIFEST_FILES).flat().includes(fileName);
  });

  console.log(
    `[Detector: Dependencies] Found ${manifestFiles.length} manifest files to analyze:`,
    manifestFiles.map((f) => f.path),
  );

  for (const manifest of manifestFiles) {
    console.log(`[Detector: Dependencies] Analyzing ${manifest.path}...`);
    const content = await getFileContent(manifest.path);
    if (!content) {
      console.log(`[Detector: Dependencies] Could not read ${manifest.path}`);
      continue;
    }

    const ecosystem = detectEcosystem(manifest.path);
    if (!ecosystem) {
      console.log(
        `[Detector: Dependencies] Unknown ecosystem for ${manifest.path}`,
      );
      continue;
    }

    console.log(`[Detector: Dependencies] Detected ecosystem: ${ecosystem}`);
    // Use AI_EXTENDED_DEPENDENCIES for comprehensive AI package detection
    const llmDeps =
      AI_EXTENDED_DEPENDENCIES[ecosystem] || LLM_DEPENDENCIES[ecosystem] || [];
    let foundDeps = [];

    if (manifest.path.endsWith("package.json")) {
      foundDeps = findInPackageJson(content, llmDeps);
    } else if (manifest.path.endsWith("requirements.txt")) {
      foundDeps = findInRequirements(content, llmDeps);
    } else if (manifest.path.match(/pyproject\.toml|Pipfile/)) {
      foundDeps = findInPyproject(content, llmDeps);
    } else if (manifest.path.endsWith("go.mod")) {
      foundDeps = findInGoMod(content, llmDeps);
    } else if (manifest.path.endsWith("Cargo.toml")) {
      foundDeps = findInCargoToml(content, llmDeps);
    } else if (manifest.path.endsWith("pom.xml")) {
      foundDeps = findInPomXml(content, llmDeps);
    } else if (manifest.path.match(/build\.gradle/)) {
      foundDeps = findInGradle(content, llmDeps);
    }

    if (foundDeps.length > 0) {
      console.log(
        `[Detector: Dependencies] ✓ Found ${foundDeps.length} LLM dependencies in ${manifest.path}:`,
        foundDeps,
      );

      // Create individual findings for each dependency (machine-readable)
      foundDeps.forEach((dep) => {
        findings.push({
          id: `dep-${ecosystem}-${dep.name.replace(/[^a-zA-Z0-9]/g, "-")}`,
          title: `Dependency: ${dep.name}`,
          category: "dependencies",
          severity: "high",
          weight: 5,
          description: `LLM-related dependency: ${dep.name}${dep.version ? ` (version: ${dep.version})` : ""}`,
          evidence: [
            {
              file: manifest.path,
              line: dep.line,
              snippet: dep.snippet || dep.name,
            },
          ],
          dependencyInfo: {
            name: dep.name,
            version: dep.version || "unknown",
            ecosystem,
            manifestFile: manifest.path,
            source: "manual-parsing",
          },
        });
      });
    } else {
      console.log(
        `[Detector: Dependencies] No LLM dependencies found in ${manifest.path}`,
      );
    }
  }

  console.log(
    `[Detector: Dependencies] Complete (manual parsing). Findings: ${findings.length}`,
  );
  // Return findings without SBOM metadata (fallback mode)
  return {
    findings,
    sbomAvailable: false,
    dependencies: [], // No SBOM data available
  };
}

/**
 * Detect AI packages that are imported in source code but missing from the
 * declared dependencies (e.g. langchain-community / langchain-core, which are
 * only transitive manifest entries yet imported directly). Complements the
 * manifest/SBOM-based dependenciesDetector the way Snyk's source-code-analysis
 * does, so undeclared-but-used AI libraries are not silently dropped from the
 * inventory.
 *
 * Findings carry dependencyInfo.source = 'source-import-analysis' and no
 * version (unknown stays unknown).
 */
async function aiImportsDetector({ tree, aiFilesFound, getFileContent, allFindings }) {
  console.log("[Detector: AI Imports] Scanning source imports for undeclared AI packages...");
  const findings = [];

  // Scan AI-relevant files found by the Code detector PLUS repo source files
  // from the tree — an undeclared-only import chain may never enter
  // aiFilesFound (smart-mode searches target declared dependencies). Capped
  // to keep fetch cost bounded on large repos.
  const SOURCE_EXT = /\.(py|js|jsx|ts|tsx|mjs|cjs)$/i;
  const MAX_EXTRA_FILES = 120;
  const seenFiles = new Set();
  let scanList = [];
  for (const f of Array.isArray(aiFilesFound) ? aiFilesFound : []) {
    if (!seenFiles.has(f) && SOURCE_EXT.test(f)) { seenFiles.add(f); scanList.push(f); }
  }
  const repoPaths = new Set();
  for (const entry of Array.isArray(tree) ? tree : []) {
    if (!entry?.path || !SOURCE_EXT.test(entry.path)) continue;
    repoPaths.add(entry.path);
    if (scanList.length < MAX_EXTRA_FILES && !seenFiles.has(entry.path)) {
      seenFiles.add(entry.path);
      scanList.push(entry.path);
    }
  }
  if (scanList.length === 0) {
    console.log("[Detector: AI Imports] No source files to scan");
    return { findings };
  }
  if (repoPaths.size > MAX_EXTRA_FILES) {
    console.log(
      `[Detector: AI Imports] Note: ${repoPaths.size} source files in tree, scanning first ${scanList.length}`,
    );
  }

  // Normalize names for dedupe: PEP 503 (python -/_/. equal) and lowercase.
  const normalize = (name) => name.toLowerCase().replace(/[-_.]/g, "-");
  const knownDeps = new Set();
  for (const f of allFindings || []) {
    if (f.category === "dependencies") {
      const name = f.dependencyInfo?.name || (f.title || "").replace(/^Dependency:\s*/i, "");
      if (name) knownDeps.add(normalize(name));
    }
  }

  const pyMap = AI_IMPORT_MODULE_MAP.python || {};
  const nodeMap = AI_IMPORT_MODULE_MAP.node || {};

  const seen = new Set();
  for (const file of scanList) {
    const isPython = /\.py$/i.test(file);
    const isJs = /\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(file);
    if (!isPython && !isJs) continue;

    const content = await getFileContent(file);
    if (!content) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      // Skip comment lines (cheap heuristic — import lines never start with
      // a comment marker)
      if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

      let pkg = null;

      if (isPython) {
        const m = line.match(/^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)/);
        if (m) {
          const mod = m[1];
          if (pyMap[mod]) {
            pkg = pyMap[mod];
          } else if (/^langchain_[a-z0-9_]+$/.test(mod)) {
            // Generic langchain_* → langchain-* distribution namespace,
            // but skip repo-local modules (a repo's own langchain_utils.py
            // is not the langchain-utils distribution)
            if (repoPaths.has(`${mod}.py`) ||
                repoPaths.has(`${mod.replace(/_/g, "/")}.py`) ||
                [...repoPaths].some((p) => p.startsWith(`${mod.replace(/_/g, "/")}/`))) {
              continue;
            }
            pkg = mod.replace(/_/g, "-");
          }
        }
      } else {
        const m = line.match(
          /(?:require\s*\(\s*|from\s+|import\s+.*\bfrom\s+|import\s+)["']([^"']+)["']/,
        );
        if (m) {
          const spec = m[1];
          // Scoped packages keep scope/name; plain packages take segment 0
          const mod = spec.startsWith("@")
            ? spec.split("/").slice(0, 2).join("/")
            : spec.split("/")[0];
          if (nodeMap[mod]) {
            pkg = nodeMap[mod];
          } else if (/^@langchain\/[a-z0-9-]+$/.test(mod)) {
            pkg = mod;
          }
        }
      }

      if (!pkg) continue;
      const key = `${isPython ? "py" : "js"}:${normalize(pkg)}`;
      if (seen.has(key) || knownDeps.has(normalize(pkg))) continue;
      seen.add(key);

      findings.push({
        id: `import-${isPython ? "py" : "js"}-${pkg.replace(/[^a-zA-Z0-9]/g, "-")}`,
        title: `Dependency: ${pkg}`,
        category: "dependencies",
        severity: "medium",
        weight: 3,
        description: `AI package imported in source but not declared in manifests: ${pkg} (version unknown)`,
        evidence: [
          {
            file,
            line: i + 1,
            snippet: line.trim().slice(0, 200),
          },
        ],
        dependencyInfo: {
          name: pkg,
          version: "unknown",
          ecosystem: isPython ? "python" : "npm",
          source: "source-import-analysis",
        },
      });
    }
  }

  console.log(
    `[Detector: AI Imports] Complete. Found ${findings.length} undeclared AI package import(s)`,
  );
  return { findings };
}

function extractLLMDependenciesFromSBOM(sbom) {
  console.log("[SBOM Parser] Extracting AI/LLM dependencies from SPDX SBOM...");
  const llmDeps = [];

  // SPDX format: sbom.packages is an array of package objects
  const packages = sbom.packages || [];
  console.log(
    `[SBOM Parser] Processing ${packages.length} packages from SBOM...`,
  );

  // Create a flat list of all known AI dependencies (lowercase for matching)
  // Use AI_EXTENDED_DEPENDENCIES which includes LLM providers, frameworks, agents, protocols, etc.
  const allKnownDeps = [
    ...AI_EXTENDED_DEPENDENCIES.python,
    ...AI_EXTENDED_DEPENDENCIES.node,
    ...AI_EXTENDED_DEPENDENCIES.go,
    ...AI_EXTENDED_DEPENDENCIES.java,
    ...AI_EXTENDED_DEPENDENCIES.rust,
  ].map((d) => d.toLowerCase());

  for (const pkg of packages) {
    const pkgName = pkg.name?.toLowerCase() || "";

    // Skip empty or invalid package names
    if (!pkgName) continue;

    // Match exact or partial (for scoped packages like @anthropic-ai/sdk)
    const isLLMDep = allKnownDeps.some((llmDep) => {
      const llmDepLower = llmDep.toLowerCase();
      // Exact match
      if (pkgName === llmDepLower) return true;
      // Scoped package match (e.g., @anthropic-ai/sdk contains anthropic)
      if (pkgName.includes(llmDepLower)) return true;
      // Reverse match (for cases like langchain-openai matching langchain)
      if (llmDepLower.includes(pkgName)) return true;
      return false;
    });

    if (isLLMDep) {
      const ecosystem = detectEcosystemFromSPDX(pkg);
      console.log(
        `[SBOM Parser] ✓ Found LLM dependency: ${pkg.name} (${ecosystem})`,
      );

      llmDeps.push({
        name: pkg.name,
        version: pkg.versionInfo || "unknown",
        ecosystem,
        spdxId: pkg.SPDXID,
        license: pkg.licenseConcluded || pkg.licenseDeclared || "unknown",
      });
    }
  }

  console.log(
    `[SBOM Parser] Extracted ${llmDeps.length} LLM dependencies from SBOM`,
  );
  return llmDeps;
}

function detectEcosystemFromSPDX(pkg) {
  // SPDX packages often have externalRefs that indicate the ecosystem
  const refs = pkg.externalRefs || [];
  for (const ref of refs) {
    if (ref.referenceType === "purl") {
      // Package URL format: pkg:npm/lodash@1.0.0 or pkg:pypi/requests
      const match = ref.referenceLocator?.match(/^pkg:([^/]+)\//);
      if (match) {
        const purlType = match[1];
        // Map PURL types to our ecosystems
        const ecosystemMap = {
          npm: "node",
          pypi: "python",
          golang: "go",
          maven: "java",
          cargo: "rust",
          gem: "ruby",
          nuget: "dotnet",
        };
        return ecosystemMap[purlType] || purlType;
      }
    }
  }

  // Fallback: try to infer from package name patterns
  const pkgName = pkg.name || "";
  if (pkgName.startsWith("@")) return "node"; // Scoped NPM package

  // Go module detection: properly validate github.com domain (not just substring)
  // Go modules: github.com/owner/repo (no protocol) or https://github.com/owner/repo
  // Must ensure github.com is the actual domain, not a substring in malicious URLs
  if (
    /^(github\.com\/|https?:\/\/github\.com\/|git@github\.com:)/.test(pkgName)
  ) {
    return "go"; // Go module
  }

  if (pkgName.includes(":")) return "java"; // Maven coordinate

  return "unknown";
}

function detectEcosystem(path) {
  if (path.match(/package\.json|yarn\.lock|pnpm-lock/)) return "node";
  if (path.match(/requirements\.txt|pyproject\.toml|Pipfile/)) return "python";
  if (path.endsWith("go.mod")) return "go";
  if (path.endsWith("Cargo.toml")) return "rust";
  if (path.match(/pom\.xml|build\.gradle/)) return "java";
  return null;
}

function findInPackageJson(content, llmDeps) {
  try {
    const pkg = JSON.parse(content);
    const lines = content.split("\n");
    const results = [];

    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    const matchingDeps = Object.keys(allDeps).filter((dep) =>
      llmDeps.some((llmDep) => depMatchesPattern(dep, llmDep.toLowerCase())),
    );

    // Find line numbers for each dependency
    matchingDeps.forEach((dep) => {
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
        snippet: `"${dep}": "${version}"`,
      });
    });

    return results;
  } catch (e) {
    return [];
  }
}

/**
 * Word-boundary dependency-name matcher.
 * Equivalent to the previous `new RegExp("(^|[^a-z])" + dep + "([^a-z]|$)", "i")`
 * but without dynamic RegExp construction (static-analysis ReDoS finding:
 * javascript.lang.security.audit.detect-non-literal-regexp). The registry names
 * are our own constants, not user input, but avoiding dynamic RegExp is free.
 * @param {string} depName - Dependency name from a manifest
 * @param {string} llmDepLower - Known AI dependency name, lowercased
 * @returns {boolean} True if depName matches exactly or at a word boundary
 */
function depMatchesPattern(depName, llmDepLower) {
  const depLower = depName.toLowerCase();
  if (depLower === llmDepLower) return true;

  let idx = depLower.indexOf(llmDepLower);
  while (idx !== -1) {
    const before = idx === 0 ? "" : depLower[idx - 1];
    const end = idx + llmDepLower.length;
    const after = end >= depLower.length ? "" : depLower[end];
    if (!/[a-z]/.test(before) && !/[a-z]/.test(after)) return true;
    idx = depLower.indexOf(llmDepLower, idx + 1);
  }
  return false;
}

function findInRequirements(content, llmDeps) {
  const lines = content.split("\n");
  const deps = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Match: package-name==version or package-name>=version or just package-name
    const match = trimmed.match(/^([a-zA-Z0-9\-_.]+)([>=<~!]+(.+))?/);
    if (match) {
      const depName = match[1];
      const versionSpec = match[2] || "";

      // Use exact match or word boundary match
      const isLLMDep = llmDeps.some((llmDep) =>
        depMatchesPattern(depName, llmDep.toLowerCase()),
      );

      if (isLLMDep) {
        deps.push({
          name: depName,
          version: versionSpec
            ? versionSpec.replace(/^[>=<~!]+/, "")
            : "unspecified",
          line: i + 1,
          snippet: trimmed,
        });
      }
    }
  }
  return deps;
}

function findInPyproject(content, llmDeps) {
  const lines = content.split("\n");
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
      const isLLMDep = llmDeps.some((llmDep) =>
        depMatchesPattern(depName, llmDep.toLowerCase()),
      );

      if (isLLMDep) {
        seen.add(depLower);
        deps.push({
          name: depName,
          version: "unspecified",
          line: i + 1,
          snippet: line.trim(),
        });
      }
    }
  }
  return deps;
}

/**
 * Parse go.mod for AI dependencies.
 * Handles both `require github.com/x/y v1.2.3` and the `require (...)` block.
 * Without this, Go repos (e.g. reference project xbom) yield no dependencies
 * in fallback mode (no SBOM API).
 */
function findInGoMod(content, llmDeps) {
  const lines = content.split("\n");
  const deps = [];
  let inRequireBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith("//")) continue;

    if (trimmed.startsWith("require (")) {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && trimmed === ")") {
      inRequireBlock = false;
      continue;
    }

    // `require github.com/sashabaranov/go-openai v1.32.0` or block line
    const match = trimmed.match(/^(?:require\s+)?([a-zA-Z0-9._\-/~]+)\s+(v[^\s]+)/);
    if (!match || (inRequireBlock === false && !trimmed.startsWith("require"))) continue;

    const depName = match[1];
    const depLower = depName.toLowerCase();

    const isLLMDep = llmDeps.some((llmDep) => {
      const llmDepLower = llmDep.toLowerCase();
      return depLower === llmDepLower || depLower.includes(llmDepLower);
    });

    if (isLLMDep) {
      deps.push({
        name: depName,
        version: match[2],
        line: i + 1,
        snippet: trimmed,
      });
    }
  }
  return deps;
}

/**
 * Parse Cargo.toml [dependencies] section for AI crates.
 */
function findInCargoToml(content, llmDeps) {
  const lines = content.split("\n");
  const deps = [];
  let inDependencies = false;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    if (trimmed.startsWith("[")) {
      inDependencies = trimmed === "[dependencies]";
      continue;
    }
    if (!inDependencies) continue;

    // `async-openai = "0.27"` or `async-openai = { version = "0.27", features = [...] }`
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=/);
    if (!match) continue;

    const depName = match[1];
    const depLower = depName.toLowerCase();

    const isLLMDep = llmDeps.some((llmDep) => {
      const llmDepLower = llmDep.toLowerCase();
      return depLower === llmDepLower || depLower.includes(llmDepLower);
    });

    if (isLLMDep) {
      // version from inline table ({ version = "1.0" }) or simple string ("1.0")
      const versionMatch =
        trimmed.match(/version\s*=\s*"([^"]+)"/) ||
        trimmed.match(/=\s*"([^"]+)"/);
      deps.push({
        name: depName,
        version: versionMatch ? versionMatch[1] : "unspecified",
        line: i + 1,
        snippet: trimmed,
      });
    }
  }
  return deps;
}

/**
 * Parse pom.xml for AI dependencies (groupId:artifactId coordinates).
 */
function findInPomXml(content, llmDeps) {
  const deps = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length - 1; i++) {
    const groupId = lines[i].match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
    const artifactId = lines[i + 1]?.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
    if (!groupId || !artifactId) continue;

    const coordinate = `${groupId}:${artifactId}`;
    const coordinateLower = coordinate.toLowerCase();
    const artifactLower = artifactId.toLowerCase();

    const isLLMDep = llmDeps.some((llmDep) => {
      const llmDepLower = llmDep.toLowerCase();
      return (
        coordinateLower.includes(llmDepLower) ||
        artifactLower.includes(llmDepLower.split(":").pop())
      );
    });

    if (isLLMDep) {
      // Version may appear in one of the following lines
      let version = "unspecified";
      for (let j = i + 2; j < Math.min(i + 6, lines.length); j++) {
        const v = lines[j].match(/<version>([^<]+)<\/version>/)?.[1]?.trim();
        if (v) {
          version = v;
          break;
        }
      }
      deps.push({
        name: coordinate,
        version,
        line: i + 1,
        snippet: lines[i].trim(),
      });
    }
  }
  return deps;
}

/**
 * Parse build.gradle(.kts) for AI dependencies.
 */
function findInGradle(content, llmDeps) {
  const lines = content.split("\n");
  const deps = [];

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed) continue;

    // implementation 'com.openai:openai-java:0.1.0' / implementation "..." / api "..."
    const match = trimmed.match(/(?:implementation|api|compile|runtimeOnly)\s+["']([^"']+)["']/);
    if (!match) continue;

    const notation = match[1]; // group:artifact:version
    const notationLower = notation.toLowerCase();

    const isLLMDep = llmDeps.some((llmDep) => {
      const llmDepLower = llmDep.toLowerCase();
      return notationLower.includes(llmDepLower);
    });

    if (isLLMDep) {
      const parts = notation.split(":");
      deps.push({
        name: parts.length >= 2 ? `${parts[0]}:${parts[1]}` : notation,
        version: parts.length >= 3 ? parts[2] : "unspecified",
        line: i + 1,
        snippet: trimmed,
      });
    }
  }
  return deps;
}

async function codeDetector({
  tree,
  getFileContent,
  owner,
  repo,
  token,
  resumeState,
  repoMeta,
  sbomAvailable,
  detectedDependencies,
}) {
  console.log("[Detector: Code] Starting code analysis...");
  const findings = [];
  let aiFilesFound = []; // Track files where AI usage was found

  // Try GitHub Search API first (more efficient if token is provided)
  // NOTE: We use GitHub Search API for primary detection, but still need recursive tree scanning because:
  // 1. GitHub Search API has rate limits and may not cover all patterns
  // 2. Some AI-specific files (config files, model files, etc.) may not match search patterns
  // 3. We need to scan files identified by search API for detailed analysis (line numbers, context)
  // 4. Fallback is needed when Search API is unavailable or rate-limited
  if (token) {
    console.log(
      "[Detector: Code] Using GitHub Search API for efficient scanning...",
    );
    const languages = repoMeta?.languages || [];

    // Pass SBOM intelligence to search function for optimization
    const searchResult = await searchCodeViaAPI(
      owner,
      repo,
      token,
      resumeState,
      languages,
      sbomAvailable,
      detectedDependencies,
      getFileContent,
    );

    if (searchResult) {
      findings.push(...searchResult.findings);
      console.log(
        `[Detector: Code] Search API found ${searchResult.findings.length} findings so far`,
      );

      // Extract files where AI was found for later detailed scanning
      searchResult.findings.forEach((finding) => {
        finding.evidence?.forEach((ev) => {
          if (ev.file && !aiFilesFound.includes(ev.file)) {
            aiFilesFound.push(ev.file);
          }
        });
      });

      console.log(
        `[Detector: Code] Identified ${aiFilesFound.length} files with AI usage for detailed scanning`,
      );

      // If paused due to rate limit, return findings with resume state
      if (searchResult.paused) {
        return {
          findings,
          paused: true,
          resumeState: searchResult.resumeState,
          aiFilesFound, // Pass this to other detectors
        };
      }

      // All searches complete
      console.log("[Detector: Code] ✓ All searches completed");
      return { findings, paused: false, aiFilesFound };
    }
    console.log(
      "[Detector: Code] Search API not available, falling back to file scanning...",
    );
  }

  // Fallback: Traditional file scanning
  // WHY RECURSIVE SCANNING: Even with Search API, we need recursive tree access because:
  // - Search API may miss AI-specific config files (model names in YAML/JSON)
  // - Some detectors need to scan specific file types (e.g., modelsIdentifierDetector scans config files)
  // - Documentation detection needs to check entire tree for README.md, SECURITY.md, etc.
  // - The tree is fetched once (recursive=1) and reused, so it's efficient
  const CODE_EXTENSIONS = [".py", ".js", ".ts", ".jsx", ".tsx", ".ipynb"];
  const codeFiles = tree
    .filter((entry) => {
      const ext = entry.path.match(/\.[^.]+$/)?.[0] || "";
      return (
        CODE_EXTENSIONS.includes(ext) && (!entry.size || entry.size < 500000)
      );
    })
    .slice(0, 200);

  console.log(
    `[Detector: Code] Found ${codeFiles.length} code files to scan (limited to 200, <500KB each)`,
  );

  const sdkFindings = new Map();
  const apiFindings = new Map();
  let filesScanned = 0;

  for (const file of codeFiles) {
    filesScanned++;
    if (filesScanned % 20 === 0) {
      console.log(
        `[Detector: Code] Progress: ${filesScanned}/${codeFiles.length} files scanned...`,
      );
    }

    let content = await getFileContent(file.path);
    if (!content) continue;

    const ext = file.path.match(/\.[^.]+$/)?.[0] || "";

    // Notebooks are JSON; convert to plain source before pattern matching
    if (ext === ".ipynb") {
      content = stripNotebookCells(content);
      if (!content) continue;
    }

    const language = ext === ".py" || ext === ".ipynb" ? "python" : "javascript";
    const patterns = SDK_PATTERNS[language] || [];

    for (const { pattern, provider, weight } of patterns) {
      if (pattern.test(content)) {
        const key = `${provider}-${language}`;
        if (!sdkFindings.has(key)) {
          sdkFindings.set(key, { provider, weight, files: [] });
        }
        const allLines = content.split("\n");
        allLines.forEach((line, idx) => {
          if (pattern.test(line)) {
            sdkFindings.get(key).files.push({
              file: file.path,
              line: idx + 1,
              snippet: line.trim(),
            });
          }
        });
      }
    }

    for (const { pattern, provider, weight } of API_ENDPOINTS) {
      if (pattern.test(content)) {
        const key = `api-${provider}`;
        if (!apiFindings.has(key)) {
          apiFindings.set(key, { provider, weight, files: [] });
        }
        const allLines = content.split("\n");
        allLines.forEach((line, idx) => {
          if (pattern.test(line)) {
            apiFindings.get(key).files.push({
              file: file.path,
              line: idx + 1,
              snippet: line.trim(),
            });
          }
        });
      }
    }
  }

  console.log(`[Detector: Code] Scanned ${filesScanned} files`);
  console.log(
    `[Detector: Code] Found ${sdkFindings.size} SDK patterns, ${apiFindings.size} API endpoint patterns`,
  );

  for (const [key, data] of sdkFindings) {
    console.log(
      `[Detector: Code] ✓ ${data.provider} SDK detected in ${data.files.length} files`,
    );
    findings.push({
      id: `code-sdk-${key}`,
      title: `${data.provider} SDK Usage Detected`,
      category: "code",
      severity: "high",
      weight: data.weight,
      description: `Found ${data.provider} SDK usage in ${data.files.length} file(s)`,
      evidence: data.files
        .slice(0, 5)
        .map((f) => ({ file: f.file, snippet: f.snippet.substring(0, 200) })),
    });
  }

  for (const [key, data] of apiFindings) {
    console.log(
      `[Detector: Code] ✓ ${data.provider} API endpoints detected in ${data.files.length} files`,
    );
    findings.push({
      id: `code-api-${key}`,
      title: `${data.provider} API Endpoint Detected`,
      category: "code",
      severity: "medium",
      weight: data.weight,
      description: `Found API calls to ${data.provider} in ${data.files.length} file(s)`,
      evidence: data.files
        .slice(0, 5)
        .map((f) => ({ file: f.file, snippet: f.snippet.substring(0, 200) })),
    });
  }

  console.log(`[Detector: Code] Complete. Findings: ${findings.length}`);
  return { findings, paused: false, aiFilesFound };
}

async function searchCodeViaAPI(
  owner,
  repo,
  token,
  resumeState = null,
  languages = [],
  sbomAvailable = false,
  detectedDependencies = [],
  getFileContent = null,
) {
  const findings = resumeState?.findings || [];
  const sdkFindings = resumeState?.sdkFindings || new Map();

  // Build file extension filter based on detected languages
  let codeExtensions = "";

  if (languages.length > 0) {
    const extensionMap = {
      JavaScript: ["js", "jsx", "mjs", "cjs"],
      TypeScript: ["ts", "tsx"],
      Python: ["py", "pyw"],
      Java: ["java"],
      Go: ["go"],
      Rust: ["rs"],
      Ruby: ["rb"],
      PHP: ["php"],
      C: ["c", "h"],
      "C++": ["cpp", "cc", "cxx", "hpp", "hxx"],
      "C#": ["cs"],
      Kotlin: ["kt", "kts"],
      Scala: ["scala"],
      Swift: ["swift"],
    };

    const extensions = new Set();
    languages.forEach((lang) => {
      const exts = extensionMap[lang];
      if (exts) {
        exts.forEach((ext) => extensions.add(`extension:${ext}`));
      }
    });

    if (extensions.size > 0) {
      codeExtensions = Array.from(extensions).join(" ");
      console.log(
        `[Code Search] Using language-specific extensions: ${codeExtensions}`,
      );
    }
  }

  // Default to common extensions if no languages detected
  if (!codeExtensions) {
    codeExtensions =
      "extension:py extension:js extension:ts extension:jsx extension:tsx extension:java extension:go";
    console.log(`[Code Search] Using default extensions: ${codeExtensions}`);
  }

  // Build smart search queries based on SBOM data
  let searches = [];

  if (sbomAvailable && detectedDependencies.length > 0) {
    // SMART MODE: Build targeted searches based on detected dependencies
    console.log(
      `[Code Search] 🎯 SMART MODE: Building targeted searches from ${detectedDependencies.length} SBOM dependencies`,
    );

    // Map dependencies to search patterns
    const depNames = detectedDependencies.map((d) => d.name.toLowerCase());

    // Build provider-specific searches based on what's actually installed
    const providerSearches = {
      OpenAI: [],
      Anthropic: [],
      LangChain: [],
      Google: [],
      Cohere: [],
      Mistral: [],
      HuggingFace: [],
    };

    // Check which providers are installed
    if (
      depNames.some((n) => n.includes("openai") && !n.includes("langchain"))
    ) {
      providerSearches["OpenAI"].push(
        { query: `from openai import ${codeExtensions}`, provider: "OpenAI" },
        {
          query: `openai.chat.completions ${codeExtensions}`,
          provider: "OpenAI",
        },
        { query: `api.openai.com ${codeExtensions}`, provider: "OpenAI" },
      );
    }

    if (depNames.some((n) => n.includes("anthropic"))) {
      providerSearches["Anthropic"].push(
        {
          query: `from anthropic import ${codeExtensions}`,
          provider: "Anthropic",
        },
        { query: `@anthropic-ai/sdk ${codeExtensions}`, provider: "Anthropic" },
        { query: `api.anthropic.com ${codeExtensions}`, provider: "Anthropic" },
      );
    }

    if (depNames.some((n) => n.includes("langchain"))) {
      // Generic LangChain import
      providerSearches["LangChain"].push({
        query: `from langchain ${codeExtensions}`,
        provider: "LangChain",
      });

      // Only search for ChatOpenAI if langchain-openai is installed
      if (
        depNames.some(
          (n) =>
            n.includes("langchain-openai") || n.includes("langchain_openai"),
        )
      ) {
        providerSearches["LangChain"].push({
          query: `ChatOpenAI ${codeExtensions}`,
          provider: "LangChain-OpenAI",
        });
      }

      // Only search for ChatGoogle if langchain-google is installed
      if (
        depNames.some(
          (n) =>
            n.includes("langchain-google") || n.includes("langchain_google"),
        )
      ) {
        providerSearches["LangChain"].push({
          query: `ChatGoogleGenerativeAI ${codeExtensions}`,
          provider: "LangChain-Google",
        });
      }

      // Only search for ChatAnthropic if langchain-anthropic is installed
      if (
        depNames.some(
          (n) =>
            n.includes("langchain-anthropic") ||
            n.includes("langchain_anthropic"),
        )
      ) {
        providerSearches["LangChain"].push({
          query: `ChatAnthropic ${codeExtensions}`,
          provider: "LangChain-Anthropic",
        });
      }
    }

    if (
      depNames.some(
        (n) =>
          n.includes("google") ||
          n.includes("generativeai") ||
          n.includes("gemini"),
      )
    ) {
      providerSearches["Google"].push(
        { query: `google.generativeai ${codeExtensions}`, provider: "Google" },
        { query: `gemini ${codeExtensions}`, provider: "Google" },
      );
    }

    if (depNames.some((n) => n.includes("cohere"))) {
      providerSearches["Cohere"].push({
        query: `from cohere import ${codeExtensions}`,
        provider: "Cohere",
      });
    }

    if (depNames.some((n) => n.includes("mistral"))) {
      providerSearches["Mistral"].push({
        query: `from mistralai import ${codeExtensions}`,
        provider: "Mistral",
      });
    }

    // New provider/framework searches (2026-11 gap analysis)
    if (depNames.some((n) => n.includes("ollama"))) {
      providerSearches["Ollama"] = [
        { query: `from ollama ${codeExtensions}`, provider: "Ollama" },
        { query: `ollama.chat ${codeExtensions}`, provider: "Ollama" },
      ];
    }

    if (depNames.some((n) => n.includes("boto3") || n.includes("bedrock"))) {
      providerSearches["Bedrock"] = [
        { query: `bedrock-runtime ${codeExtensions}`, provider: "AWS Bedrock" },
        { query: `invoke_model ${codeExtensions}`, provider: "AWS Bedrock" },
      ];
    }

    if (
      depNames.some(
        (n) =>
          n.includes("langgraph") ||
          n.includes("crewai") ||
          n.includes("autogen") ||
          n.includes("google-adk") ||
          n.includes("openai-agents") ||
          n.includes("pydantic-ai") ||
          n.includes("strands"),
      )
    ) {
      providerSearches["Agents"] = [
        { query: `create_react_agent ${codeExtensions}`, provider: "LangGraph" },
        { query: `StateGraph ${codeExtensions}`, provider: "LangGraph" },
        { query: `from crewai import ${codeExtensions}`, provider: "CrewAI" },
      ];
    }

    if (
      depNames.some(
        (n) =>
          n.includes("transformers") ||
          n.includes("diffusers") ||
          n.includes("huggingface"),
      )
    ) {
      providerSearches["HuggingFace"].push(
        {
          query: `from transformers import ${codeExtensions}`,
          provider: "HuggingFace",
        },
        { query: `AutoModel ${codeExtensions}`, provider: "HuggingFace" },
      );
    }

    // Flatten all provider searches into single array
    for (const [provider, queries] of Object.entries(providerSearches)) {
      if (queries.length > 0) {
        console.log(
          `[Code Search] 🎯 Adding ${queries.length} targeted searches for ${provider} (detected in SBOM)`,
        );
        searches.push(...queries);
      }
    }

    // Add generic API endpoint search
    searches.push({
      query: `/v1/chat/completions ${codeExtensions}`,
      provider: "OpenAI-compatible",
    });

    // Limit to 10 searches due to API constraints
    if (searches.length > 10) {
      console.log(
        `[Code Search] ⚠️  Generated ${searches.length} searches, limiting to 10 most relevant`,
      );
      searches = searches.slice(0, 10);
    }

    console.log(
      `[Code Search] 🎯 SMART MODE: ${searches.length} targeted searches (only searching for installed dependencies)`,
    );
  } else {
    // FALLBACK MODE: Use broad pattern matching (original behavior)
    console.log(
      `[Code Search] 📡 FALLBACK MODE: SBOM not available, using broad pattern matching`,
    );

    // Search queries for different LLM SDKs (MAX 10 due to Code Search API rate limit)
    searches = [
      { query: `from openai import ${codeExtensions}`, provider: "OpenAI" },
      {
        query: `openai.chat.completions ${codeExtensions}`,
        provider: "OpenAI",
      },
      {
        query: `from anthropic import ${codeExtensions}`,
        provider: "Anthropic",
      },
      { query: `@anthropic-ai/sdk ${codeExtensions}`, provider: "Anthropic" },
      { query: `from langchain ${codeExtensions}`, provider: "LangChain" },
      { query: `ChatOpenAI ${codeExtensions}`, provider: "OpenAI" },
      { query: `google.generativeai ${codeExtensions}`, provider: "Google" },
      { query: `api.openai.com ${codeExtensions}`, provider: "OpenAI" },
      { query: `api.anthropic.com ${codeExtensions}`, provider: "Anthropic" },
      {
        query: `/v1/chat/completions ${codeExtensions}`,
        provider: "OpenAI-compatible",
      },
    ];
  }

  const startIdx = resumeState?.lastSearchIndex || 0;
  console.log(
    `[Code Search] Starting from search ${startIdx}/${searches.length} (API limit: 10 req/min)`,
  );

  let lastRateLimit = resumeState?.lastRateLimit || {
    remaining: 10,
    limit: 10,
  };
  let hitRateLimit = false;
  let lastSearchIndex = startIdx;

  for (let i = startIdx; i < searches.length; i++) {
    const { query, provider } = searches[i];
    lastSearchIndex = i;

    console.log(
      `[Code Search] [${i + 1}/${searches.length}] Searching for: "${query}"`,
    );

    const result = await searchCodeInRepo(owner, repo, query, token);

    if (!result) {
      // Check if it was a rate limit issue
      if (result === false) {
        // Rate limit hit
        console.warn(
          `[Code Search] ⚠️  Rate limit exhausted at search ${i + 1}`,
        );
        console.log(
          `[Code Search] 🔄 Will resume after other detectors complete...`,
        );
        hitRateLimit = true;

        // Return partial results and resume state
        return {
          findings: convertSearchToFindings(sdkFindings),
          paused: true,
          resumeState: {
            sdkFindings,
            lastSearchIndex: i,
            lastRateLimit,
            findings,
          },
        };
      }
      console.log(`[Code Search] No results or error for: "${query}"`);
      continue;
    }

    // Update rate limit tracking
    if (result.rateLimit) {
      lastRateLimit = result.rateLimit;
      console.log(
        `[Code Search] Rate limit: ${lastRateLimit.remaining}/${lastRateLimit.limit} remaining`,
      );

      // If we hit 0, pause and defer remaining searches
      if (lastRateLimit.remaining === 0) {
        console.warn(`[Code Search] ⚠️  Rate limit exhausted (0 remaining)`);
        console.log(
          `[Code Search] 🔄 Deferring remaining ${searches.length - i - 1} searches...`,
        );
        hitRateLimit = true;

        // Return partial results
        return {
          findings: convertSearchToFindings(sdkFindings),
          paused: true,
          resumeState: {
            sdkFindings,
            lastSearchIndex: i + 1,
            lastRateLimit,
            findings,
          },
        };
      }

      // Warn if running low
      if (lastRateLimit.remaining <= 2) {
        console.warn(
          `[Code Search] ⚠️  Running low (${lastRateLimit.remaining} remaining)`,
        );
      }
    }

    const key = `${provider}-search`;
    if (!sdkFindings.has(key)) {
      sdkFindings.set(key, { provider, files: new Set() });
    }

    // Process items and fetch line numbers if we have snippets but no line numbers
    for (const item of result.items) {
      let lineNumber = item.line_number;
      let snippet = item.snippet;

      // Always validate that the line contains the provider name to avoid false positives
      let isValid = false;

      // If we need to fetch the file to validate (no line number or we want to verify)
      if (
        (snippet && !lineNumber && item.path && getFileContent) ||
        (lineNumber && item.path && getFileContent)
      ) {
        try {
          const fileContent = await getFileContent(item.path);
          if (fileContent) {
            const lines = fileContent.split("\n");
            const providerLower = provider.toLowerCase();

            // If we have a line number from the API, verify it
            if (lineNumber && lineNumber > 0 && lineNumber <= lines.length) {
              const line = lines[lineNumber - 1].trim();
              // Validate this line actually contains the provider name
              if (
                (providerLower === "langchain" &&
                  line.toLowerCase().includes("langchain")) ||
                (providerLower === "openai" &&
                  line.toLowerCase().includes("openai")) ||
                (providerLower === "anthropic" &&
                  line.toLowerCase().includes("anthropic")) ||
                (providerLower === "google" &&
                  line.toLowerCase().includes("google")) ||
                (providerLower === "cohere" &&
                  line.toLowerCase().includes("cohere")) ||
                (providerLower === "mistral" &&
                  line.toLowerCase().includes("mistral")) ||
                (providerLower === "huggingface" &&
                  line.toLowerCase().includes("huggingface")) ||
                providerLower === "openai-compatible" || // Compatible endpoints are always valid
                (providerLower === "langchain-openai" &&
                  line.toLowerCase().includes("langchain") &&
                  line.toLowerCase().includes("openai")) ||
                (providerLower === "langchain-google" &&
                  line.toLowerCase().includes("langchain") &&
                  line.toLowerCase().includes("google")) ||
                (providerLower === "langchain-anthropic" &&
                  line.toLowerCase().includes("langchain") &&
                  line.toLowerCase().includes("anthropic"))
              ) {
                isValid = true;
                snippet = line;
              } else {
                console.warn(
                  `[Code Search] Line ${lineNumber} in ${item.path} does not contain "${provider}": "${line.substring(0, 100)}"`,
                );
              }
            }
            // If we don't have a line number, search for the snippet
            else if (snippet) {
              // Extract first few words from snippet for exact matching
              const searchWords = snippet.split(/\s+/).slice(0, 3).join(" ");
              // Search for exact match in the file
              for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const trimmedLine = line.trim();
                // Use exact matching on start of line instead of fuzzy substring
                if (trimmedLine.startsWith(searchWords)) {
                  // Validate this line actually contains the provider name
                  if (
                    (providerLower === "langchain" &&
                      line.toLowerCase().includes("langchain")) ||
                    (providerLower === "openai" &&
                      line.toLowerCase().includes("openai")) ||
                    (providerLower === "anthropic" &&
                      line.toLowerCase().includes("anthropic")) ||
                    (providerLower === "google" &&
                      line.toLowerCase().includes("google")) ||
                    (providerLower === "cohere" &&
                      line.toLowerCase().includes("cohere")) ||
                    (providerLower === "mistral" &&
                      line.toLowerCase().includes("mistral")) ||
                    (providerLower === "huggingface" &&
                      line.toLowerCase().includes("huggingface")) ||
                    providerLower === "openai-compatible" ||
                    (providerLower === "langchain-openai" &&
                      line.toLowerCase().includes("langchain") &&
                      line.toLowerCase().includes("openai")) ||
                    (providerLower === "langchain-google" &&
                      line.toLowerCase().includes("langchain") &&
                      line.toLowerCase().includes("google")) ||
                    (providerLower === "langchain-anthropic" &&
                      line.toLowerCase().includes("langchain") &&
                      line.toLowerCase().includes("anthropic"))
                  ) {
                    lineNumber = i + 1; // Line numbers are 1-indexed
                    // Update snippet to be the actual line
                    snippet = trimmedLine;
                    isValid = true;
                    break;
                  }
                }
              }
            }
          }
        } catch (error) {
          console.warn(
            `[Code Search] Could not fetch ${item.path} for validation:`,
            error.message,
          );
        }
      }

      // Skip this item if it failed validation
      if (!isValid) {
        console.log(
          `[Code Search] Skipping invalid result for ${provider} in ${item.path}`,
        );
        continue;
      }

      // Build GitHub URL with line anchor
      // GitHub Search API returns html_url with commit SHA (e.g., .../blob/abc123/path)
      let url = item.html_url || null;
      if (url && lineNumber) {
        // Remove existing line anchor if present, add new one
        url = url.replace(/#L\d+$/, "") + `#L${lineNumber}`;
      } else if (!url && lineNumber) {
        // Build URL if we don't have one (fallback - use main branch)
        url = `https://github.com/${owner}/${repo}/blob/main/${item.path}#L${lineNumber}`;
      } else if (url && !lineNumber) {
        // Keep original URL even without line number (it has commit SHA which is better than branch)
      }

      // Store file path with line number and snippet
      const fileInfo = {
        path: item.path,
        line: lineNumber,
        url: url,
        snippet: snippet,
      };
      sdkFindings.get(key).files.add(JSON.stringify(fileInfo));
    }

    console.log(
      `[Code Search] Found ${result.items.length} results for ${provider}`,
    );
  }

  console.log(`[Code Search] ✓ Completed all ${searches.length} searches`);
  console.log(
    `[Code Search] Final rate limit: ${lastRateLimit.remaining}/${lastRateLimit.limit} remaining`,
  );

  return {
    findings: convertSearchToFindings(sdkFindings),
    paused: false,
  };
}

function convertSearchToFindings(sdkFindings) {
  const findings = [];
  for (const [key, data] of sdkFindings) {
    // Skip findings with zero files found
    if (data.files.size === 0) {
      console.log(
        `[Code Search] Skipping ${data.provider} SDK - no files found`,
      );
      continue;
    }

    // Parse file info (stored as JSON strings)
    const fileInfos = Array.from(data.files)
      .slice(0, 5)
      .map((fileStr) => {
        try {
          return JSON.parse(fileStr);
        } catch {
          // Fallback for old format (just path string)
          return { path: fileStr, line: null, url: null };
        }
      });

    findings.push({
      id: `code-sdk-search-${key}`,
      title: `${data.provider} SDK Usage Detected (via Search API)`,
      category: "code",
      severity: "high",
      weight: 5,
      description: `Found ${data.provider} SDK usage in ${data.files.size} file(s) using GitHub Search API`,
      evidence: fileInfos.map((fileInfo) => ({
        file: fileInfo.path,
        line: fileInfo.line,
        url: fileInfo.url,
        snippet: fileInfo.snippet || null, // Don't add fallback text - let UI handle it
      })),
      filesFound: data.files.size, // Track for filtering
    });
  }
  return findings;
}

async function configDetector({ tree, getFileContent, owner, repo }) {
  console.log("[Detector: Config] Starting configuration analysis...");
  const findings = [];

  // Expand config file detection
  const CONFIG_FILES = [
    ".env",
    ".env.example",
    ".env.sample",
    ".env.local",
    "config.yml",
    "config.yaml",
    "docker-compose.yml",
    "settings.json",
    "settings.yaml",
    "app.config",
    // AI framework config conventions (cisco aibom scans these too)
    "langgraph.json",
    "crewai.yaml",
    "crewai.yml",
    "dspy.toml",
    ".aibom.yaml",
    "aibom.yaml",
  ];

  const configFiles = tree.filter((entry) => {
    const fileName = entry.path.split("/").pop();
    const path = entry.path.toLowerCase();
    return (
      CONFIG_FILES.includes(fileName) ||
      path.match(/config\/.*\.(yml|yaml|json|toml)$/) ||
      fileName === "config.py" ||
      fileName === "config.js" ||
      fileName === "constants.py" ||
      fileName === "constants.js"
    );
  });

  console.log(
    `[Detector: Config] Found ${configFiles.length} config files to scan for model references`,
  );

  // NOTE: We intentionally do NOT scan for API keys because:
  // 1. Good projects don't commit API keys (they use env vars at runtime)
  // 2. Code patterns and dependencies are better AI/LLM indicators
  // 3. We shouldn't log or expose secret references for security reasons

  const modelNameFindings = new Map();

  for (const file of configFiles) {
    console.log(`[Detector: Config] Scanning ${file.path}...`);
    const content = await getFileContent(file.path);
    if (!content) continue;

    // Skip binary or large files using enhanced detection
    if (shouldSkipContent(content, 100)) {
      console.log(
        `[Detector: Config] Skipping ${file.path} - binary or too large`,
      );
      continue;
    }

    const lines = content.split("\n");

    // Check for model names in config (NOT API keys)
    for (const { pattern, provider, model } of MODEL_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Skip comments and string literals
        if (isCommentOrStringLiteral(line)) {
          continue;
        }

        if (pattern.test(line)) {
          // Check for false positives
          const matchedText = line.match(pattern)?.[0] || "";
          if (isFalsePositivePattern(line, matchedText)) {
            console.log(
              `[Detector: Config] ⚠️  Skipping false positive in ${file.path}:${i + 1}`,
            );
            continue;
          }

          const key = `model-${provider}-${model}`;
          if (!modelNameFindings.has(key)) {
            modelNameFindings.set(key, { provider, model, files: [] });
          }

          // Build GitHub URL for evidence
          const githubUrl =
            owner && repo
              ? buildGitHubUrl(owner, repo, file.path, i + 1)
              : null;

          modelNameFindings.get(key).files.push({
            file: file.path,
            line: i + 1,
            url: githubUrl,
            snippet: lines[i].trim().substring(0, 100),
          });

          console.log(
            `[Detector: Config] 🎯 Found ${provider} model "${model}" in config: ${file.path}:${i + 1}`,
          );
          break; // One per file is enough for config
        }
      }
    }
  }

  // Create findings for model names (API key findings removed - see note above)
  for (const [key, data] of modelNameFindings) {
    console.log(
      `[Detector: Config] ✓ Found ${data.provider} model "${data.model}" in ${data.files.length} config files`,
    );

    // Use enhanced severity determination
    const severity = determineSeverity("config", 4);

    findings.push({
      id: `config-${key}`,
      title: `${data.provider} Model in Configuration: ${data.model}`,
      category: "config",
      severity: severity,
      weight: 4,
      description: `Found ${data.provider} model "${data.model}" configured in ${data.files.length} file(s)`,
      evidence: data.files.slice(0, 5), // Already has line, url, snippet
      modelInfo: {
        provider: data.provider,
        modelName: data.model,
        locations: data.files, // Already has file, line, url, snippet
        files: data.files.map((f) => f.file), // For backward compatibility
      },
    });
  }

  console.log(`[Detector: Config] Complete. Findings: ${findings.length}`);
  return findings;
}

async function ciDetector({ tree, getFileContent }) {
  console.log("[Detector: CI/CD] Starting CI/CD analysis...");
  const findings = [];
  const ciFiles = tree.filter((entry) =>
    entry.path.includes(".github/workflows"),
  );

  console.log(`[Detector: CI/CD] Found ${ciFiles.length} workflow files`);

  for (const file of ciFiles) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    for (const { pattern, description } of CI_PATTERNS) {
      if (pattern.test(content)) {
        console.log(`[Detector: CI/CD] ✓ Found ${description} in ${file.path}`);
        findings.push({
          id: `ci-action-${file.path.replace(/\//g, "-")}`,
          title: `AI Tool in CI/CD: ${description}`,
          category: "ci",
          severity: "medium",
          weight: 4,
          description: `Found ${description} in CI/CD pipeline`,
          evidence: [
            { file: file.path, snippet: "AI tool detected in workflow" },
          ],
        });
      }
    }
  }

  console.log(`[Detector: CI/CD] Complete. Findings: ${findings.length}`);
  return findings;
}

async function modelsDetector({ tree, getFileContent }) {
  console.log("[Detector: Models] Starting model file detection...");
  const findings = [];
  const modelFiles = new Map();

  for (const entry of tree) {
    const fileName = entry.path.split("/").pop();
    const ext = fileName.match(/\.[^.]+$/)?.[0] || "";

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
        modelFiles
          .get(key)
          .files.push({ file: entry.path, size: entry.size || 0 });
      }
    }
  }

  // R1: parse Git-LFS pointer files for artifact hashes. Large model files
  // are stored as LFS pointers — ~130-byte plain-text files carrying
  // `oid sha256:<hex>` — so fetching entries ≤512 bytes resolves the
  // artifact hash without downloading weights.
  const artifacts = [];
  const lfsCandidates = [];
  // Weight-artifact extensions — tokenizer/config JSONs may match model-file
  // name patterns but are not weight artifacts worth hashing
  const WEIGHT_EXT = /\.(safetensors|bin|pt|pth|ckpt|gguf|ggml|onnx|h5|pb|tflite|msgpack|pkl|pickle)$/i;
  for (const [, data] of modelFiles) {
    for (const f of data.files) {
      if (!WEIGHT_EXT.test(f.file)) continue;
      // entry.size known and pointer-sized → candidate; unknown size (0) →
      // also worth one cheap fetch, guarded by content check below
      if (f.size === 0 || (f.size > 0 && f.size <= 512)) {
        lfsCandidates.push(f);
      }
    }
  }
  if (lfsCandidates.length > 0) {
    console.log(
      `[Detector: Models] Checking ${lfsCandidates.length} model file(s) for Git-LFS pointers...`,
    );
    for (const f of lfsCandidates.slice(0, 50)) {
      try {
        const content = await getFileContent(f.file);
        if (!content || !content.includes("https://git-lfs.github.com/spec/v1")) {
          continue;
        }
        const oidMatch = content.match(/oid\s+sha256:\s*([0-9a-f]{64})/i);
        if (!oidMatch) continue;
        const sizeMatch = content.match(/^size\s+(\d+)\s*$/m);
        artifacts.push({
          path: f.file,
          sha256: oidMatch[1].toLowerCase(),
          sizeBytes: sizeMatch ? parseInt(sizeMatch[1], 10) : f.size,
          source: "git-lfs-pointer",
        });
        console.log(
          `[Detector: Models] ✓ LFS artifact: ${f.file} sha256:${oidMatch[1].slice(0, 12)}…`,
        );
      } catch (err) {
        console.log(
          `[Detector: Models] Could not read ${f.file} for LFS parsing: ${err.message}`,
        );
      }
    }
  }

  for (const [key, data] of modelFiles) {
    console.log(
      `[Detector: Models] ✓ Found ${data.files.length} ${data.description} files`,
    );
    findings.push({
      id: `models-${key.replace(/[^a-zA-Z0-9]/g, "-")}`,
      title: `Local Model Files: ${data.description}`,
      category: "models",
      severity: "high",
      weight: Math.min(data.files.length + 4, 8),
      description: `Found ${data.files.length} ${data.description} file(s)`,
      evidence: data.files
        .slice(0, 10)
        .map((f) => ({ file: f.file, snippet: `File size: ${f.size} bytes` })),
    });
  }

  // One machine-readable finding per hashed artifact (R1) — bom-generators
  // matches these to model components by name tokens and emits CycloneDX
  // hashes / SPDX checksums.
  for (const artifact of artifacts) {
    const fileName = artifact.path.split("/").pop();
    findings.push({
      id: `artifact-${artifact.sha256.slice(0, 12)}`,
      title: `Model Artifact: ${fileName} (sha256 verified)`,
      category: "models",
      severity: "low",
      weight: 3,
      description: `Model artifact with verified integrity: ${artifact.path} (sha256 ${artifact.sha256})`,
      evidence: [
        {
          file: artifact.path,
          snippet: `Git-LFS pointer — oid sha256:${artifact.sha256}, ${artifact.sizeBytes} bytes`,
        },
      ],
      artifactInfo: {
        path: artifact.path,
        sha256: artifact.sha256,
        sizeBytes: artifact.sizeBytes,
        source: "git-lfs-pointer",
      },
    });
  }

  console.log(
    `[Detector: Models] Complete. Findings: ${findings.length} (${artifacts.length} hashed artifacts)`,
  );
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
  if (!name || typeof name !== "string") return false;

  // Filter out common false positives for short model names
  // "yi" model name can appear in "yield" (Python keyword)
  const falsePositives = [
    "yield",
    "lying",
    "dying",
    "tying",
    "flying",
    "trying",
  ];
  if (falsePositives.includes(name.toLowerCase())) {
    return false;
  }

  // For non-HuggingFace providers, assume pattern matching is accurate enough
  if (provider !== "HuggingFace") return true;

  const lowerName = name.toLowerCase();

  // Filter out MIME types
  const mimeTypePrefixes = [
    "application/",
    "image/",
    "text/",
    "font/",
    "audio/",
    "video/",
    "multipart/",
  ];
  if (mimeTypePrefixes.some((prefix) => lowerName.startsWith(prefix))) {
    return false;
  }

  // Filter out framework/library imports
  const frameworkPatterns = [
    /^next\//, // Next.js
    /^react\//, // React
    /^vue\//, // Vue
    /^angular\//, // Angular
    /^@angular\//, // Angular scoped
    /^lodash\//, // Lodash utilities
    /^jquery\//, // jQuery
    /^bootstrap\//, // Bootstrap
    /^tailwind\//, // Tailwind
  ];

  if (frameworkPatterns.some((pattern) => pattern.test(lowerName))) {
    return false;
  }

  // Filter out CSS classes and styling (e.g., text-white/80)
  if (
    /^(text|bg|border|shadow|rounded|flex|grid|gap|p|m|w|h)-/.test(lowerName)
  ) {
    return false;
  }

  // Filter out invalid/placeholder names
  const invalidNames = [
    "n/a",
    "none",
    "null",
    "undefined",
    "todo",
    "fixme",
    "tbd",
  ];
  if (invalidNames.includes(lowerName)) {
    return false;
  }

  // Filter out file paths (should have reasonable org and model names)
  const parts = name.split("/");
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
  if (
    name.includes("://") ||
    name.includes("www.") ||
    name.includes(".com") ||
    name.includes(".org")
  ) {
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
    const desc = finding.description?.toLowerCase() || "";
    const title = finding.title?.toLowerCase() || "";
    const text = desc + " " + title;

    // Check for explicit SDK/library usage
    if (text.includes("openai") && !text.includes("langchain")) {
      providers.add("OpenAI");
    }
    if (text.includes("anthropic")) {
      providers.add("Anthropic");
    }
    if (
      text.includes("google") ||
      text.includes("gemini") ||
      text.includes("generativeai")
    ) {
      providers.add("Google");
    }
    if (
      text.includes("huggingface") ||
      text.includes("transformers") ||
      text.includes("diffusers")
    ) {
      providers.add("HuggingFace");
    }
    if (text.includes("cohere")) {
      providers.add("Cohere");
    }
    if (text.includes("mistral")) {
      providers.add("Mistral");
    }
    // Extended providers (2026-11 gap analysis)
    if (text.includes("ollama")) {
      providers.add("Ollama");
    }
    if (text.includes("groq")) {
      providers.add("Groq");
    }
    // Word-bounded: "supernova"/"titanium" must not attribute AWS Bedrock
    if (/\bnova\b|\btitan\b|\bbedrock\b/.test(text)) {
      providers.add("AWS Bedrock");
    }
    if (text.includes("vertex") || text.includes("aiplatform")) {
      providers.add("Google");
    }

    // Check dependency names
    if (finding.dependencyInfo) {
      const depName = finding.dependencyInfo.name.toLowerCase();
      if (depName.includes("openai")) providers.add("OpenAI");
      if (depName.includes("anthropic")) providers.add("Anthropic");
      if (depName.includes("google") || depName.includes("generativeai"))
        providers.add("Google");
      if (
        depName.includes("transformers") ||
        depName.includes("diffusers") ||
        depName.includes("huggingface")
      ) {
        providers.add("HuggingFace");
      }
      if (depName.includes("cohere")) providers.add("Cohere");
      if (depName.includes("mistral")) providers.add("Mistral");
      if (depName.includes("ollama")) providers.add("Ollama");
      if (depName.includes("groq")) providers.add("Groq");
      if (depName.includes("bedrock") || depName.includes("boto3"))
        providers.add("AWS Bedrock");
      if (depName.includes("vertexai") || depName.includes("aiplatform"))
        providers.add("Google");
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
    JavaScript: [".js", ".jsx", ".mjs", ".cjs"],
    TypeScript: [".ts", ".tsx"],
    Python: [".py", ".pyw"],
    "Jupyter Notebook": [".ipynb"],
    Java: [".java"],
    Go: [".go"],
    Rust: [".rs"],
    Ruby: [".rb"],
    PHP: [".php"],
    C: [".c", ".h"],
    "C++": [".cpp", ".cc", ".cxx", ".hpp", ".hxx"],
    "C#": [".cs"],
    Kotlin: [".kt", ".kts"],
    Scala: [".scala"],
    Swift: [".swift"],
    "Objective-C": [".m", ".mm", ".h"],
    Shell: [".sh", ".bash"],
    R: [".r", ".R"],
  };

  const extensions = new Set();

  // Add extensions for detected languages
  languages.forEach((lang) => {
    const exts = extensionMap[lang];
    if (exts) {
      exts.forEach((ext) => extensions.add(ext));
    }
  });

  // If no languages detected or recognized, use common defaults
  if (extensions.size === 0) {
    console.log(
      "[Detector: AI Models] No recognized languages, using default extensions",
    );
    return [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"];
  }

  const extArray = Array.from(extensions);
  console.log(
    `[Detector: AI Models] Scanning extensions based on detected languages: ${extArray.join(", ")}`,
  );
  return extArray;
}

async function modelsIdentifierDetector({
  tree,
  getFileContent,
  owner,
  repo,
  token,
  aiFilesFound,
  repoMeta,
  allFindings,
}) {
  console.log("[Detector: AI Models] Starting AI model identification...");
  const findings = [];
  const modelsFound = new Map();

  // WHY RECURSIVE TREE SCANNING FOR MODELS:
  // Model names are often in config files (YAML, JSON, TOML, .env) that may not be detected by code search
  // We prioritize files where AI usage was already detected, then scan config files, then code files
  // This targeted approach minimizes unnecessary scanning while ensuring we catch model references

  // Get file extensions to scan based on repository languages
  const languages = repoMeta?.languages || [];
  const codeExtensions = getCodeExtensionsForLanguages(languages);
  console.log(
    `[Detector: AI Models] Repository languages: ${languages.join(", ")}`,
  );

  // Detect which AI providers are actually used based on code/dependencies findings
  const providersUsed = detectProvidersInUse(allFindings || []);
  console.log(
    `[Detector: AI Models] Detected providers in use: ${Array.from(providersUsed).join(", ") || "None detected, will infer from patterns"}`,
  );

  const hasHuggingFaceModels =
    Object.values(modelsFound).some(
      (d) => d.isHuggingFace || d.provider === "HuggingFace",
    ) || providersUsed.has("HuggingFace");
  const shouldCheckHuggingFace =
    providersUsed.size === 0 || hasHuggingFaceModels;
  console.log(
    `[Detector: AI Models] Will query HuggingFace API: ${shouldCheckHuggingFace}`,
  );

  // Patterns to identify specific model usage
  const modelPatterns = [
    // OpenAI models - LLM
    {
      pattern: /["']?(gpt-4o-mini)["']?/gi,
      provider: "OpenAI",
      model: "gpt-4o-mini",
      type: "text-generation",
    },
    {
      pattern: /["']?(gpt-4o)["']?/gi,
      provider: "OpenAI",
      model: "gpt-4o",
      type: "text-generation",
    },
    {
      pattern: /["']?(gpt-4-turbo)["']?/gi,
      provider: "OpenAI",
      model: "gpt-4-turbo",
      type: "text-generation",
    },
    {
      pattern: /["']?(gpt-4)(?![-\w.])["']?/gi,
      provider: "OpenAI",
      model: "gpt-4",
      type: "text-generation",
    },
    {
      pattern: /["']?(gpt-3\.5-turbo)["']?/gi,
      provider: "OpenAI",
      model: "gpt-3.5-turbo",
      type: "text-generation",
    },
    {
      pattern: /["']?(o1-preview)["']?/gi,
      provider: "OpenAI",
      model: "o1-preview",
      type: "text-generation",
    },
    {
      pattern: /["']?(o1-mini)["']?/gi,
      provider: "OpenAI",
      model: "o1-mini",
      type: "text-generation",
    },
    {
      pattern: /["']?(o1-pro)["']?/gi,
      provider: "OpenAI",
      model: "o1-pro",
      type: "text-generation",
    },
    {
      pattern: /["']?(o3-mini)["']?/gi,
      provider: "OpenAI",
      model: "o3-mini",
      type: "text-generation",
    },
    {
      // Quoted-only to avoid matching identifiers named "o3" in code
      pattern: /["'](o3)["']/gi,
      provider: "OpenAI",
      model: "o3",
      type: "text-generation",
    },
    {
      pattern: /["']?(o4-mini)["']?/gi,
      provider: "OpenAI",
      model: "o4-mini",
      type: "text-generation",
    },
    {
      pattern: /["']?(gpt-4\.1-mini|gpt-4\.1-nano)["']?/gi,
      provider: "OpenAI",
      model: "gpt-4.1-mini",
      type: "text-generation",
    },
    {
      // Bare form guarded so it does not double-match inside "gpt-4.1-mini"
      pattern: /["']?(gpt-4\.1)(?![-\w.])["']?/gi,
      provider: "OpenAI",
      model: "gpt-4.1",
      type: "text-generation",
    },
    {
      pattern: /["']?(gpt-4\.5)(?![-\w.])["']?/gi,
      provider: "OpenAI",
      model: "gpt-4.5",
      type: "text-generation",
    },
    {
      pattern: /["']?(gpt-5)(?![-\w.])["']?/gi,
      provider: "OpenAI",
      model: "gpt-5",
      type: "text-generation",
    },

    // OpenAI models - Embeddings
    {
      pattern: /["']?(text-embedding-3-large)["']?/gi,
      provider: "OpenAI",
      model: "text-embedding-3-large",
      type: "embeddings",
    },
    {
      pattern: /["']?(text-embedding-3-small)["']?/gi,
      provider: "OpenAI",
      model: "text-embedding-3-small",
      type: "embeddings",
    },
    {
      pattern: /["']?(text-embedding-ada-002)["']?/gi,
      provider: "OpenAI",
      model: "text-embedding-ada-002",
      type: "embeddings",
    },

    // OpenAI models - Image Generation
    {
      pattern: /["']?(dall-e-3)["']?/gi,
      provider: "OpenAI",
      model: "dall-e-3",
      type: "text-to-image",
    },
    {
      pattern: /["']?(dall-e-2)["']?/gi,
      provider: "OpenAI",
      model: "dall-e-2",
      type: "text-to-image",
    },

    // Anthropic models - LLM
    {
      pattern: /["']?(claude-3-5-sonnet-\d+)["']?/gi,
      provider: "Anthropic",
      model: "claude-3.5-sonnet",
      type: "text-generation",
    },
    {
      // Bare alias (no date suffix): "claude-3-5-sonnet", "claude-3.5-sonnet"
      pattern: /["']?(claude-3\.5-sonnet|claude-3-5-sonnet)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-3.5-sonnet",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-3-opus-\d+)["']?/gi,
      provider: "Anthropic",
      model: "claude-3-opus",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-3-sonnet-\d+)["']?/gi,
      provider: "Anthropic",
      model: "claude-3-sonnet",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-3-haiku-\d+)["']?/gi,
      provider: "Anthropic",
      model: "claude-3-haiku",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-3-7-sonnet)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-3.7-sonnet",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-3-sonnet)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-3-sonnet",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-3-haiku)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-3-haiku",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-opus-4-5|claude-4-5-opus)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-opus-4.5",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-sonnet-4-5|claude-4-5-sonnet)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-sonnet-4.5",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-haiku-4-5|claude-4-5-haiku)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-haiku-4.5",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-opus-4|claude-4-opus)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-opus-4",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-sonnet-4|claude-4-sonnet)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-sonnet-4",
      type: "text-generation",
    },
    {
      pattern: /["']?(claude-haiku-4|claude-4-haiku)(?![-\w])["']?/gi,
      provider: "Anthropic",
      model: "claude-haiku-4",
      type: "text-generation",
    },

    // Google AI models - LLM (Gemini)
    {
      pattern: /["']?(gemini-1\.5-pro-\d+)["']?/gi,
      provider: "Google",
      model: "gemini-1.5-pro",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemini-1\.5-flash-\d+)["']?/gi,
      provider: "Google",
      model: "gemini-1.5-flash",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemini-1\.5-pro)["']?/gi,
      provider: "Google",
      model: "gemini-1.5-pro",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemini-1\.5-flash)["']?/gi,
      provider: "Google",
      model: "gemini-1.5-flash",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemini-pro)["']?/gi,
      provider: "Google",
      model: "gemini-pro",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemini-2\.0-flash-exp)["']?/gi,
      provider: "Google",
      model: "gemini-2.0-flash-exp",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemini-2\.5-pro)["']?/gi,
      provider: "Google",
      model: "gemini-2.5-pro",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemini-2\.5-flash)["']?/gi,
      provider: "Google",
      model: "gemini-2.5-flash",
      type: "text-generation",
    },

    // Google AI models - Embeddings (models/embedding-001 format)
    {
      pattern: /["']?(models\/embedding-001)["']?/gi,
      provider: "Google",
      model: "models/embedding-001",
      type: "embeddings",
    },
    {
      pattern: /["']?(models\/text-embedding-004)["']?/gi,
      provider: "Google",
      model: "models/text-embedding-004",
      type: "embeddings",
    },
    {
      pattern: /["']?(text-embedding-004)["']?/gi,
      provider: "Google",
      model: "text-embedding-004",
      type: "embeddings",
    },

    // HuggingFace models (pattern: organization/model-name)
    // Only match if it's actually from HuggingFace context
    // Exclude known Google models that use org/model format
    {
      pattern: /["']([a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+)["']/gi,
      provider: "HuggingFace",
      model: "extract",
      type: "unknown",
    },

    // HuggingFace explicit URL patterns (hf.co/)
    {
      pattern:
        /["']?hf\.co\/([a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+)(?::[a-zA-Z0-9_-]+)?["']?/gi,
      provider: "HuggingFace",
      model: "extract",
      type: "unknown",
    },

    // Mistral models
    {
      pattern: /["']?(mistral-large)["']?/gi,
      provider: "Mistral",
      model: "mistral-large",
      type: "text-generation",
    },
    {
      pattern: /["']?(mixtral-8x7b)["']?/gi,
      provider: "Mistral",
      model: "mixtral-8x7b",
      type: "text-generation",
    },

    // Cohere models (order matters: more specific patterns first to prevent partial matches)
    {
      pattern: /["']?(command-r7b-arabic)["']?/gi,
      provider: "Cohere",
      model: "command-r7b-arabic",
      type: "text-generation",
    },
    {
      pattern: /["']?(command-r-plus)["']?/gi,
      provider: "Cohere",
      model: "command-r-plus",
      type: "text-generation",
    },
    // Match "command-r" only when not followed by more alphanumeric characters (to avoid matching inside "command-r7b-arabic")
    {
      pattern: /["']?(command-r)(?![a-z0-9-])["']?/gi,
      provider: "Cohere",
      model: "command-r",
      type: "text-generation",
    },
    {
      pattern: /["']?(command-a)["']?/gi,
      provider: "Cohere",
      model: "command-a",
      type: "text-generation",
    },

    // Ollama/Local models
    {
      pattern: /["']?(llama3\.3)["']?/gi,
      provider: "Meta",
      model: "llama3.3",
      type: "text-generation",
    },
    {
      pattern: /["']?(llama3\.2)["']?/gi,
      provider: "Meta",
      model: "llama3.2",
      type: "text-generation",
    },
    {
      pattern: /["']?(llama3\.1)["']?/gi,
      provider: "Meta",
      model: "llama3.1",
      type: "text-generation",
    },
    {
      pattern: /["']?(llama3)(?![-\w.])["']?/gi,
      provider: "Meta",
      model: "llama3",
      type: "text-generation",
    },
    {
      pattern: /["']?(codellama)["']?/gi,
      provider: "Meta",
      model: "codellama",
      type: "text-generation",
    },
    {
      pattern: /["']?(deepseek-coder-v2)["']?/gi,
      provider: "DeepSeek",
      model: "deepseek-coder-v2",
      type: "text-generation",
    },
    {
      pattern: /["']?(deepseek-r1)["']?/gi,
      provider: "DeepSeek",
      model: "deepseek-r1",
      type: "text-generation",
    },
    {
      pattern: /["']?(deepseek-v3)["']?/gi,
      provider: "DeepSeek",
      model: "deepseek-v3",
      type: "text-generation",
    },
    {
      pattern: /["']?(qwen2\.5)(?![-\w.])["']?/gi,
      provider: "Alibaba",
      model: "qwen2.5",
      type: "text-generation",
    },
    {
      pattern: /["']?(qwen2\.5-coder)["']?/gi,
      provider: "Alibaba",
      model: "qwen2.5-coder",
      type: "text-generation",
    },
    {
      pattern: /["']?(qwq)["']?/gi,
      provider: "Alibaba",
      model: "qwq",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemma2)["']?/gi,
      provider: "Google",
      model: "gemma2",
      type: "text-generation",
    },
    {
      pattern: /["']?(gemma3)["']?/gi,
      provider: "Google",
      model: "gemma3",
      type: "text-generation",
    },
    {
      pattern: /["']?(phi4)["']?/gi,
      provider: "Microsoft",
      model: "phi4",
      type: "text-generation",
    },
    {
      pattern: /["']?(phi3)["']?/gi,
      provider: "Microsoft",
      model: "phi3",
      type: "text-generation",
    },
    {
      pattern: /["']?(mistral)(?![-\w.])["']?/gi,
      provider: "Mistral",
      model: "mistral",
      type: "text-generation",
    },
    {
      pattern: /["']?(medllama2)["']?/gi,
      provider: "Meta",
      model: "medllama2",
      type: "text-generation",
    },
    {
      pattern: /["']?(meditron)["']?/gi,
      provider: "EPFL",
      model: "meditron",
      type: "text-generation",
    },
    {
      pattern: /["']?(mathstral)["']?/gi,
      provider: "Mistral",
      model: "mathstral",
      type: "text-generation",
    },
    // Use word boundaries to prevent false matches in "yield", "lying", etc.
    // Match: "yi", 'yi', or yi as standalone word (not inside other words)
    {
      pattern: /["']yi["']|\byi\b/gi,
      provider: "01.AI",
      model: "yi",
      type: "text-generation",
    },
    {
      pattern: /["']?(athene-v2)["']?/gi,
      provider: "Nexusflow",
      model: "athene-v2",
      type: "text-generation",
    },
    {
      pattern: /["']?(llama4)["']?/gi,
      provider: "Meta",
      model: "llama4",
      type: "text-generation",
    },
    {
      pattern: /["']?(qwen3)["']?/gi,
      provider: "Alibaba",
      model: "qwen3",
      type: "text-generation",
    },
    {
      // Capture the specific variant (grok-2, grok-4, ...) instead of collapsing to "grok"
      pattern: /["']?(grok-[\w.]+)["']?/gi,
      provider: "xAI",
      model: "extract",
      type: "text-generation",
    },
    {
      // Amazon Nova / Titan families (quoted ids or bare family names)
      pattern: /["']?(amazon\.(?:nova|titan)[\w.-]*|(?:nova|titan)-(?:pro|lite|micro|premier|text|embed)[\w.-]*)["']?/gi,
      provider: "AWS Bedrock",
      model: "extract",
      type: "text-generation",
    },
    {
      // Bedrock-style qualified model ids: anthropic.claude-..., meta.llama..., us.anthropic.claude-...
      pattern: /["']((?:us\.|eu\.|apac\.)?(?:anthropic|amazon|meta|ai21|cohere|deepseek|mistral)\.[a-zA-Z0-9.-]+)["']/gi,
      provider: "AWS Bedrock",
      model: "extract-bedrock",
      type: "text-generation",
    },
  ];

  // Define exclusion list for non-code files
  const EXCLUDE_EXTENSIONS = [
    ".md",
    ".txt",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".doc",
    ".docx",
  ];

  const isCodeFile = (path) => {
    const ext = path.match(/\.[^.]+$/)?.[0]?.toLowerCase() || "";
    return codeExtensions.includes(ext) && !EXCLUDE_EXTENSIONS.includes(ext);
  };

  // Priority 1: Files where AI usage was already detected (from code search)
  const priorityFiles = [];
  if (aiFilesFound && aiFilesFound.length > 0) {
    console.log(
      `[Detector: AI Models] Priority scanning ${aiFilesFound.length} files with confirmed AI usage`,
    );
    aiFilesFound.forEach((path) => {
      // Only include actual code files, not documentation
      if (isCodeFile(path)) {
        priorityFiles.push(path);
      } else {
        console.log(`[Detector: AI Models] Skipping non-code file: ${path}`);
      }
    });
  }

  // Priority 2: Config files that might contain model names (but not documentation)
  const configFiles = tree.filter((entry) => {
    const path = entry.path.toLowerCase();
    const fileName = entry.path.split("/").pop().toLowerCase();

    // Exclude documentation directories
    if (
      path.includes("/docs/") ||
      path.includes("/documentation/") ||
      path.includes("/examples/") ||
      path.includes("/tutorials/")
    ) {
      return false;
    }

    return (
      fileName.match(/^(config|settings|\.env|constants)/) ||
      path.includes("/config/") ||
      (fileName.match(/\.(yaml|yml|json|toml|env)$/) &&
        (path.includes("model") || path.includes("llm") || path.includes("ai")))
    );
  });

  console.log(
    `[Detector: AI Models] Found ${configFiles.length} config files to scan for model references`,
  );
  configFiles.forEach((cf) => priorityFiles.push(cf.path));

  // Priority 3: Regular code files (already filtered by isCodeFile above)
  const codeFiles = tree
    .filter((entry) => {
      return (
        isCodeFile(entry.path) &&
        (!entry.size || entry.size < 500000) &&
        !priorityFiles.includes(entry.path)
      ); // Don't duplicate
    })
    .slice(0, 50); // Reduced since we're prioritizing AI files

  const allFilesToScan = [
    ...priorityFiles.map((path) => ({ path, priority: true })),
    ...codeFiles.map((entry) => ({ path: entry.path, priority: false })),
  ];

  console.log(
    `[Detector: AI Models] Total files to scan: ${allFilesToScan.length} (${priorityFiles.length} priority)`,
  );

  let filesScanned = 0;
  for (const { path, priority } of allFilesToScan) {
    filesScanned++;

    if (filesScanned % 10 === 0 || priority) {
      console.log(
        `[Detector: AI Models] Scanning ${priority ? "[PRIORITY] " : ""}${path} (${filesScanned}/${allFilesToScan.length})`,
      );
    }

    let content = await getFileContent(path);
    if (!content) {
      if (priority) {
        console.log(
          `[Detector: AI Models] ⚠️  Could not fetch priority file: ${path}`,
        );
      }
      continue;
    }

    // Notebooks are JSON; convert to plain source before pattern matching
    if (path.toLowerCase().endsWith(".ipynb")) {
      content = stripNotebookCells(content);
      if (!content) continue;
    }

    // Split content into lines for line number tracking
    const lines = content.split("\n");

    // Scan for model patterns
    for (const { pattern, provider, model, type } of modelPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;

      while ((match = regex.exec(content)) !== null) {
        let modelName =
          model === "extract" || model === "extract-bedrock" ? match[1] : model;

        // Special case: Exclude Google's models/* format from HuggingFace detector
        if (provider === "HuggingFace" && modelName.startsWith("models/")) {
          continue; // This is a Google model, not HuggingFace
        }

        // Normalize Bedrock qualified ids
        // (e.g. "us.anthropic.claude-3-5-sonnet-20241022-v2:0" -> "claude-3-5-sonnet")
        if (
          provider === "AWS Bedrock" &&
          (model === "extract" || model === "extract-bedrock")
        ) {
          const normalizedBedrockId = normalizeBedrockModelId(modelName);
          if (!normalizedBedrockId) continue;
          modelName = normalizedBedrockId;
        }

        // Calculate line number by counting newlines before match
        const lineNum = content.substring(0, match.index).split("\n").length;
        const lineContent = lines[lineNum - 1] || "";

        // HF-slug candidates extracted from import/require statements are
        // module specifiers, not models (e.g. `import { hideBin } from
        // 'yargs/helpers'`) — models are never importable modules, so reject
        // them locally without any API round-trip.
        if (
          provider === "HuggingFace" &&
          isNpmImportSpecifier(lineContent, modelName)
        ) {
          console.log(
            `[Detector: AI Models] ✗ Skipping npm import specifier: ${modelName} (module imports are not models)`,
          );
          continue;
        }

        // Validate model name to filter out false positives
        if (!isValidModelName(modelName, provider)) {
          continue; // Skip invalid model names
        }

        // Normalize Google model names: prefer "models/embedding-001" format
        let normalizedModelName = modelName;
        if (
          provider === "Google" &&
          !modelName.startsWith("models/") &&
          (modelName.includes("embedding") ||
            modelName.includes("text-embedding"))
        ) {
          normalizedModelName = `models/${modelName}`;
        }

        const key = `${provider}-${normalizedModelName}`;

        if (!modelsFound.has(key)) {
          modelsFound.set(key, {
            provider,
            modelName: normalizedModelName, // Use normalized name
            modelType: type, // text-generation, embeddings, text-to-image, etc.
            locations: [], // Change from files to locations (includes line numbers)
            isHuggingFace: provider === "HuggingFace",
          });

          if (priority) {
            const typeInfo = type !== "unknown" ? ` [${type}]` : "";
            console.log(
              `[Detector: AI Models] 🎯 Found ${provider} model "${normalizedModelName}"${typeInfo} in priority file: ${path}:${lineNum}`,
            );
          }
        }

        // Store location with line number (avoid duplicates)
        const existingLoc = modelsFound
          .get(key)
          .locations.find((loc) => loc.file === path && loc.line === lineNum);
        if (!existingLoc) {
          modelsFound.get(key).locations.push({
            file: path,
            line: lineNum,
            snippet: lineContent.trim().substring(0, 100),
          });
        }
      }
    }

    // ------------------------------------------------------------------
    // Contextual extraction: model kwargs, module constants, env-defaults.
    // Catches unknown/new model ids that literal patterns miss
    // (inspired by cisco aibom's kwarg extraction + akumar0205 dataflow).
    // ------------------------------------------------------------------
    const contextualRefs = extractContextualModelRefs(content, providersUsed);
    for (const ref of contextualRefs) {
      const provider = ref.provider || "Unknown";
      let ctxKey = `${provider}-${ref.model}`;

      // Unattributed refs: merge into an existing entry for the same model
      // name instead of emitting a duplicate "Unknown" component (the literal
      // pass may already have keyed it under a concrete provider).
      if (ref.provider === null) {
        const existingEntry = Array.from(modelsFound.entries()).find(
          ([, d]) => d.modelName.toLowerCase() === ref.model.toLowerCase(),
        );
        if (existingEntry) {
          ctxKey = existingEntry[0];
        }
      }

      if (!modelsFound.has(ctxKey)) {
        const modelType = /embed/i.test(ref.model)
          ? "embeddings"
          : /dall-e|image|diffusion|flux/i.test(ref.model)
            ? "text-to-image"
            : "text-generation";

        modelsFound.set(ctxKey, {
          provider,
          modelName: ref.model,
          modelType,
          locations: [],
          isHuggingFace: false,
          detectionSource: `Contextual Reference (${ref.method})`,
          contextual: true,
        });
      }

      const ctxLineContent = lines[ref.line - 1] || "";
      const ctxLoc = modelsFound
        .get(ctxKey)
        .locations.find((loc) => loc.file === path && loc.line === ref.line);
      if (!ctxLoc) {
        modelsFound.get(ctxKey).locations.push({
          file: path,
          line: ref.line,
          snippet: ctxLineContent.trim().substring(0, 100),
        });
      }
    }

    // Ollama-style local model tags: "llama3.2:latest", "qwen3:4b"
    // Gated on Ollama context (content or filename) to avoid
    // false positives from ports, versions, and time strings.
    if (/ollama|modelfile/i.test(content) || /ollama|modelfile/i.test(path)) {
      const ollamaTagRegex =
        /["']([a-z0-9][a-z0-9._-]{2,48}:[a-z0-9][a-z0-9._-]{0,24})["']/gi;
      let ollamaMatch;
      while ((ollamaMatch = ollamaTagRegex.exec(content)) !== null) {
        const tag = ollamaMatch[1];
        const base = tag.split(":")[0];
        // Skip hosts, ports, versions, and API path segments
        if (
          /^(localhost|127|0\.0\.0\.0|http|https|ws|wss|api|v\d)/i.test(base) ||
          /^[0-9]/.test(base)
        ) {
          continue;
        }
        if (!isPlausibleModelId(tag)) continue;

        const ollamaKey = `Ollama-${tag}`;
        const tagLineNum = content
          .substring(0, ollamaMatch.index)
          .split("\n").length;
        if (!modelsFound.has(ollamaKey)) {
          modelsFound.set(ollamaKey, {
            provider: "Ollama",
            modelName: tag,
            modelType: "text-generation",
            locations: [],
            isHuggingFace: false,
            detectionSource: "Ollama Model Tag",
            contextual: true,
          });
        }
        const tagLineContent = lines[tagLineNum - 1] || "";
        const tagLoc = modelsFound
          .get(ollamaKey)
          .locations.find(
            (loc) => loc.file === path && loc.line === tagLineNum,
          );
        if (!tagLoc) {
          modelsFound.get(ollamaKey).locations.push({
            file: path,
            line: tagLineNum,
            snippet: tagLineContent.trim().substring(0, 100),
          });
        }
      }
    }
  }

  console.log(
    `[Detector: AI Models] Found ${modelsFound.size} distinct AI models`,
  );

  // Track duplicate/related models
  const modelRelationships = new Map(); // modelName (normalized) -> [keys]

  for (const [key, data] of modelsFound) {
    // Normalize model name for duplicate detection (lowercase, remove provider prefix)
    let normalized = data.modelName.toLowerCase();
    // Remove provider prefix if present (e.g., "openai/" -> "")
    normalized = normalized.replace(/^[^\/]+\//, "");

    if (!modelRelationships.has(normalized)) {
      modelRelationships.set(normalized, []);
    }
    modelRelationships.get(normalized).push({
      key,
      provider: data.provider,
      fullName: data.modelName,
    });
  }

  // Mark related models
  for (const [key, data] of modelsFound) {
    let normalized = data.modelName.toLowerCase().replace(/^[^\/]+\//, "");
    const related = modelRelationships.get(normalized);

    if (related && related.length > 1) {
      // This model has duplicates from other sources
      data.relatedModels = related
        .filter((r) => r.key !== key) // Exclude self
        .map((r) => ({
          provider: r.provider,
          modelName: r.fullName,
        }));

      // Add detection source for clarity
      data.detectionSource =
        data.provider === "HuggingFace"
          ? "HuggingFace Pattern Match"
          : data.isHuggingFace
            ? "HuggingFace API"
            : `${data.provider} Official`;
    }
  }

  // Fetch HuggingFace model details only for actual HF models
  for (const [key, data] of modelsFound) {
    if (data.isHuggingFace && shouldCheckHuggingFace) {
      console.log(
        `[Detector: AI Models] Fetching details for HuggingFace model: ${data.modelName}`,
      );
      const hfInfo = await fetchHuggingFaceModelInfo(data.modelName);
      if (hfInfo) {
        // HF API 404 = the slug does not exist on the Hub. A slug-shaped
        // candidate that isn't on HuggingFace is a false positive (e.g. the
        // npm subpath import 'yargs/helpers' looks like org/repo) — drop it
        // rather than emitting a model that cannot be verified anywhere.
        if (hfInfo.status === 404) {
          console.log(
            `[Detector: AI Models] ✗ ${data.modelName} not found on HuggingFace Hub — dropping false-positive candidate`,
          );
          modelsFound.delete(key);
          continue;
        }
        data.hfDetails = hfInfo;
        // Update modelType from HuggingFace if available
        if (hfInfo.verified && hfInfo.pipeline_tag) {
          data.modelType = hfInfo.pipeline_tag;
        }

        // Parse ModelCard YAML if available and merge with cardData
        if (hfInfo.modelCardContent) {
          try {
            const parsedCard = parseModelCardYAML(hfInfo.modelCardContent);
            if (Object.keys(parsedCard).length > 0) {
              data.modelCardData = parsedCard;
              // Merge parsed YAML data into cardData for easier access
              if (hfInfo.cardData) {
                hfInfo.cardData = { ...hfInfo.cardData, ...parsedCard };
              } else {
                hfInfo.cardData = { ...parsedCard };
              }
              console.log(
                `[Detector: AI Models] ✓ Parsed ModelCard YAML for ${data.modelName} (${Object.keys(parsedCard).length} fields)`,
              );
            }
          } catch (e) {
            console.log(
              `[Detector: AI Models] Could not parse ModelCard YAML for ${data.modelName}: ${e.message}`,
            );
          }
        }

        // No parseable card YAML (or no README) — synthesize a structured
        // card from the verified API details so every HF model still gets a
        // model card in the UI and the generated BOMs.
        if (!data.modelCardData) {
          const synthesized = buildModelCardDataFromHuggingFace(hfInfo, data.modelName);
          if (synthesized) {
            data.modelCardData = synthesized;
            console.log(
              `[Detector: AI Models] ✓ Synthesized model card from HuggingFace API data for ${data.modelName}`,
            );
          }
        }
      }
    } else if (data.isHuggingFace && !shouldCheckHuggingFace) {
      console.log(
        `[Detector: AI Models] Skipping HuggingFace API check for ${data.modelName} (no HuggingFace libraries detected)`,
      );
    }

    // Build description based on provider and model type
    let description;
    const typeLabel =
      data.modelType && data.modelType !== "unknown"
        ? ` (${data.modelType})`
        : "";

    if (data.isHuggingFace && data.hfDetails) {
      if (data.hfDetails.verified) {
        description = `HuggingFace model: ${data.modelName}${typeLabel} - ${data.hfDetails.downloads?.toLocaleString()} downloads, License: ${data.hfDetails.license || "Unknown"}`;
      } else {
        description = `HuggingFace model: ${data.modelName}${typeLabel} (unverified - API unavailable)`;
      }
    } else if (data.provider === "Google") {
      description = `Google AI model: ${data.modelName}${typeLabel}`;
    } else if (data.provider === "OpenAI") {
      description = `OpenAI model: ${data.modelName}${typeLabel}`;
    } else if (data.provider === "Anthropic") {
      description = `Anthropic model: ${data.modelName}${typeLabel}`;
    } else {
      description = `${data.provider} model: ${data.modelName}${typeLabel}`;
    }

    // Create evidence with line numbers
    const evidence = data.locations.slice(0, 5).map((loc) => ({
      file: loc.file,
      line: loc.line,
      snippet: loc.snippet,
    }));

    // Only add HuggingFace model card info if verified
    if (data.hfDetails && data.hfDetails.verified) {
      evidence.push({
        file: "HuggingFace Model Card",
        snippet: JSON.stringify(
          {
            model: data.hfDetails.id,
            downloads: data.hfDetails.downloads,
            likes: data.hfDetails.likes,
            license: data.hfDetails.license,
            tags: data.hfDetails.tags?.slice(0, 5).join(", "),
            pipeline: data.hfDetails.pipeline_tag,
          },
          null,
          2,
        ),
      });
    }

    // Detect model lineage relationships
    if (data.hfDetails?.cardData?.base_model) {
      const baseModel = data.hfDetails.cardData.base_model;
      // Check if base model is already in our modelsFound
      const baseModelKey = Object.keys(modelsFound).find((key) => {
        const modelData = modelsFound[key];
        return (
          modelData.modelName === baseModel ||
          modelData.modelName.includes(baseModel) ||
          baseModel.includes(modelData.modelName)
        );
      });

      if (baseModelKey) {
        // This is a fine-tuned version of an existing model
        if (!data.relatedModels) data.relatedModels = [];
        data.relatedModels.push({
          model: baseModel,
          relationship: "fine-tuned-from",
          source: "huggingface-base-model",
        });
        console.log(
          `[Detector: AI Models] 🔗 Detected lineage: ${data.modelName} is fine-tuned from ${baseModel}`,
        );
      } else {
        // Base model not found, still record the relationship
        if (!data.relatedModels) data.relatedModels = [];
        data.relatedModels.push({
          model: baseModel,
          relationship: "fine-tuned-from",
          source: "huggingface-base-model",
          note: "Base model not detected in this repository",
        });
        console.log(
          `[Detector: AI Models] 🔗 Recorded lineage: ${data.modelName} is fine-tuned from ${baseModel} (base model not found locally)`,
        );
      }
    }

    // Detect fine-tuning techniques used on this model
    const fineTuningTechniques = [];
    const content =
      allFindings.find(
        (f) =>
          f.category === "code" &&
          f.evidence?.some((e) => e.file === data.locations[0]?.file),
      )?.evidence?.[0]?.snippet || "";

    for (const pattern of FINE_TUNING_PATTERNS.patterns) {
      if (pattern.pattern.test(content)) {
        fineTuningTechniques.push({
          technique: pattern.technique,
          weight: pattern.weight,
        });
      }
    }

    if (fineTuningTechniques.length > 0) {
      if (!data.fineTuning) data.fineTuning = [];
      data.fineTuning.push(...fineTuningTechniques);
    }

    // Detect lineage from naming patterns (e.g., model-instruct, model-chat, model-v2)
    const modelNameLower = data.modelName.toLowerCase();
    for (const [existingKey, existingModel] of Object.entries(modelsFound)) {
      if (existingKey === key) continue; // Don't compare with itself

      const existingNameLower = existingModel.modelName.toLowerCase();

      // Check for common fine-tuning naming patterns
      const isInstructVariant =
        modelNameLower.includes("instruct") &&
        existingNameLower ===
          modelNameLower.replace("-instruct", "").replace("instruct", "");
      const isChatVariant =
        modelNameLower.includes("chat") &&
        existingNameLower ===
          modelNameLower.replace("-chat", "").replace("chat", "");
      const isV2Variant =
        modelNameLower.includes("v2") &&
        existingNameLower ===
          modelNameLower.replace("-v2", "").replace("v2", "");
      const isLoraVariant =
        modelNameLower.includes("lora") &&
        existingNameLower ===
          modelNameLower.replace("-lora", "").replace("lora", "");

      if (isInstructVariant || isChatVariant || isV2Variant || isLoraVariant) {
        if (!data.relatedModels) data.relatedModels = [];
        const relationship = isInstructVariant
          ? "instruct-tuned"
          : isChatVariant
            ? "chat-tuned"
            : isV2Variant
              ? "v2-version"
              : "lora-tuned";

        data.relatedModels.push({
          model: existingModel.modelName,
          relationship: relationship,
          source: "naming-pattern",
        });
        console.log(
          `[Detector: AI Models] 🔗 Detected lineage via naming: ${data.modelName} is ${relationship} from ${existingModel.modelName}`,
        );
        break; // Only add one relationship per naming pattern
      }
    }

    findings.push({
      id: `model-${key}`,
      title: `AI Model Identified: ${data.modelName}`,
      category: "models",
      severity: "high",
      weight: 5,
      description,
      evidence,
      modelInfo: {
        provider: data.provider,
        modelName: data.modelName,
        modelType: data.modelType, // text-generation, embeddings, text-to-image, etc.
        locations: data.locations, // Use locations with line numbers
        files: data.locations.map((loc) => loc.file), // Also keep files array for backward compatibility
        ...(data.hfDetails && { huggingface: data.hfDetails }),
        ...(data.modelCardData && { modelCardData: data.modelCardData }),
        ...(data.detectionSource && { detectionSource: data.detectionSource }),
        ...(data.relatedModels && { relatedModels: data.relatedModels }),
      },
    });

    const typeInfo =
      data.modelType && data.modelType !== "unknown"
        ? ` [${data.modelType}]`
        : "";
    console.log(
      `[Detector: AI Models] ✓ ${data.provider} model "${data.modelName}"${typeInfo} found in ${data.locations.length} location(s)`,
    );
  }

  console.log(`[Detector: AI Models] Complete. Findings: ${findings.length}`);
  return findings;
}

async function fineTuningDetector({ tree, getFileContent }) {
  console.log(
    "[Detector: Fine-tuning] Starting fine-tuning technique detection...",
  );
  const findings = [];

  // Get file extensions to scan based on repository languages
  const codeExtensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".ipynb"];

  // Scan code files for fine-tuning patterns
  const codeFiles = tree
    .filter((entry) => {
      const ext = entry.path.match(/\.[^.]+$/)?.[0] || "";
      return (
        codeExtensions.includes(ext) && (!entry.size || entry.size < 500000)
      );
    })
    .slice(0, 100); // Limit to 100 files

  console.log(
    `[Detector: Fine-tuning] Scanning ${codeFiles.length} code files for fine-tuning patterns...`,
  );

  const fineTuningTechniques = new Map();

  for (const file of codeFiles) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    for (const pattern of FINE_TUNING_PATTERNS.patterns) {
      if (pattern.pattern.test(content)) {
        const key = pattern.technique;
        if (!fineTuningTechniques.has(key)) {
          fineTuningTechniques.set(key, {
            technique: pattern.technique,
            weight: pattern.weight,
            locations: [],
          });
        }

        const match = content.match(pattern.pattern);
        fineTuningTechniques.get(key).locations.push({
          file: file.path,
          line: content.substring(0, match.index).split("\n").length,
          snippet: match[0].substring(0, 100),
        });
      }
    }
  }

  // Create findings
  for (const [key, data] of fineTuningTechniques) {
    const title = `${data.technique} Fine-tuning Technique Detected`;
    const description = `Found ${data.technique} fine-tuning technique in ${data.locations.length} location(s)`;

    const evidence = data.locations.slice(0, 5).map((loc) => ({
      file: loc.file,
      line: loc.line,
      snippet: loc.snippet,
    }));

    findings.push({
      id: `finetuning-${key.toLowerCase().replace(/\s+/g, "-")}`,
      title,
      category: "finetuning",
      severity: "info",
      weight: data.weight,
      description,
      evidence,
      fineTuningInfo: {
        technique: data.technique,
        locations: data.locations,
      },
    });
  }

  console.log(`[Detector: Fine-tuning] Complete. Findings: ${findings.length}`);
  return findings;
}

/**
 * R4: Attestation/signature presence detection. Tree scan for signing /
 * provenance artifacts (sigstore, in-toto links, SLSA provenance, Gitsign
 * workflows) plus a capped content check of GitHub workflow files for
 * slsa/provenance/sigstore/gitsign actions. Emits a positive governance
 * finding when evidence exists; absence is recorded by the BOM generators
 * as an explicit "none found" attestation state (no silent clean bill).
 */
async function attestationDetector({ tree, getFileContent }) {
  console.log("[Detector: Attestations] Scanning for signing/provenance artifacts...");
  const evidence = [];
  const types = new Set();

  const FILE_PATTERNS = [
    { re: /\.sigstore(\.json)?$/i, type: "sigstore bundle" },
    { re: /\.sig$/i, type: "signature file" },
    { re: /\.att$/i, type: "attestation file" },
    { re: /(^|\/)verification\.key$/i, type: "in-toto verification key" },
    { re: /SLSA_PROVENANCE/i, type: "SLSA provenance" },
    { re: /provenance\.json$/i, type: "SLSA provenance" },
    { re: /(^|\/)link$/i, type: "in-toto attestation link" },
    { re: /\.link$/i, type: "in-toto attestation link" }
  ];

  const workflowCandidates = [];
  for (const entry of tree) {
    if (!entry.path || entry.type === "tree") continue;
    for (const pattern of FILE_PATTERNS) {
      if (pattern.re.test(entry.path)) {
        evidence.push({ file: entry.path, snippet: `${pattern.type} present in repository` });
        types.add(pattern.type);
        break;
      }
    }
    // GitHub workflow files — checked for slsa/provenance/sigstore tooling
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(entry.path)) {
      workflowCandidates.push(entry.path);
    }
  }

  // Capped content check of workflow files for attestation tooling
  for (const path of workflowCandidates.slice(0, 20)) {
    try {
      const content = await getFileContent(path);
      if (!content) continue;
      const m = content.match(/(slsa-github-generator|slsa|provenance|sigstore|gitsign|in-toto|attest)/i);
      if (m) {
        evidence.push({
          file: path,
          line: content.slice(0, content.indexOf(m[0])).split("\n").length,
          snippet: `Workflow references attestation tooling: ${m[0]}`,
        });
        types.add("attestation workflow");
      }
    } catch (err) {
      console.log(`[Detector: Attestations] Could not read ${path}: ${err.message}`);
    }
  }

  if (evidence.length === 0) {
    console.log("[Detector: Attestations] Complete. No attestation evidence found");
    return { findings: [] };
  }

  const typeList = [...types].join(", ");
  console.log(
    `[Detector: Attestations] Complete. Found ${evidence.length} evidence item(s): ${typeList}`,
  );
  return {
    findings: [
      {
        id: "attestation-presence",
        title: "Artifact signing / attestation detected",
        category: "governance",
        severity: "low",
        weight: 3,
        description: `Signing or provenance evidence present in repository (${typeList})`,
        evidence: evidence.slice(0, 10),
        attestationInfo: { detected: true, types: [...types] },
      },
    ],
  };
}

async function dataPipelineDetector({ tree, getFileContent }) {
  console.log("[Detector: Data Pipeline] Starting data pipeline detection...");
  const findings = [];
  const datasetsFound = new Map();

  // Get file extensions to scan based on repository languages
  const codeExtensions = [
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".scala",
    ".go",
    ".rs",
  ];

  // Scan code files for data loading patterns
  const codeFiles = tree
    .filter((entry) => {
      const ext = entry.path.match(/\.[^.]+$/)?.[0] || "";
      return (
        codeExtensions.includes(ext) && (!entry.size || entry.size < 500000)
      );
    })
    .slice(0, 100); // Limit to 100 files

  console.log(
    `[Detector: Data Pipeline] Scanning ${codeFiles.length} code files for data loading patterns...`,
  );

  for (const file of codeFiles) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    // Check for data loading patterns
    for (const category of Object.values(DATA_PIPELINE_PATTERNS)) {
      if (!category.patterns) continue;

      for (const pattern of category.patterns) {
        const regex = new RegExp(pattern.pattern, "gi");
        let match;
        while ((match = regex.exec(content)) !== null) {
          const key = `${pattern.tool}-${file.path}`;
          if (!datasetsFound.has(key)) {
            datasetsFound.set(key, {
              tool: pattern.tool,
              file: file.path,
              category: Object.keys(DATA_PIPELINE_PATTERNS).find(
                (k) => DATA_PIPELINE_PATTERNS[k] === category,
              ),
              weight: pattern.weight,
              locations: [],
            });
          }

          const datasetInfo = datasetsFound.get(key);
          let datasetName = null;
          let datasetSource = "custom";

          // Extract dataset name if pattern supports it
          if (pattern.extractDataset && match[1]) {
            datasetName = match[1];
            // Determine source
            if (pattern.tool === "HuggingFace Datasets") {
              datasetSource = "huggingface";
            } else if (pattern.tool.includes("Kaggle")) {
              datasetSource = "kaggle";
            }
          }

          datasetInfo.locations.push({
            line: content.substring(0, match.index).split("\n").length,
            snippet: match[0].substring(0, 100),
            dataset: datasetName,
            source: datasetSource,
          });
        }
      }
    }
  }

  // Check for data versioning files and tools
  const dataVersioningFiles = tree.filter((entry) => {
    const path = entry.path.toLowerCase();
    return DATA_PIPELINE_PATTERNS.data_versioning.files.some((file) =>
      path.includes(file.replace("/", "")),
    );
  });

  console.log(
    `[Detector: Data Pipeline] Found ${dataVersioningFiles.length} data versioning files`,
  );

  for (const file of dataVersioningFiles.slice(0, 10)) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    const key = `data-versioning-${file.path}`;
    datasetsFound.set(key, {
      tool: "Data Versioning",
      file: file.path,
      category: "data_versioning",
      weight: 4,
      locations: [
        {
          line: 1,
          snippet: `Data versioning file: ${file.path}`,
          dataset: null,
          source: "versioning",
        },
      ],
    });
  }

  // R5-lite: enrich HF-sourced dataset names via the HuggingFace datasets
  // API (license/description/last-modified — license-if-public tier).
  // Slug-shaped and top-level hub ids both resolve; capped like LFS fetches.
  const hfDatasets = [];
  for (const [key, data] of datasetsFound) {
    for (const loc of data.locations) {
      if (loc.dataset && loc.source === "huggingface" && !hfDatasets.some((d) => d.name === loc.dataset)) {
        hfDatasets.push({ name: loc.dataset });
      }
    }
  }
  if (hfDatasets.length > 0) {
    console.log(
      `[Detector: Data Pipeline] Enriching ${hfDatasets.length} HuggingFace dataset(s) via the datasets API...`,
    );
    for (const ds of hfDatasets.slice(0, 25)) {
      const info = await fetchHuggingFaceDatasetInfo(ds.name);
      if (info.verified && info.enrichment) {
        ds.hf = info.enrichment;
      }
    }
  }

  // Create findings
  for (const [key, data] of datasetsFound) {
    const title = `${data.tool} Data Pipeline Detected`;
    const description = `Found ${data.tool} usage for data ${data.category} in ${data.locations.length} location(s)`;

    const evidence = data.locations.slice(0, 5).map((loc) => ({
      file: data.file,
      line: loc.line,
      snippet: loc.snippet,
    }));

    findings.push({
      id: `data-pipeline-${key.replace(/[^a-zA-Z0-9]/g, "-")}`,
      title,
      category: "data-pipeline",
      severity: "info",
      weight: data.weight,
      description,
      evidence,
      dataPipelineInfo: {
        tool: data.tool,
        category: data.category,
        datasets: data.locations
          .filter((loc) => loc.dataset)
          .map((loc) => {
            const entry = { name: loc.dataset, source: loc.source };
            // HF datasets-API enrichment (license/description) attached earlier
            const hf = hfDatasets.find((d) => d.name === loc.dataset);
            if (hf && hf.hf) {
              entry.hf = hf.hf;
            }
            return entry;
          }),
      },
    });
  }

  console.log(
    `[Detector: Data Pipeline] Complete. Findings: ${findings.length}`,
  );
  return findings;
}

async function promptsDetector({ tree, getFileContent }) {
  console.log("[Detector: Prompts] Starting prompt template detection...");
  const findings = [];
  const PROMPT_PATHS = ["prompts", "templates", "llm", "ai"];
  const promptFiles = tree.filter(
    (entry) =>
      PROMPT_PATHS.some((p) => entry.path.toLowerCase().includes(p)) &&
      entry.path.match(/\.(txt|md|json|yaml)$/),
  );

  console.log(
    `[Detector: Prompts] Found ${promptFiles.length} potential prompt files`,
  );

  const foundPrompts = [];
  for (const file of promptFiles.slice(0, 20)) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    const foundIndicators = PROMPT_INDICATORS.filter((ind) =>
      content.toLowerCase().includes(ind.toLowerCase()),
    );

    if (foundIndicators.length > 0) {
      foundPrompts.push({ file: file.path, indicators: foundIndicators });
    }
  }

  const promptDirs = new Set();
  for (const entry of tree) {
    for (const promptPath of PROMPT_PATHS) {
      if (entry.path.toLowerCase().includes(promptPath)) {
        const dirMatch = entry.path.match(
          new RegExp(`.*${promptPath}[^/]*`, "i"),
        );
        if (dirMatch) promptDirs.add(dirMatch[0]);
      }
    }
  }

  // Log prompt-related information for analysis, but don't create findings
  // Prompts are not components in AIBOM specifications (CycloneDX, SPDX)
  // They are inputs/configuration, not part of the bill of materials
  if (promptDirs.size > 0) {
    console.log(
      `[Detector: Prompts] ℹ️  Found ${promptDirs.size} prompt/AI directories: ${Array.from(promptDirs).join(", ")}`,
    );
    console.log(
      `[Detector: Prompts] Note: Directory names are logged but not included as AIBOM findings`,
    );
    console.log(
      `[Detector: Prompts] Reason: Prompts are not components in AIBOM specifications - they are inputs/configuration, not BOM components`,
    );
  }

  if (foundPrompts.length > 0) {
    console.log(
      `[Detector: Prompts] ℹ️  Found ${foundPrompts.length} files with prompt indicators`,
    );
    console.log(
      `[Detector: Prompts] Note: Prompt templates are logged but not included as AIBOM findings`,
    );
    console.log(
      `[Detector: Prompts] Reason: Prompts are not components in AIBOM specifications - they are inputs/configuration, not BOM components`,
    );
  }

  if (promptDirs.size === 0 && foundPrompts.length === 0) {
    console.log("[Detector: Prompts] No prompt directories or templates found");
  }

  console.log(`[Detector: Prompts] Complete. Findings: ${findings.length}`);
  return findings; // Returns empty array - prompts are not AIBOM components
}

// ============================================================================
// HARDWARE DETECTION
// ============================================================================
async function hardwareDetector({ tree, getFileContent, allFindings = [] }) {
  console.log("[Detector: Hardware] Starting hardware detection...");
  const findings = [];
  const hardwareInfo = {
    gpu: new Set(), // Generic GPU detection (CUDA, GPU libraries)
    gpuModels: new Set(), // Specific GPU models (A10G, H100, T4, etc.)
    tpu: new Set(),
    specialized: new Set(),
    distributedTraining: new Set(), // Distributed training frameworks
    evidence: [],
  };

  // Check dependencies for hardware libraries
  const depFindings = allFindings.filter((f) => f.category === "dependencies");
  for (const depFinding of depFindings) {
    const depName =
      depFinding.dependencyInfo?.name?.toLowerCase() ||
      depFinding.title.toLowerCase();

    // Check GPU dependencies
    for (const gpuDep of HARDWARE_PATTERNS.gpu.dependencies) {
      if (depName.includes(gpuDep.toLowerCase())) {
        hardwareInfo.gpu.add(gpuDep);
        hardwareInfo.evidence.push({
          file: "Dependencies",
          snippet: `GPU library: ${depFinding.dependencyInfo?.name || depFinding.title}`,
          type: "GPU",
        });
      }
    }

    // Check TPU dependencies
    for (const tpuDep of HARDWARE_PATTERNS.tpu.dependencies) {
      if (depName.includes(tpuDep.toLowerCase())) {
        hardwareInfo.tpu.add(tpuDep);
        hardwareInfo.evidence.push({
          file: "Dependencies",
          snippet: `TPU library: ${depFinding.dependencyInfo?.name || depFinding.title}`,
          type: "TPU",
        });
      }
    }

    // Check specialized hardware dependencies
    for (const specDep of HARDWARE_PATTERNS.specialized.dependencies) {
      if (depName.includes(specDep.toLowerCase())) {
        hardwareInfo.specialized.add(specDep);
        hardwareInfo.evidence.push({
          file: "Dependencies",
          snippet: `Specialized hardware: ${depFinding.dependencyInfo?.name || depFinding.title}`,
          type: "specialized",
        });
      }
    }

    // Check distributed training dependencies
    for (const dtDep of HARDWARE_PATTERNS.distributed_training.dependencies) {
      if (
        depName.includes(dtDep.toLowerCase()) ||
        dtDep.toLowerCase().includes(depName)
      ) {
        hardwareInfo.distributedTraining.add(dtDep);
        hardwareInfo.evidence.push({
          file: "Dependencies",
          snippet: `Distributed training: ${depFinding.dependencyInfo?.name || depFinding.title}`,
          type: "distributed_training",
        });
      }
    }
  }

  // Scan code files for hardware usage patterns
  // GPU: Scan Python, JavaScript/TypeScript (for TensorFlow.js, WebGL)
  // TPU: Only scan Python files (TPU is Python/TensorFlow/JAX specific)
  // Specialized: Scan Python primarily, some JS for ONNX Runtime Web
  const codeFiles = tree.filter(
    (entry) => entry.path.match(/\.(py|js|ts|ipynb)$/) && entry.type === "blob",
  );

  console.log(
    `[Detector: Hardware] Scanning ${Math.min(codeFiles.length, 50)} code files for hardware patterns...`,
  );

  for (const file of codeFiles.slice(0, 50)) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    const isPythonFile = file.path.match(/\.(py|ipynb)$/);
    const isJsFile = file.path.match(/\.(js|ts|jsx|tsx)$/);

    // Check GPU patterns (all file types - GPU is used in Python, JS via TensorFlow.js, WebGL)
    for (const pattern of HARDWARE_PATTERNS.gpu.patterns) {
      if (pattern.pattern.test(content)) {
        const match = content.match(pattern.pattern);

        // Extract specific GPU model if pattern has extractModel flag
        if (pattern.extractModel && match && match[1]) {
          const gpuModel = match[1].trim();
          hardwareInfo.gpuModels.add(gpuModel);
          hardwareInfo.evidence.push({
            file: file.path,
            snippet: match[0].substring(0, 100),
            type: "GPU",
            gpuModel: gpuModel,
          });
          console.log(
            `[Detector: Hardware] ✓ Found specific GPU model: ${gpuModel} in ${file.path}`,
          );
        } else {
          // Generic GPU detection
          hardwareInfo.gpu.add(pattern.type);
          hardwareInfo.evidence.push({
            file: file.path,
            snippet: match ? match[0].substring(0, 100) : "GPU usage detected",
            type: "GPU",
          });
        }
      }
    }

    // Check TPU patterns (Python files ONLY - TPU is TensorFlow/JAX specific)
    if (isPythonFile) {
      for (const pattern of HARDWARE_PATTERNS.tpu.patterns) {
        if (pattern.pattern.test(content)) {
          hardwareInfo.tpu.add(pattern.type);
          const match = content.match(pattern.pattern);
          hardwareInfo.evidence.push({
            file: file.path,
            snippet: match ? match[0].substring(0, 100) : "TPU usage detected",
            type: "TPU",
          });
        }
      }
    }

    // Check specialized hardware patterns (primarily Python, some JS for ONNX Runtime Web)
    for (const pattern of HARDWARE_PATTERNS.specialized.patterns) {
      // TensorRT, OpenVINO: Python only
      if (pattern.type === "TensorRT" || pattern.type === "OpenVINO") {
        if (!isPythonFile) continue;
      }

      if (pattern.pattern.test(content)) {
        hardwareInfo.specialized.add(pattern.type);
        const match = content.match(pattern.pattern);
        hardwareInfo.evidence.push({
          file: file.path,
          snippet: match
            ? match[0].substring(0, 100)
            : `${pattern.type} usage detected`,
          type: "specialized",
        });
      }
    }

    // Check distributed training patterns (Python files primarily)
    if (isPythonFile) {
      for (const pattern of HARDWARE_PATTERNS.distributed_training.patterns) {
        if (pattern.pattern.test(content)) {
          hardwareInfo.distributedTraining.add(pattern.framework);
          const match = content.match(pattern.pattern);
          hardwareInfo.evidence.push({
            file: file.path,
            snippet: match
              ? match[0].substring(0, 100)
              : `${pattern.framework} usage detected`,
            type: "distributed_training",
          });
        }
      }
    }
  }

  // Create findings
  if (hardwareInfo.gpu.size > 0 || hardwareInfo.gpuModels.size > 0) {
    const gpuParts = [];
    if (hardwareInfo.gpuModels.size > 0) {
      gpuParts.push(`Models: ${Array.from(hardwareInfo.gpuModels).join(", ")}`);
    }
    if (hardwareInfo.gpu.size > 0) {
      gpuParts.push(`Libraries: ${Array.from(hardwareInfo.gpu).join(", ")}`);
    }

    const description =
      hardwareInfo.gpuModels.size > 0
        ? `GPU compute detected: ${Array.from(hardwareInfo.gpuModels).join(", ")}${hardwareInfo.gpu.size > 0 ? ` (${Array.from(hardwareInfo.gpu).join(", ")})` : ""}`
        : `GPU compute detected: ${Array.from(hardwareInfo.gpu).join(", ")}`;

    console.log(
      `[Detector: Hardware] ✓ Found GPU usage: ${gpuParts.join("; ")}`,
    );
    findings.push({
      id: "hardware-gpu",
      title: "GPU Hardware Detected",
      category: "hardware",
      severity: "high",
      weight: 4,
      description: description,
      evidence: hardwareInfo.evidence
        .filter((e) => e.type === "GPU")
        .slice(0, 5),
      hardwareInfo: {
        type: "GPU",
        models: Array.from(hardwareInfo.gpuModels),
        libraries: Array.from(hardwareInfo.gpu),
      },
    });
  }

  if (hardwareInfo.tpu.size > 0) {
    console.log(
      `[Detector: Hardware] ✓ Found TPU usage: ${Array.from(hardwareInfo.tpu).join(", ")}`,
    );
    findings.push({
      id: "hardware-tpu",
      title: "TPU Hardware Detected",
      category: "hardware",
      severity: "high",
      weight: 4,
      description: `TPU compute detected: ${Array.from(hardwareInfo.tpu).join(", ")}`,
      evidence: hardwareInfo.evidence
        .filter((e) => e.type === "TPU")
        .slice(0, 5),
      hardwareInfo: {
        type: "TPU",
        libraries: Array.from(hardwareInfo.tpu),
      },
    });
  }

  if (hardwareInfo.specialized.size > 0) {
    console.log(
      `[Detector: Hardware] ✓ Found specialized hardware: ${Array.from(hardwareInfo.specialized).join(", ")}`,
    );
    findings.push({
      id: "hardware-specialized",
      title: "Specialized Hardware Detected",
      category: "hardware",
      severity: "medium",
      weight: 3,
      description: `Specialized compute: ${Array.from(hardwareInfo.specialized).join(", ")}`,
      evidence: hardwareInfo.evidence
        .filter((e) => e.type === "specialized")
        .slice(0, 5),
      hardwareInfo: {
        type: "specialized",
        libraries: Array.from(hardwareInfo.specialized),
      },
    });
  }

  if (hardwareInfo.distributedTraining.size > 0) {
    console.log(
      `[Detector: Hardware] ✓ Found distributed training: ${Array.from(hardwareInfo.distributedTraining).join(", ")}`,
    );
    findings.push({
      id: "hardware-distributed-training",
      title: "Distributed Training Framework Detected",
      category: "hardware",
      severity: "high",
      weight: 5,
      description: `Distributed training frameworks: ${Array.from(hardwareInfo.distributedTraining).join(", ")}`,
      evidence: hardwareInfo.evidence
        .filter((e) => e.type === "distributed_training")
        .slice(0, 5),
      hardwareInfo: {
        type: "distributed_training",
        frameworks: Array.from(hardwareInfo.distributedTraining),
      },
    });
  }

  console.log(`[Detector: Hardware] Complete. Findings: ${findings.length}`);
  return findings;
}

// ============================================================================
// INFRASTRUCTURE DETECTION
// ============================================================================
async function infrastructureDetector({
  tree,
  getFileContent,
  allFindings = [],
}) {
  console.log(
    "[Detector: Infrastructure] Starting infrastructure detection...",
  );
  const findings = [];
  const infraInfo = {
    containerization: new Set(),
    orchestration: new Set(),
    cloud: new Set(),
    mlops: new Map(), // Change to Map to store detailed info per platform
    hpo: new Set(), // Hyperparameter optimization frameworks
    modelServing: new Set(), // Model serving frameworks
    monitoring: new Set(), // Model monitoring tools
    evidence: [],
  };

  // Check for containerization files (Docker)
  // Only report ML-specific containerization (GPU, ML frameworks) - generic Docker isn't an AIBOM component
  const dockerFiles = tree.filter((entry) =>
    INFRASTRUCTURE_PATTERNS.containerization.files.some(
      (f) =>
        entry.path.toLowerCase().endsWith(f.toLowerCase()) ||
        entry.path.toLowerCase().includes(f.toLowerCase()),
    ),
  );

  console.log(
    `[Detector: Infrastructure] Found ${dockerFiles.length} containerization files`,
  );

  for (const file of dockerFiles) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    // Only detect ML-specific containerization patterns (GPU, ML frameworks)
    // Generic Docker isn't a component in AIBOM - it's deployment infrastructure
    let foundMLPattern = false;
    for (const pattern of INFRASTRUCTURE_PATTERNS.containerization.patterns) {
      if (pattern.pattern.test(content)) {
        foundMLPattern = true;
        infraInfo.containerization.add(pattern.platform);
        const match = content.match(pattern.pattern);
        infraInfo.evidence.push({
          file: file.path,
          snippet: match ? match[0].substring(0, 100) : pattern.platform,
          type: "containerization",
        });
      }
    }

    // Log generic Docker for analysis, but don't create finding
    if (!foundMLPattern) {
      console.log(
        `[Detector: Infrastructure] ℹ️  Found Dockerfile but no ML-specific patterns: ${file.path}`,
      );
      console.log(
        `[Detector: Infrastructure] Note: Generic Docker is deployment infrastructure, not an AIBOM component`,
      );
    }
  }

  // Check for orchestration files (Kubernetes)
  // Only report ML-specific orchestration (GPU scheduling) - generic Kubernetes isn't an AIBOM component
  const k8sFiles = tree.filter((entry) =>
    INFRASTRUCTURE_PATTERNS.orchestration.files.some((f) =>
      entry.path.toLowerCase().includes(f.toLowerCase()),
    ),
  );

  console.log(
    `[Detector: Infrastructure] Found ${k8sFiles.length} orchestration files`,
  );

  for (const file of k8sFiles) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    // Only detect ML-specific orchestration patterns (GPU scheduling, digest
    // pinning, model env config) - generic Kubernetes isn't an AIBOM component
    for (const pattern of INFRASTRUCTURE_PATTERNS.orchestration.patterns) {
      if (pattern.pattern.test(content)) {
        // Only report ML-specific Kubernetes patterns
        // Generic Kubernetes patterns are logged but not reported as findings
        if (
          pattern.platform.includes("GPU") ||
          pattern.platform.includes("Digest-Pinned") ||
          pattern.platform.includes("AI Model Environment")
        ) {
          infraInfo.orchestration.add(pattern.platform);
          const match = content.match(pattern.pattern);
          infraInfo.evidence.push({
            file: file.path,
            snippet: match ? match[0].substring(0, 100) : pattern.platform,
            type: "orchestration",
          });
        } else {
          console.log(
            `[Detector: Infrastructure] ℹ️  Found generic Kubernetes pattern in ${file.path}: ${pattern.platform}`,
          );
          console.log(
            `[Detector: Infrastructure] Note: Generic Kubernetes is deployment infrastructure, not an AIBOM component`,
          );
        }
      }
    }

    // Check HPO patterns (Python files primarily)
    if (isPythonFile) {
      for (const pattern of HPO_PATTERNS.patterns) {
        if (pattern.pattern.test(content)) {
          infraInfo.hpo.add(pattern.framework);
          const match = content.match(pattern.pattern);
          infraInfo.evidence.push({
            file: file.path,
            snippet: match
              ? match[0].substring(0, 100)
              : `${pattern.framework} usage detected`,
            type: "hpo",
          });
        }
      }
    }

    // Check model serving patterns
    for (const pattern of INFRASTRUCTURE_PATTERNS.model_serving.patterns) {
      if (pattern.pattern.test(content)) {
        infraInfo.modelServing.add(pattern.framework);
        const match = content.match(pattern.pattern);
        infraInfo.evidence.push({
          file: file.path,
          snippet: match ? match[0].substring(0, 100) : pattern.framework,
          type: "model_serving",
        });
      }
    }

    // Check monitoring patterns
    for (const pattern of MONITORING_PATTERNS.patterns) {
      if (pattern.pattern.test(content)) {
        infraInfo.monitoring.add(pattern.tool);
        const match = content.match(pattern.pattern);
        infraInfo.evidence.push({
          file: file.path,
          snippet: match ? match[0].substring(0, 100) : pattern.tool,
          type: "monitoring",
        });
      }
    }
  }

  // Check for cloud patterns in code and config files
  const configFiles = tree.filter(
    (entry) =>
      entry.path.match(/\.(py|js|ts|yaml|yml|json|toml|ini|cfg)$/) &&
      entry.type === "blob",
  );

  console.log(
    `[Detector: Infrastructure] Scanning ${Math.min(configFiles.length, 100)} files for cloud patterns...`,
  );

  for (const file of configFiles.slice(0, 100)) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    // Check cloud patterns
    for (const pattern of INFRASTRUCTURE_PATTERNS.cloud.patterns) {
      if (pattern.pattern.test(content)) {
        infraInfo.cloud.add(pattern.platform);
        const match = content.match(pattern.pattern);
        infraInfo.evidence.push({
          file: file.path,
          snippet: match ? match[0].substring(0, 100) : pattern.platform,
          type: "cloud",
        });
      }
    }

    // Check MLOps patterns
    for (const pattern of INFRASTRUCTURE_PATTERNS.mlops.patterns) {
      if (pattern.pattern.test(content)) {
        const match = content.match(pattern.pattern);
        const platform = pattern.platform;

        if (!infraInfo.mlops.has(platform)) {
          infraInfo.mlops.set(platform, {
            detected: true,
            projects: new Set(),
            tags: new Set(),
            apiKeys: new Set(),
          });
        }

        const platformInfo = infraInfo.mlops.get(platform);

        // Extract project name if pattern supports it
        if (pattern.extractProject && match && match[1]) {
          platformInfo.projects.add(match[1]);
        }

        // Extract API key if pattern supports it (for security awareness)
        if (pattern.extractApiKey && match && match[1]) {
          platformInfo.apiKeys.add("[REDACTED]"); // Don't store actual keys
        }

        infraInfo.evidence.push({
          file: file.path,
          snippet: match ? match[0].substring(0, 100) : platform,
          type: "mlops",
          platform: platform,
          project: pattern.extractProject && match ? match[1] : null,
        });
      }
    }
  }

  // Check dependencies for MLOps tools
  const depFindings = allFindings.filter((f) => f.category === "dependencies");
  for (const depFinding of depFindings) {
    const depName =
      depFinding.dependencyInfo?.name?.toLowerCase() ||
      depFinding.title.toLowerCase();

    for (const mlopsDep of INFRASTRUCTURE_PATTERNS.mlops.dependencies) {
      if (depName.includes(mlopsDep.toLowerCase())) {
        // Map dependency name to platform name
        const platformMap = {
          mlflow: "MLflow",
          wandb: "Weights & Biases",
          tensorboard: "TensorBoard",
          clearml: "ClearML",
          "neptune-client": "Neptune",
          "comet-ml": "Comet ML",
          aim: "Aim",
          sacred: "Sacred",
        };

        const platform = platformMap[mlopsDep] || mlopsDep;

        if (!infraInfo.mlops.has(platform)) {
          infraInfo.mlops.set(platform, {
            detected: true,
            projects: new Set(),
            tags: new Set(),
            apiKeys: new Set(),
          });
        }

        infraInfo.evidence.push({
          file: "Dependencies",
          snippet: `MLOps tool: ${depFinding.dependencyInfo?.name || depFinding.title}`,
          type: "mlops",
          platform: platform,
        });
      }
    }
  }

  // Check HPO dependencies (reuse existing depFindings)
  for (const depFinding of depFindings) {
    const depName =
      depFinding.dependencyInfo?.name?.toLowerCase() ||
      depFinding.title.toLowerCase();

    for (const hpoDep of HPO_PATTERNS.dependencies) {
      if (depName.includes(hpoDep.toLowerCase())) {
        infraInfo.hpo.add(hpoDep);
        infraInfo.evidence.push({
          file: "Dependencies",
          snippet: `HPO library: ${depFinding.dependencyInfo?.name || depFinding.title}`,
          type: "hpo",
        });
      }
    }
  }

  // Check model serving dependencies
  for (const depFinding of depFindings) {
    const depName =
      depFinding.dependencyInfo?.name?.toLowerCase() ||
      depFinding.title.toLowerCase();

    for (const servingDep of INFRASTRUCTURE_PATTERNS.model_serving
      .dependencies) {
      if (depName.includes(servingDep.toLowerCase())) {
        infraInfo.modelServing.add(servingDep);
        infraInfo.evidence.push({
          file: "Dependencies",
          snippet: `Model serving: ${depFinding.dependencyInfo?.name || depFinding.title}`,
          type: "model_serving",
        });
      }
    }
  }

  // Check monitoring dependencies
  for (const depFinding of depFindings) {
    const depName =
      depFinding.dependencyInfo?.name?.toLowerCase() ||
      depFinding.title.toLowerCase();

    for (const monitoringDep of MONITORING_PATTERNS.dependencies) {
      if (depName.includes(monitoringDep.toLowerCase())) {
        infraInfo.monitoring.add(monitoringDep);
        infraInfo.evidence.push({
          file: "Dependencies",
          snippet: `Monitoring tool: ${depFinding.dependencyInfo?.name || depFinding.title}`,
          type: "monitoring",
        });
      }
    }
  }

  // Create findings
  if (infraInfo.containerization.size > 0) {
    console.log(
      `[Detector: Infrastructure] ✓ Found containerization: ${Array.from(infraInfo.containerization).join(", ")}`,
    );
    findings.push({
      id: "infra-containerization",
      title: "Containerization Detected",
      category: "infrastructure",
      severity: "medium",
      weight: 3,
      description: `Containerization platforms: ${Array.from(infraInfo.containerization).join(", ")}`,
      evidence: infraInfo.evidence
        .filter((e) => e.type === "containerization")
        .slice(0, 5),
      infraInfo: {
        type: "containerization",
        platforms: Array.from(infraInfo.containerization),
      },
    });
  }

  if (infraInfo.orchestration.size > 0) {
    console.log(
      `[Detector: Infrastructure] ✓ Found orchestration: ${Array.from(infraInfo.orchestration).join(", ")}`,
    );
    findings.push({
      id: "infra-orchestration",
      title: "Orchestration Detected",
      category: "infrastructure",
      severity: "medium",
      weight: 3,
      description: `Orchestration platforms: ${Array.from(infraInfo.orchestration).join(", ")}`,
      evidence: infraInfo.evidence
        .filter((e) => e.type === "orchestration")
        .slice(0, 5),
      infraInfo: {
        type: "orchestration",
        platforms: Array.from(infraInfo.orchestration),
      },
    });
  }

  if (infraInfo.cloud.size > 0) {
    console.log(
      `[Detector: Infrastructure] ✓ Found cloud platforms: ${Array.from(infraInfo.cloud).join(", ")}`,
    );
    findings.push({
      id: "infra-cloud",
      title: "Cloud Platform Detected",
      category: "infrastructure",
      severity: "high",
      weight: 4,
      description: `Cloud platforms: ${Array.from(infraInfo.cloud).join(", ")}`,
      evidence: infraInfo.evidence
        .filter((e) => e.type === "cloud")
        .slice(0, 5),
      infraInfo: {
        type: "cloud",
        platforms: Array.from(infraInfo.cloud),
      },
    });
  }

  if (infraInfo.mlops.size > 0) {
    const platforms = Array.from(infraInfo.mlops.keys());
    console.log(
      `[Detector: Infrastructure] ✓ Found MLOps tools: ${platforms.join(", ")}`,
    );

    // Create detailed description with project information
    const platformDetails = Array.from(infraInfo.mlops.entries()).map(
      ([platform, info]) => {
        const projects = Array.from(info.projects);
        const projectStr =
          projects.length > 0 ? ` (projects: ${projects.join(", ")})` : "";
        return `${platform}${projectStr}`;
      },
    );

    findings.push({
      id: "infra-mlops",
      title: "MLOps Experiment Tracking Detected",
      category: "infrastructure",
      severity: "medium",
      weight: 3,
      description: `Experiment tracking platforms: ${platformDetails.join(", ")}`,
      evidence: infraInfo.evidence
        .filter((e) => e.type === "mlops")
        .slice(0, 5),
      infraInfo: {
        type: "mlops",
        platforms: Array.from(infraInfo.mlops.entries()).map(
          ([platform, info]) => ({
            platform,
            projects: Array.from(info.projects),
            hasApiKeys: info.apiKeys.size > 0,
          }),
        ),
      },
    });
  }

  if (infraInfo.hpo.size > 0) {
    console.log(
      `[Detector: Infrastructure] ✓ Found HPO frameworks: ${Array.from(infraInfo.hpo).join(", ")}`,
    );
    findings.push({
      id: "infra-hpo",
      title: "Hyperparameter Optimization Detected",
      category: "infrastructure",
      severity: "medium",
      weight: 3,
      description: `HPO frameworks: ${Array.from(infraInfo.hpo).join(", ")}`,
      evidence: infraInfo.evidence.filter((e) => e.type === "hpo").slice(0, 5),
      infraInfo: {
        type: "hpo",
        frameworks: Array.from(infraInfo.hpo),
      },
    });
  }

  if (infraInfo.modelServing.size > 0) {
    console.log(
      `[Detector: Infrastructure] ✓ Found model serving: ${Array.from(infraInfo.modelServing).join(", ")}`,
    );
    findings.push({
      id: "infra-model-serving",
      title: "Model Serving Framework Detected",
      category: "infrastructure",
      severity: "medium",
      weight: 4,
      description: `Model serving frameworks: ${Array.from(infraInfo.modelServing).join(", ")}`,
      evidence: infraInfo.evidence
        .filter((e) => e.type === "model_serving")
        .slice(0, 5),
      infraInfo: {
        type: "model_serving",
        frameworks: Array.from(infraInfo.modelServing),
      },
    });
  }

  if (infraInfo.monitoring.size > 0) {
    console.log(
      `[Detector: Infrastructure] ✓ Found monitoring tools: ${Array.from(infraInfo.monitoring).join(", ")}`,
    );
    findings.push({
      id: "infra-monitoring",
      title: "Model Monitoring Tools Detected",
      category: "infrastructure",
      severity: "medium",
      weight: 3,
      description: `Monitoring tools: ${Array.from(infraInfo.monitoring).join(", ")}`,
      evidence: infraInfo.evidence
        .filter((e) => e.type === "monitoring")
        .slice(0, 5),
      infraInfo: {
        type: "monitoring",
        tools: Array.from(infraInfo.monitoring),
      },
    });
  }

  console.log(
    `[Detector: Infrastructure] Complete. Findings: ${findings.length}`,
  );
  return findings;
}

// ============================================================================
// DOCUMENTATION PARSER
// ============================================================================
/**
 * Parse RFC 9116 security.txt format
 * Fields: Contact, Expires, Encryption, Acknowledgments, Preferred-Languages, Canonical, Policy
 */
function parseSecurityTxt(content) {
  const securityInfo = {
    contact: [],
    expires: null,
    encryption: [],
    acknowledgments: [],
    preferredLanguages: [],
    canonical: null,
    policy: null,
  };

  const lines = content.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue; // Skip comments and empty lines

    // RFC 9116 format: Field: Value
    const colonIndex = trimmed.indexOf(":");
    if (colonIndex === -1) continue;

    const field = trimmed.substring(0, colonIndex).trim().toLowerCase();
    const value = trimmed.substring(colonIndex + 1).trim();

    switch (field) {
      case "contact":
        securityInfo.contact.push(value);
        break;
      case "expires":
        securityInfo.expires = value;
        break;
      case "encryption":
        securityInfo.encryption.push(value);
        break;
      case "acknowledgments":
        securityInfo.acknowledgments.push(value);
        break;
      case "preferred-languages":
        securityInfo.preferredLanguages = value.split(",").map((l) => l.trim());
        break;
      case "canonical":
        securityInfo.canonical = value;
        break;
      case "policy":
        securityInfo.policy = value;
        break;
    }
  }

  return securityInfo;
}

async function documentationParser({ tree, getFileContent }) {
  console.log("[Detector: Documentation] Starting documentation analysis...");
  const parsedDocs = {
    intendedUse: [],
    limitations: [],
    ethicalConsiderations: [],
    biasInformation: [],
    securityNotes: [],
    securityTxt: null, // RFC 9116 security.txt parsed data
    files: [],
  };

  // Find documentation files (including security.txt in .well-known/ or root)
  const docFiles = tree.filter((entry) => {
    const path = entry.path.toLowerCase();
    const fileName = entry.path.split("/").pop().toLowerCase();

    // Check standard documentation files
    if (
      DOCUMENTATION_FILES.some(
        (docFile) =>
          path.endsWith(docFile.toLowerCase()) ||
          fileName === docFile.toLowerCase(),
      )
    ) {
      return true;
    }

    // Check for security.txt in .well-known/ directory (RFC 9116 preferred location)
    if (
      path === ".well-known/security.txt" ||
      path === "/.well-known/security.txt"
    ) {
      return true;
    }

    return false;
  });

  console.log(
    `[Detector: Documentation] Found ${docFiles.length} documentation files`,
  );

  for (const file of docFiles.slice(0, 20)) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    parsedDocs.files.push(file.path);
    const lowerContent = content.toLowerCase();
    const fileName = file.path.split("/").pop().toLowerCase();

    // Special handling for RFC 9116 security.txt format
    if (
      fileName === "security.txt" ||
      file.path.toLowerCase().endsWith("/security.txt")
    ) {
      console.log(
        `[Detector: Documentation] Parsing RFC 9116 security.txt: ${file.path}`,
      );
      parsedDocs.securityTxt = parseSecurityTxt(content);

      // Also add security contact info to securityNotes for consistency
      if (parsedDocs.securityTxt.contact.length > 0) {
        parsedDocs.securityNotes.push({
          file: file.path,
          text: `Security Contact: ${parsedDocs.securityTxt.contact.join(", ")}`,
        });
      }
      if (parsedDocs.securityTxt.policy) {
        parsedDocs.securityNotes.push({
          file: file.path,
          text: `Security Policy: ${parsedDocs.securityTxt.policy}`,
        });
      }
      continue; // Skip markdown parsing for security.txt
    }

    // Extract sections by headers (for markdown files)
    const lines = content.split("\n");
    let currentSection = "";
    let currentContent = [];

    for (const line of lines) {
      // Check for markdown headers
      if (line.match(/^#{1,3}\s+/)) {
        // Save previous section
        if (currentSection && currentContent.length > 0) {
          const sectionText = currentContent.join(" ").substring(0, 500);

          if (
            currentSection.includes("intent") ||
            currentSection.includes("purpose") ||
            currentSection.includes("use case")
          ) {
            parsedDocs.intendedUse.push({ file: file.path, text: sectionText });
          }
          if (
            currentSection.includes("limit") ||
            currentSection.includes("constraint") ||
            currentSection.includes("known issue")
          ) {
            parsedDocs.limitations.push({ file: file.path, text: sectionText });
          }
          if (
            currentSection.includes("ethic") ||
            currentSection.includes("responsible") ||
            currentSection.includes("privacy")
          ) {
            parsedDocs.ethicalConsiderations.push({
              file: file.path,
              text: sectionText,
            });
          }
          if (
            currentSection.includes("bias") ||
            currentSection.includes("fairness") ||
            currentSection.includes("demographic")
          ) {
            parsedDocs.biasInformation.push({
              file: file.path,
              text: sectionText,
            });
          }
          if (
            currentSection.includes("security") ||
            currentSection.includes("vulnerability") ||
            currentSection.includes("cve")
          ) {
            parsedDocs.securityNotes.push({
              file: file.path,
              text: sectionText,
            });
          }
        }

        currentSection = line.toLowerCase();
        currentContent = [];
      } else if (line.trim()) {
        currentContent.push(line.trim());
      }
    }

    // Check for keyword presence if no clear sections found
    if (
      lowerContent.includes("intended use") ||
      lowerContent.includes("purpose")
    ) {
      const match = content.match(
        /(?:intended use|purpose)[:\s]+(.*?)(?:\n\n|$)/is,
      );
      if (match && parsedDocs.intendedUse.length === 0) {
        parsedDocs.intendedUse.push({
          file: file.path,
          text: match[1].substring(0, 500),
        });
      }
    }
  }

  if (parsedDocs.securityTxt) {
    console.log(
      `[Detector: Documentation] ✓ Parsed security.txt: ${parsedDocs.securityTxt.contact.length} contact(s), policy: ${parsedDocs.securityTxt.policy ? "yes" : "no"}`,
    );
  }
  console.log(
    `[Detector: Documentation] Extracted: ${parsedDocs.intendedUse.length} intended use, ${parsedDocs.limitations.length} limitations, ${parsedDocs.ethicalConsiderations.length} ethical considerations`,
  );

  return parsedDocs;
}

// ============================================================================
// RISK DETECTION
// ============================================================================
async function riskDetector({
  tree,
  getFileContent,
  allFindings = [],
  parsedDocs = null,
}) {
  console.log("[Detector: Risk] Starting risk assessment...");
  const findings = [];
  const risks = {
    vulnerabilities: [],
    deprecation: [],
    bias: [],
    limitations: [],
    ethical: [],
    missingDocs: [],
  };

  // Get parsed documentation if not provided
  if (!parsedDocs) {
    parsedDocs = await documentationParser({ tree, getFileContent });
  }

  // Track missing critical documentation (for analysis notes, not findings)
  const hasReadme = parsedDocs.files.some((f) =>
    f.toLowerCase().includes("readme"),
  );
  const hasModelCard = parsedDocs.files.some((f) =>
    f.toLowerCase().includes("model"),
  );
  const hasSecurity = parsedDocs.files.some((f) => {
    const lower = f.toLowerCase();
    return lower.includes("security") || lower.endsWith("security.txt");
  });

  if (!hasReadme) {
    risks.missingDocs.push("No README.md found");
  }
  if (!hasModelCard) {
    risks.missingDocs.push("No MODEL_CARD.md found");
  }
  if (!hasSecurity) {
    risks.missingDocs.push("No SECURITY.md or security.txt (RFC 9116) found");
  }

  // Check dependencies for known issues
  const depFindings = allFindings.filter((f) => f.category === "dependencies");
  for (const depFinding of depFindings) {
    const depName = depFinding.dependencyInfo?.name || "";
    const depVersion = depFinding.dependencyInfo?.version || "";

    // Check for deprecated packages (heuristic - would need actual vulnerability DB)
    if (depName.includes("deprecated") || depName.includes("legacy")) {
      risks.deprecation.push({
        package: depName,
        version: depVersion,
        note: "Package name suggests deprecation",
      });
    }
  }

  // Scan documentation for risk keywords
  const allDocText = [
    ...parsedDocs.intendedUse.map((d) => d.text),
    ...parsedDocs.limitations.map((d) => d.text),
    ...parsedDocs.ethicalConsiderations.map((d) => d.text),
    ...parsedDocs.biasInformation.map((d) => d.text),
    ...parsedDocs.securityNotes.map((d) => d.text),
  ]
    .join(" ")
    .toLowerCase();

  // Check for vulnerability mentions
  for (const keyword of RISK_KEYWORDS.vulnerabilities) {
    if (allDocText.includes(keyword.toLowerCase())) {
      risks.vulnerabilities.push({
        keyword,
        found: "Documentation mentions security concerns",
      });
    }
  }

  // Check for deprecation mentions
  for (const keyword of RISK_KEYWORDS.deprecation) {
    if (allDocText.includes(keyword.toLowerCase())) {
      risks.deprecation.push({
        keyword,
        found: "Documentation mentions deprecation",
      });
    }
  }

  // Check for bias/fairness mentions
  for (const keyword of RISK_KEYWORDS.bias) {
    if (allDocText.includes(keyword.toLowerCase())) {
      risks.bias.push({
        keyword,
        found: "Documentation discusses bias/fairness",
      });
    }
  }

  // Check for limitation mentions
  for (const keyword of RISK_KEYWORDS.limitations) {
    if (allDocText.includes(keyword.toLowerCase())) {
      risks.limitations.push({
        keyword,
        found: "Documentation lists limitations",
      });
    }
  }

  // Check for ethical mentions
  for (const keyword of RISK_KEYWORDS.ethical) {
    if (allDocText.includes(keyword.toLowerCase())) {
      risks.ethical.push({
        keyword,
        found: "Documentation addresses ethical considerations",
      });
    }
  }

  // Log missing documentation but don't create findings (AIBOM documents what IS found, not what's missing)
  if (risks.missingDocs.length > 0) {
    console.log(
      `[Detector: Risk] ℹ️  Missing documentation noted (not a finding): ${risks.missingDocs.join(", ")}`,
    );
  }

  // Create findings only for POSITIVE indicators (what we found)
  if (parsedDocs.intendedUse.length > 0) {
    console.log(
      `[Detector: Risk] ✓ Found ${parsedDocs.intendedUse.length} documented intended use`,
    );
    findings.push({
      id: "governance-intended-use-documented",
      title: "Intended Use Documented",
      category: "governance",
      severity: "info",
      weight: 0,
      description: `Model intended use is documented in ${parsedDocs.intendedUse.length} location(s)`,
      evidence: parsedDocs.intendedUse.slice(0, 3).map((u) => ({
        file: u.file,
        snippet: u.text.substring(0, 200),
      })),
      riskInfo: {
        type: "intended-use",
        count: parsedDocs.intendedUse.length,
      },
    });
  }

  if (parsedDocs.limitations.length > 0) {
    console.log(
      `[Detector: Risk] ✓ Found ${parsedDocs.limitations.length} documented limitations`,
    );
    findings.push({
      id: "risk-limitations-documented",
      title: "Limitations Documented",
      category: "governance",
      severity: "info",
      weight: 0,
      description: `Model limitations are documented in ${parsedDocs.limitations.length} location(s)`,
      evidence: parsedDocs.limitations.slice(0, 3).map((l) => ({
        file: l.file,
        snippet: l.text.substring(0, 200),
      })),
      riskInfo: {
        type: "limitations",
        count: parsedDocs.limitations.length,
      },
    });
  }

  if (parsedDocs.biasInformation.length > 0) {
    console.log(
      `[Detector: Risk] ✓ Found ${parsedDocs.biasInformation.length} bias/fairness discussions`,
    );
    findings.push({
      id: "risk-bias-documented",
      title: "Bias/Fairness Documented",
      category: "governance",
      severity: "info",
      weight: 0,
      description: `Bias and fairness considerations documented in ${parsedDocs.biasInformation.length} location(s)`,
      evidence: parsedDocs.biasInformation.slice(0, 3).map((b) => ({
        file: b.file,
        snippet: b.text.substring(0, 200),
      })),
      riskInfo: {
        type: "bias-fairness",
        count: parsedDocs.biasInformation.length,
      },
    });
  }

  if (parsedDocs.ethicalConsiderations.length > 0) {
    console.log(
      `[Detector: Risk] ✓ Found ${parsedDocs.ethicalConsiderations.length} ethical considerations`,
    );
    findings.push({
      id: "risk-ethics-documented",
      title: "Ethical Considerations Documented",
      category: "governance",
      severity: "info",
      weight: 0,
      description: `Ethical considerations documented in ${parsedDocs.ethicalConsiderations.length} location(s)`,
      evidence: parsedDocs.ethicalConsiderations.slice(0, 3).map((e) => ({
        file: e.file,
        snippet: e.text.substring(0, 200),
      })),
      riskInfo: {
        type: "ethical",
        count: parsedDocs.ethicalConsiderations.length,
      },
    });
  }

  // Check for bias and fairness assessment tools (positive governance indicator)
  const biasFairnessTools = [];
  for (const depFinding of depFindings) {
    const depName =
      depFinding.dependencyInfo?.name?.toLowerCase() ||
      depFinding.title.toLowerCase();

    for (const biasTool of BIAS_FAIRNESS_PATTERNS.dependencies) {
      if (depName.includes(biasTool.toLowerCase())) {
        biasFairnessTools.push({
          tool: biasTool,
          dependency: depFinding.dependencyInfo?.name || depFinding.title,
          version: depFinding.dependencyInfo?.version,
        });
      }
    }
  }

  // Check for bias/fairness patterns in code
  const codeFiles = tree
    .filter(
      (entry) =>
        entry.path.match(/\.(py|js|ts|java|scala|go|rs)$/) &&
        entry.type === "blob",
    )
    .slice(0, 50);

  for (const file of codeFiles) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    for (const pattern of BIAS_FAIRNESS_PATTERNS.patterns) {
      if (pattern.pattern.test(content)) {
        const existingTool = biasFairnessTools.find(
          (t) => t.tool === pattern.tool,
        );
        if (!existingTool) {
          biasFairnessTools.push({
            tool: pattern.tool,
            detectedIn: file.path,
            pattern: pattern.pattern.source,
          });
        }
      }
    }
  }

  if (biasFairnessTools.length > 0) {
    console.log(
      `[Detector: Risk] ✓ Found ${biasFairnessTools.length} bias/fairness assessment tools`,
    );
    findings.push({
      id: "governance-bias-fairness-tools",
      title: "Bias & Fairness Assessment Tools Detected",
      category: "governance",
      severity: "info",
      weight: 0,
      description: `Bias and fairness assessment tools detected: ${biasFairnessTools.map((t) => t.tool).join(", ")}`,
      evidence: biasFairnessTools.slice(0, 3).map((tool) => ({
        file: tool.detectedIn || "Dependencies",
        snippet: tool.dependency
          ? `Dependency: ${tool.dependency}`
          : `Pattern detected in code`,
      })),
      governanceInfo: {
        type: "bias_fairness_assessment",
        tools: biasFairnessTools,
      },
    });
  }

  console.log(`[Detector: Risk] Complete. Findings: ${findings.length}`);
  return { findings, risks, parsedDocs };
}

// ============================================================================
// PROTOCOL DETECTOR - MCP, A2A, and AI Plugin Systems
// ============================================================================

/**
 * Parse MCP server configuration and extract AI-relevant information
 */
function parseMcpServerConfig(serverName, serverConfig) {
  const info = {
    name: serverName,
    command: serverConfig.command || null,
    args: serverConfig.args || [],
    env: {},
    category: "unknown",
    provider: null,
    description: null,
    capabilities: [],
  };

  // Extract environment variables (redact sensitive values)
  if (serverConfig.env) {
    for (const [key, value] of Object.entries(serverConfig.env)) {
      // Don't include actual API key values, just note their presence
      if (
        key.toLowerCase().includes("key") ||
        key.toLowerCase().includes("token") ||
        key.toLowerCase().includes("secret")
      ) {
        info.env[key] = "[REDACTED]";
      } else {
        info.env[key] = value;
      }
    }
  }

  // Categorize based on server name and command
  const nameLower = serverName.toLowerCase();
  const commandStr = [info.command, ...(info.args || [])]
    .join(" ")
    .toLowerCase();

  // Database/Storage servers
  if (nameLower.includes("sqlite") || commandStr.includes("sqlite")) {
    info.category = "database";
    info.description = "SQLite database access via MCP";
    info.capabilities.push("database-query", "data-storage");
  } else if (
    nameLower.includes("postgres") ||
    commandStr.includes("postgres")
  ) {
    info.category = "database";
    info.description = "PostgreSQL database access via MCP";
    info.capabilities.push("database-query", "data-storage");
  } else if (nameLower.includes("redis") || commandStr.includes("redis")) {
    info.category = "database";
    info.description = "Redis cache/database access via MCP";
    info.capabilities.push("cache", "data-storage");
  }

  // File system servers
  else if (
    nameLower.includes("filesystem") ||
    nameLower.includes("fs") ||
    commandStr.includes("filesystem")
  ) {
    info.category = "filesystem";
    info.description = "Local filesystem access via MCP";
    info.capabilities.push("file-read", "file-write");
  }

  // Code/Development servers
  else if (nameLower.includes("github") || commandStr.includes("github")) {
    info.category = "code-platform";
    info.provider = "GitHub";
    info.description = "GitHub repository access via MCP";
    info.capabilities.push("code-read", "issue-management", "pr-management");
  } else if (nameLower.includes("gitlab") || commandStr.includes("gitlab")) {
    info.category = "code-platform";
    info.provider = "GitLab";
    info.description = "GitLab repository access via MCP";
    info.capabilities.push("code-read", "issue-management");
  } else if (nameLower.includes("git") || commandStr.includes("git")) {
    info.category = "version-control";
    info.description = "Git version control access via MCP";
    info.capabilities.push("code-read", "version-control");
  }

  // Communication/Collaboration servers
  else if (nameLower.includes("slack") || commandStr.includes("slack")) {
    info.category = "communication";
    info.provider = "Slack";
    info.description = "Slack workspace access via MCP";
    info.capabilities.push("messaging", "channel-access");
  } else if (nameLower.includes("discord") || commandStr.includes("discord")) {
    info.category = "communication";
    info.provider = "Discord";
    info.description = "Discord server access via MCP";
    info.capabilities.push("messaging");
  } else if (
    nameLower.includes("email") ||
    nameLower.includes("gmail") ||
    commandStr.includes("email")
  ) {
    info.category = "communication";
    info.description = "Email access via MCP";
    info.capabilities.push("email-read", "email-send");
  }

  // Search/Web servers
  else if (nameLower.includes("brave") || commandStr.includes("brave-search")) {
    info.category = "web-search";
    info.provider = "Brave";
    info.description = "Brave Search API access via MCP";
    info.capabilities.push("web-search");
  } else if (nameLower.includes("google") || commandStr.includes("google")) {
    info.category = "web-search";
    info.provider = "Google";
    info.description = "Google services access via MCP";
    info.capabilities.push("web-search", "google-services");
  } else if (
    nameLower.includes("fetch") ||
    nameLower.includes("http") ||
    commandStr.includes("fetch")
  ) {
    info.category = "web-access";
    info.description = "HTTP/Web fetch capabilities via MCP";
    info.capabilities.push("web-fetch", "api-access");
  } else if (
    nameLower.includes("puppeteer") ||
    nameLower.includes("playwright") ||
    nameLower.includes("browser")
  ) {
    info.category = "browser-automation";
    info.description = "Browser automation via MCP";
    info.capabilities.push("web-scraping", "browser-control");
  }

  // Memory/State servers
  else if (nameLower.includes("memory") || commandStr.includes("memory")) {
    info.category = "memory";
    info.description = "Persistent memory/state management via MCP";
    info.capabilities.push("state-management", "memory");
  }

  // AI/Reasoning servers
  else if (
    nameLower.includes("thinking") ||
    nameLower.includes("reasoning") ||
    commandStr.includes("sequential-thinking")
  ) {
    info.category = "ai-reasoning";
    info.description = "AI reasoning/thinking capabilities via MCP";
    info.capabilities.push("reasoning", "chain-of-thought");
  }

  // Cloud provider servers
  else if (
    nameLower.includes("aws") ||
    nameLower.includes("s3") ||
    commandStr.includes("aws")
  ) {
    info.category = "cloud";
    info.provider = "AWS";
    info.description = "AWS services access via MCP";
    info.capabilities.push("cloud-services");
  } else if (nameLower.includes("gcp") || nameLower.includes("google-cloud")) {
    info.category = "cloud";
    info.provider = "GCP";
    info.description = "Google Cloud services access via MCP";
    info.capabilities.push("cloud-services");
  } else if (nameLower.includes("azure") || commandStr.includes("azure")) {
    info.category = "cloud";
    info.provider = "Azure";
    info.description = "Azure services access via MCP";
    info.capabilities.push("cloud-services");
  }

  // Custom/NPX servers - try to extract package name
  else if (commandStr.includes("npx") || commandStr.includes("npm")) {
    const npmMatch = commandStr.match(/@[\w-]+\/[\w-]+|[\w-]+-mcp|mcp-[\w-]+/);
    if (npmMatch) {
      info.category = "npm-package";
      info.description = `NPM package MCP server: ${npmMatch[0]}`;
    }
  }

  // Python/uvx servers
  else if (commandStr.includes("uvx") || commandStr.includes("python")) {
    const pyMatch = commandStr.match(/mcp[_-][\w-]+|[\w-]+[_-]mcp/);
    if (pyMatch) {
      info.category = "python-package";
      info.description = `Python MCP server: ${pyMatch[0]}`;
    }
  }

  return info;
}

/**
 * Extract AI provider hints from MCP environment variables
 */
function extractAiProvidersFromEnv(env) {
  const providers = [];

  for (const key of Object.keys(env || {})) {
    const keyLower = key.toLowerCase();
    if (keyLower.includes("openai")) providers.push("OpenAI");
    else if (keyLower.includes("anthropic") || keyLower.includes("claude"))
      providers.push("Anthropic");
    else if (keyLower.includes("google") || keyLower.includes("gemini"))
      providers.push("Google");
    else if (keyLower.includes("azure")) providers.push("Azure");
    else if (keyLower.includes("cohere")) providers.push("Cohere");
    else if (keyLower.includes("huggingface") || keyLower.includes("hf_"))
      providers.push("HuggingFace");
  }

  return [...new Set(providers)];
}

async function protocolDetector({ tree, getFileContent }) {
  console.log("[Detector: Protocols] Starting AI protocol detection...");
  const findings = [];

  // Check for MCP configuration files
  const mcpConfigFiles = AI_PROTOCOL_PATTERNS.mcp.config_files;
  const a2aConfigFiles = AI_PROTOCOL_PATTERNS.a2a.config_files;
  const skConfigFiles = AI_PROTOCOL_PATTERNS.semantic_kernel.config_files;

  for (const entry of tree) {
    const fileName = entry.path.split("/").pop();
    const filePath = entry.path;

    // Check for MCP config files
    if (mcpConfigFiles.includes(fileName) || filePath.includes(".mcp/")) {
      console.log(`[Detector: Protocols] ✓ Found MCP config: ${filePath}`);
      const content = await getFileContent(filePath);

      let mcpServers = {};
      let parsedServers = [];
      let aiProviders = [];

      if (content) {
        try {
          const json = JSON.parse(content);

          // Extract MCP servers from various config formats
          if (json.mcpServers) {
            mcpServers = json.mcpServers;
          } else if (json["mcp-servers"]) {
            mcpServers = json["mcp-servers"];
          } else if (json.servers) {
            mcpServers = json.servers;
          }

          // Parse each server configuration
          for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
            const serverInfo = parseMcpServerConfig(serverName, serverConfig);
            parsedServers.push(serverInfo);

            // Extract AI provider hints from env vars
            const envProviders = extractAiProvidersFromEnv(serverConfig.env);
            aiProviders.push(...envProviders);

            console.log(
              `[Detector: Protocols]   → MCP Server: ${serverName} (${serverInfo.category})`,
            );
            if (serverInfo.capabilities.length > 0) {
              console.log(
                `[Detector: Protocols]     Capabilities: ${serverInfo.capabilities.join(", ")}`,
              );
            }
          }

          aiProviders = [...new Set(aiProviders)];
        } catch (e) {
          console.log(
            `[Detector: Protocols]   ⚠️ Could not parse JSON: ${e.message}`,
          );
        }
      }

      const serverNames = Object.keys(mcpServers);
      const serverCount = serverNames.length;

      // Create main MCP config finding
      let description = "MCP (Model Context Protocol) configuration detected";
      if (serverCount > 0) {
        const categories = [
          ...new Set(
            parsedServers.map((s) => s.category).filter((c) => c !== "unknown"),
          ),
        ];
        description = `MCP configuration with ${serverCount} server(s)`;
        if (categories.length > 0) {
          description += ` spanning ${categories.join(", ")}`;
        }
        if (aiProviders.length > 0) {
          description += `. AI providers detected: ${aiProviders.join(", ")}`;
        }
      }

      findings.push({
        id: `protocol-mcp-config-${filePath.replace(/[^a-zA-Z0-9]/g, "-")}`,
        title: "MCP (Model Context Protocol) Configuration",
        category: "protocol",
        severity: "high",
        weight: 5,
        description: description,
        evidence: [
          {
            file: filePath,
            snippet:
              serverCount > 0
                ? `Servers: ${serverNames.slice(0, 5).join(", ")}${serverCount > 5 ? ` (+${serverCount - 5} more)` : ""}`
                : "MCP config file",
          },
        ],
        protocolInfo: {
          type: "mcp",
          configFile: filePath,
          servers: serverNames,
          parsedServers: parsedServers,
          aiProviders: aiProviders,
          capabilities: [
            ...new Set(parsedServers.flatMap((s) => s.capabilities)),
          ],
        },
      });

      // Create individual findings for significant MCP servers
      for (const server of parsedServers) {
        if (server.category !== "unknown" && server.capabilities.length > 0) {
          findings.push({
            id: `protocol-mcp-server-${server.name.replace(/[^a-zA-Z0-9]/g, "-")}`,
            title: `MCP Server: ${server.name}`,
            category: "protocol",
            severity: "medium",
            weight: 2,
            description:
              server.description ||
              `MCP server providing ${server.category} capabilities`,
            evidence: [
              {
                file: filePath,
                snippet: `Command: ${server.command || "N/A"}, Capabilities: ${server.capabilities.join(", ")}`,
              },
            ],
            protocolInfo: {
              type: "mcp-server",
              serverName: server.name,
              serverCategory: server.category,
              provider: server.provider,
              capabilities: server.capabilities,
              command: server.command,
              hasEnvVars: Object.keys(server.env).length > 0,
            },
          });
        }
      }
    }

    // Check for A2A / Agent Protocol config files
    // Includes the A2A Agent Card convention: /.well-known/agent.json
    if (
      a2aConfigFiles.includes(fileName) ||
      filePath.includes(".agent-protocol/") ||
      filePath.endsWith(".well-known/agent.json") ||
      fileName === "agent-card.json"
    ) {
      console.log(
        `[Detector: Protocols] ✓ Found A2A/Agent Protocol config: ${filePath}`,
      );
      const a2aContent = await getFileContent(filePath);

      // Parse Agent Card fields when it is valid JSON
      let a2aDescription =
        "A2A/Agent Protocol configuration detected - enables agent communication";
      let agentCardInfo = null;
      if (a2aContent) {
        try {
          const card = JSON.parse(a2aContent);
          if (card && (card.name || card.url || card.skills)) {
            agentCardInfo = {
              name: card.name || null,
              url: card.url || null,
              version: card.version || null,
              skills: Array.isArray(card.skills)
                ? card.skills.map((s) => s?.name || s?.id).filter(Boolean)
                : [],
              capabilities: card.capabilities
                ? Object.keys(card.capabilities)
                : [],
            };
            a2aDescription = `A2A Agent Card detected: ${agentCardInfo.name || filePath}`;
            if (agentCardInfo.skills.length > 0) {
              a2aDescription += ` with ${agentCardInfo.skills.length} skill(s)`;
            }
          }
        } catch (e) {
          // Not JSON - keep generic description
        }
      }

      findings.push({
        id: `protocol-a2a-config-${filePath.replace(/[^a-zA-Z0-9]/g, "-")}`,
        title: "Agent-to-Agent Protocol Configuration",
        category: "protocol",
        severity: "high",
        weight: 4,
        description: a2aDescription,
        evidence: [
          {
            file: filePath,
            snippet: a2aContent
              ? a2aContent.split("\n").slice(0, 5).join("\n").substring(0, 200)
              : "Agent Protocol config file",
          },
        ],
        protocolInfo: {
          type: "a2a",
          configFile: filePath,
          agentCard: agentCardInfo,
        },
      });
    }

    // Check for Semantic Kernel config files
    if (skConfigFiles.includes(fileName)) {
      console.log(
        `[Detector: Protocols] ✓ Found Semantic Kernel config: ${filePath}`,
      );
      findings.push({
        id: `protocol-sk-config-${filePath.replace(/[^a-zA-Z0-9]/g, "-")}`,
        title: "Semantic Kernel Configuration",
        category: "protocol",
        severity: "medium",
        weight: 3,
        description:
          "Semantic Kernel configuration detected - LLM orchestration with plugins",
        evidence: [
          {
            file: filePath,
            snippet: "Semantic Kernel config file",
          },
        ],
        protocolInfo: {
          type: "semantic-kernel",
          configFile: filePath,
        },
      });
    }
  }

  // Scan code files for MCP/A2A usage patterns
  const codeExtensions = [".py", ".js", ".ts", ".tsx", ".jsx", ".mjs"];
  const codeFiles = tree
    .filter(
      (entry) =>
        codeExtensions.some((ext) => entry.path.endsWith(ext)) &&
        !entry.path.includes("node_modules") &&
        !entry.path.includes("__pycache__"),
    )
    .slice(0, 50); // Limit to avoid too many API calls

  const mcpPatterns = AI_PROTOCOL_PATTERNS.mcp.code_patterns;
  const a2aPatterns = AI_PROTOCOL_PATTERNS.a2a.code_patterns;
  const functionPatterns = AI_PROTOCOL_PATTERNS.function_calling.code_patterns;
  const semanticKernelPatterns =
    AI_PROTOCOL_PATTERNS.semantic_kernel.code_patterns;

  // Group MCP findings by type to avoid duplicate components
  const mcpFindings = new Map();

  for (const file of codeFiles) {
    const content = await getFileContent(file.path);
    if (!content) continue;

    // Check MCP patterns
    for (const patternDef of mcpPatterns) {
      if (patternDef.pattern.test(content)) {
        const match = content.match(patternDef.pattern);
        const lineNum = content
          .substring(0, content.indexOf(match[0]))
          .split("\n").length;

        const findingKey = `mcp-${patternDef.type.toLowerCase().replace(/\s+/g, "-")}`;

        if (!mcpFindings.has(findingKey)) {
          mcpFindings.set(findingKey, {
            title: `MCP ${patternDef.type} Usage`,
            category: "protocol",
            severity: "high",
            weight: 4,
            description: `Model Context Protocol (MCP) ${patternDef.type.toLowerCase()} implementation detected`,
            evidence: [],
            protocolInfo: {
              type: "mcp",
              subType: patternDef.type,
            },
          });
        }

        // Add evidence to existing finding
        mcpFindings.get(findingKey).evidence.push({
          file: file.path,
          line: lineNum,
          snippet: match[0].substring(0, 100),
        });
      }
    }

    // Check A2A patterns
    for (const patternDef of a2aPatterns) {
      if (patternDef.pattern.test(content)) {
        const match = content.match(patternDef.pattern);
        const lineNum = content
          .substring(0, content.indexOf(match[0]))
          .split("\n").length;

        findings.push({
          id: `protocol-a2a-code-${file.path.replace(/[^a-zA-Z0-9]/g, "-")}-${patternDef.type.replace(/\s+/g, "-")}`,
          title: `Agent Protocol ${patternDef.type} Usage`,
          category: "protocol",
          severity: "medium",
          weight: 3,
          description: `Agent-to-Agent (A2A) ${patternDef.type.toLowerCase()} implementation detected`,
          evidence: [
            {
              file: file.path,
              line: lineNum,
              snippet: match[0].substring(0, 100),
            },
          ],
          protocolInfo: {
            type: "a2a",
            subType: patternDef.type,
          },
        });
        break;
      }
    }

    // Check function calling patterns (indicates tool use capability)
    for (const patternDef of functionPatterns) {
      if (patternDef.pattern.test(content)) {
        const match = content.match(patternDef.pattern);
        const lineNum = content
          .substring(0, content.indexOf(match[0]))
          .split("\n").length;

        findings.push({
          id: `protocol-tools-${file.path.replace(/[^a-zA-Z0-9]/g, "-")}-${patternDef.type.replace(/\s+/g, "-")}`,
          title: `AI ${patternDef.type}`,
          category: "protocol",
          severity: "medium",
          weight: 3,
          description: `AI function/tool calling capability detected (${patternDef.type})`,
          evidence: [
            {
              file: file.path,
              line: lineNum,
              snippet: match[0].substring(0, 100),
            },
          ],
          protocolInfo: {
            type: "function-calling",
            subType: patternDef.type,
          },
        });
        break;
      }
    }

    // Check Semantic Kernel patterns (previously defined but never scanned)
    for (const patternDef of semanticKernelPatterns) {
      if (patternDef.pattern.test(content)) {
        const match = content.match(patternDef.pattern);
        const lineNum = content
          .substring(0, content.indexOf(match[0]))
          .split("\n").length;

        findings.push({
          id: `protocol-sk-code-${file.path.replace(/[^a-zA-Z0-9]/g, "-")}-${patternDef.type.replace(/\s+/g, "-")}`,
          title: `Semantic Kernel ${patternDef.type} Usage`,
          category: "protocol",
          severity: "medium",
          weight: 3,
          description: `Microsoft Semantic Kernel ${patternDef.type.toLowerCase()} detected - LLM orchestration with plugins`,
          evidence: [
            {
              file: file.path,
              line: lineNum,
              snippet: match[0].substring(0, 100),
            },
          ],
          protocolInfo: {
            type: "semantic-kernel",
            subType: patternDef.type,
          },
        });
        break;
      }
    }
  }

  // Add grouped MCP findings to main findings array
  for (const [findingKey, findingData] of mcpFindings) {
    findings.push({
      id: `protocol-mcp-${findingKey}`,
      title: findingData.title,
      category: findingData.category,
      severity: findingData.severity,
      weight: findingData.weight,
      description: findingData.description,
      evidence: findingData.evidence,
      protocolInfo: findingData.protocolInfo,
    });
  }

  // Deduplicate findings by ID
  const uniqueFindings = [...new Map(findings.map((f) => [f.id, f])).values()];

  console.log(
    `[Detector: Protocols] Complete. Findings: ${uniqueFindings.length}`,
  );
  return { findings: uniqueFindings };
}

// ============================================================================
// AI DEV TOOLS DETECTOR - Cursor, Claude Code, Copilot, Aider, etc.
// Low confidence findings - indicates AI-assisted development
// ============================================================================
async function aiDevToolsDetector({ tree, getFileContent }) {
  console.log(
    "[Detector: AI Dev Tools] Starting AI development tools detection...",
  );
  const findings = [];

  const configFiles = AI_DEV_TOOLS.ide_copilots.config_files;
  const vscodeExtensions = AI_DEV_TOOLS.ide_copilots.vscode_extensions;

  // Check for AI dev tool config files
  for (const entry of tree) {
    const fileName = entry.path.split("/").pop();
    const filePath = entry.path;

    // Direct config file matches
    for (const configFile of configFiles) {
      if (
        filePath === configFile ||
        fileName === configFile ||
        filePath.endsWith("/" + configFile)
      ) {
        console.log(
          `[Detector: AI Dev Tools] ✓ Found AI tool config: ${filePath}`,
        );

        let toolName = "AI Development Tool";
        let description = "AI-assisted development tool configuration detected";

        // Identify specific tool
        if (
          configFile.includes("cursor") ||
          configFile.includes(".cursorrules")
        ) {
          toolName = "Cursor IDE";
          description =
            "Cursor IDE configuration - AI-first code editor built on VSCode";
        } else if (configFile.includes("copilot")) {
          toolName = "GitHub Copilot";
          description =
            "GitHub Copilot configuration - AI pair programming assistant";
        } else if (configFile.includes("aider")) {
          toolName = "Aider";
          description = "Aider configuration - AI pair programming in terminal";
        } else if (configFile.includes("continue")) {
          toolName = "Continue.dev";
          description =
            "Continue.dev configuration - open-source AI code assistant";
        } else if (configFile.includes("cody")) {
          toolName = "Sourcegraph Cody";
          description = "Sourcegraph Cody configuration - AI coding assistant";
        } else if (
          configFile.includes("windsurf") ||
          configFile.includes("codeium")
        ) {
          toolName = "Codeium/Windsurf";
          description = "Codeium/Windsurf configuration - AI code acceleration";
        } else if (configFile.includes("tabnine")) {
          toolName = "TabNine";
          description = "TabNine configuration - AI code completion";
        } else if (configFile.includes("amazonq")) {
          toolName = "Amazon Q";
          description = "Amazon Q configuration - AWS AI assistant";
        } else if (configFile.toLowerCase().includes("claude")) {
          toolName = "Claude Code";
          description =
            "Claude Code conventions file - Anthropic AI coding assistant";
        }

        findings.push({
          id: `aidev-config-${filePath.replace(/[^a-zA-Z0-9]/g, "-")}`,
          title: `${toolName} Configuration`,
          category: "ai-dev-tools",
          severity: "low", // Low confidence - just indicates AI-assisted development
          weight: 1,
          description: description,
          evidence: [
            {
              file: filePath,
              snippet: `${toolName} config file`,
            },
          ],
          devToolInfo: {
            tool: toolName,
            configFile: filePath,
            confidence: "low",
            note: "Indicates AI-assisted development, not AI functionality in the project",
          },
        });
        break;
      }
    }

    // Check for .vscode/extensions.json for recommended AI extensions
    if (
      filePath === ".vscode/extensions.json" ||
      filePath.endsWith("/.vscode/extensions.json")
    ) {
      const content = await getFileContent(filePath);
      if (content) {
        try {
          const json = JSON.parse(content);
          const recommendations = json.recommendations || [];
          const aiExtensions = recommendations.filter((ext) =>
            vscodeExtensions.some((aiExt) =>
              ext.toLowerCase().includes(aiExt.toLowerCase()),
            ),
          );

          if (aiExtensions.length > 0) {
            console.log(
              `[Detector: AI Dev Tools] ✓ Found ${aiExtensions.length} AI VSCode extensions recommended`,
            );
            findings.push({
              id: "aidev-vscode-extensions",
              title: "AI VSCode Extensions Recommended",
              category: "ai-dev-tools",
              severity: "low",
              weight: 1,
              description: `${aiExtensions.length} AI-powered VSCode extension(s) recommended: ${aiExtensions.join(", ")}`,
              evidence: [
                {
                  file: filePath,
                  snippet: aiExtensions.join(", "),
                },
              ],
              devToolInfo: {
                tool: "VSCode AI Extensions",
                extensions: aiExtensions,
                confidence: "low",
                note: "Recommended extensions for AI-assisted development",
              },
            });
          }
        } catch (e) {
          // Invalid JSON, skip
        }
      }
    }
  }

  // Check for AI dev tool dependencies in package.json
  const packageJsonFiles = tree.filter((entry) =>
    entry.path.endsWith("package.json"),
  );
  for (const pkg of packageJsonFiles) {
    const content = await getFileContent(pkg.path);
    if (!content) continue;

    try {
      const json = JSON.parse(content);
      const allDeps = {
        ...json.dependencies,
        ...json.devDependencies,
      };

      const aiDevDeps = AI_DEV_TOOLS.ide_copilots.node || [];
      const codeGenDeps = AI_DEV_TOOLS.code_gen_tools?.node || [];
      const testingDeps = AI_DEV_TOOLS.testing_tools?.node || [];

      const foundDeps = Object.keys(allDeps).filter((dep) =>
        [...aiDevDeps, ...codeGenDeps, ...testingDeps].some((aiDep) =>
          dep.toLowerCase().includes(aiDep.toLowerCase()),
        ),
      );

      if (foundDeps.length > 0) {
        console.log(
          `[Detector: AI Dev Tools] ✓ Found ${foundDeps.length} AI dev tool dependencies`,
        );
        findings.push({
          id: `aidev-deps-${pkg.path.replace(/[^a-zA-Z0-9]/g, "-")}`,
          title: "AI Development Tool Dependencies",
          category: "ai-dev-tools",
          severity: "low",
          weight: 1,
          description: `AI development tool dependencies: ${foundDeps.join(", ")}`,
          evidence: [
            {
              file: pkg.path,
              snippet: foundDeps.join(", "),
            },
          ],
          devToolInfo: {
            tool: "AI Dev Dependencies",
            dependencies: foundDeps,
            confidence: "low",
          },
        });
      }
    } catch (e) {
      // Invalid JSON
    }
  }

  // Check for AI dev tool dependencies in requirements.txt / pyproject.toml
  const pythonManifests = tree.filter(
    (entry) =>
      entry.path.endsWith("requirements.txt") ||
      entry.path.endsWith("pyproject.toml") ||
      entry.path.endsWith("requirements-dev.txt"),
  );

  const pythonAiDevDeps = [
    ...(AI_DEV_TOOLS.ide_copilots.python || []),
    ...(AI_DEV_TOOLS.code_gen_tools?.python || []),
    ...(AI_DEV_TOOLS.testing_tools?.python || []),
  ];

  for (const manifest of pythonManifests) {
    const content = await getFileContent(manifest.path);
    if (!content) continue;

    const foundDeps = pythonAiDevDeps.filter((dep) =>
      content.toLowerCase().includes(dep.toLowerCase()),
    );

    if (foundDeps.length > 0) {
      console.log(
        `[Detector: AI Dev Tools] ✓ Found ${foundDeps.length} Python AI dev tool dependencies`,
      );
      findings.push({
        id: `aidev-python-${manifest.path.replace(/[^a-zA-Z0-9]/g, "-")}`,
        title: "Python AI Development Tool Dependencies",
        category: "ai-dev-tools",
        severity: "low",
        weight: 1,
        description: `Python AI development tool dependencies: ${foundDeps.join(", ")}`,
        evidence: [
          {
            file: manifest.path,
            snippet: foundDeps.join(", "),
          },
        ],
        devToolInfo: {
          tool: "Python AI Dev Dependencies",
          dependencies: foundDeps,
          confidence: "low",
        },
      });
    }
  }

  // Deduplicate
  const uniqueFindings = [...new Map(findings.map((f) => [f.id, f])).values()];

  console.log(
    `[Detector: AI Dev Tools] Complete. Findings: ${uniqueFindings.length}`,
  );
  return { findings: uniqueFindings };
}

// ============================================================================
// SCORING
// ============================================================================
