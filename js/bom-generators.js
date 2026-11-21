// Model Card Loading Utility
// Cache for loaded model cards to avoid multiple fetches
const modelCardCache = new Map();

async function loadModelCard(modelName, provider) {
    try {
        // Normalize provider name to match directory structure
        const normalizedProvider = provider.toLowerCase();
        // Normalize model name to match filename - keep dots for version numbers
        const normalizedModelName = modelName.toLowerCase()
            .replace(/[^a-z0-9.-]/g, '-')  // Keep dots and hyphens
            .replace(/-+/g, '-')           // Collapse multiple hyphens
            .replace(/^-|-$/g, '');        // Remove leading/trailing hyphens

        // Create cache key
        const cacheKey = `${normalizedProvider}/${normalizedModelName}`;

        // Check cache first
        if (modelCardCache.has(cacheKey)) {
            console.log(`[ModelCard] Using cached model card for ${modelName}`);
            return modelCardCache.get(cacheKey);
        }

        // Construct the path to the model card JSON file
        const modelCardPath = `modelcards/${normalizedProvider}/${normalizedModelName}.json`;

        console.log(`[ModelCard] Attempting to load: ${modelCardPath}`);

        // Fetch the model card JSON
        const response = await fetch(modelCardPath);

        if (!response.ok) {
            console.log(`[ModelCard] Model card not found: ${modelCardPath}`);
            return null;
        }

        const modelCardData = await response.json();
        console.log(`[ModelCard] Successfully loaded and cached model card for ${modelName}`);

        // Cache the result
        modelCardCache.set(cacheKey, modelCardData);

        return modelCardData;

    } catch (error) {
        console.log(`[ModelCard] Error loading model card for ${modelName}: ${error.message}`);
        return null;
    }
}

// BOM Generator functions (CycloneDX & SPDX)
async function generateCycloneDXJson(analysisResult, selectedFindings) {
    const { repository, analyzedAt } = analysisResult;
    const uuid = generateUUID();
    
    const bom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        version: 1,
        serialNumber: `urn:uuid:${uuid}`,
        metadata: {
            timestamp: analyzedAt,
            // R3: explicit header self-descriptions (OWASP Part 1 / G7 #8) —
            // declare scope, completeness, generation context and authorship
            // instead of letting silence imply producer assertions.
            lifecycles: [{ phase: 'post-build' }],
            properties: [
                {
                    name: 'aibom:scope',
                    value: `repository static source analysis (${repository.fullName}@${repository.scannedRef || 'main'})`
                },
                {
                    name: 'aibom:completeness',
                    value: 'partial — post-build source-level analysis; training-time observation not possible'
                },
                {
                    name: 'aibom:generation-context',
                    value: 'after-build'
                },
                {
                    name: 'aibom:authorship',
                    value: 'tool-generated'
                },
                {
                    name: 'aibom:graph-type',
                    value: 'static dependency graph (source + manifest + SBOM analysis)'
                },
                {
                    name: 'aibom:attestation',
                    value: getAttestationState(selectedFindings, analysisResult)
                }
            ],
            tools: {
                components: [{
                    type: 'application',
                    'bom-ref': 'tool-aibom-generator',
                    name: 'AI BOM Generator',
                    version: '1.0.0',
                    description: 'Automated AI/LLM detection and SBOM generation tool',
                    externalReferences: [{
                        type: 'website',
                        url: 'https://github.com/cyfinoid/aibom-generator'
                    }]
                }]
            },
            component: {
                type: 'application',
                'bom-ref': `repo-${repository.owner}-${repository.repo}`,
                group: repository.owner,
                name: repository.repo,
                version: 'main',
                description: repository.description || '',
                purl: `pkg:github/${repository.owner}/${repository.repo}`,
                externalReferences: [
                    {
                        type: 'vcs',
                        url: repository.htmlUrl
                    },
                    {
                        type: 'website',
                        url: repository.htmlUrl
                    }
                ],
                properties: [
                    { name: 'github:topics', value: repository.topics.join(', ') },
                    { name: 'github:languages', value: repository.languages.join(', ') }
                ]
            }
        },
        components: [],
        services: [],
        dependencies: []
    };

    // Group findings to create proper ML model components
    console.log('[BOM Generator] Creating components from findings...');
    const { components: modelComponents, modelRefs, libraryRefs, mcpRefs, hardwareInfo, infraInfo, governanceInfo, protocolInfo } = await createMLModelComponents(selectedFindings);
    
    // Add MCP/Protocol properties to main component
    if (protocolInfo && protocolInfo.detected) {
        bom.metadata.component.properties.push({
            name: 'aibom:mcp:detected',
            value: 'true'
        });
        if (protocolInfo.mcpServers.length > 0) {
            bom.metadata.component.properties.push({
                name: 'aibom:mcp:servers',
                value: protocolInfo.mcpServers.join(', ')
            });
            bom.metadata.component.properties.push({
                name: 'aibom:mcp:server-count',
                value: protocolInfo.mcpServers.length.toString()
            });
        }
        if (protocolInfo.mcpCapabilities.length > 0) {
            bom.metadata.component.properties.push({
                name: 'aibom:mcp:capabilities',
                value: protocolInfo.mcpCapabilities.join(', ')
            });
        }
        if (protocolInfo.aiProviders.length > 0) {
            bom.metadata.component.properties.push({
                name: 'aibom:mcp:ai-providers',
                value: protocolInfo.aiProviders.join(', ')
            });
        }
        if (protocolInfo.hasA2A) {
            bom.metadata.component.properties.push({
                name: 'aibom:a2a:detected',
                value: 'true'
            });
        }
        if (protocolInfo.hasFunctionCalling) {
            bom.metadata.component.properties.push({
                name: 'aibom:function-calling:detected',
                value: 'true'
            });
        }
    }
    
    // Add hardware and infrastructure properties to main component
    if (hardwareInfo.detected) {
        bom.metadata.component.properties.push({
            name: 'aibom:hardware:detected',
            value: 'true'
        });
        if (hardwareInfo.types.length > 0) {
            bom.metadata.component.properties.push({
                name: 'aibom:hardware:types',
                value: hardwareInfo.types.join(', ')
            });
        }
        if (hardwareInfo.models.length > 0) {
            bom.metadata.component.properties.push({
                name: 'aibom:hardware:models',
                value: hardwareInfo.models.join(', ')
            });
        }
        if (hardwareInfo.libraries.length > 0) {
            bom.metadata.component.properties.push({
                name: 'aibom:hardware:libraries',
                value: hardwareInfo.libraries.join(', ')
            });
        }
    }
    
    if (infraInfo.detected) {
        bom.metadata.component.properties.push({
            name: 'aibom:infrastructure:detected',
            value: 'true'
        });
        const allPlatforms = [
            ...infraInfo.platforms.containerization,
            ...infraInfo.platforms.orchestration,
            ...infraInfo.platforms.cloud,
            ...infraInfo.platforms.mlops
        ];
        if (allPlatforms.length > 0) {
            bom.metadata.component.properties.push({
                name: 'aibom:infrastructure:platforms',
                value: allPlatforms.join(', ')
            });
        }
    }
    
    // Add AI-specific metadata properties from detected models
    const modelMetadata = extractModelMetadata(selectedFindings);
    if (modelMetadata.primaryPurpose) {
        bom.metadata.component.properties.push({
            name: 'aibom:primaryPurpose',
            value: modelMetadata.primaryPurpose
        });
    }
    if (modelMetadata.suppliedBy) {
        bom.metadata.component.properties.push({
            name: 'aibom:suppliedBy',
            value: modelMetadata.suppliedBy
        });
    }
    if (modelMetadata.typeOfModel) {
        bom.metadata.component.properties.push({
            name: 'aibom:typeOfModel',
            value: modelMetadata.typeOfModel
        });
    }
    if (modelMetadata.domain) {
        bom.metadata.component.properties.push({
            name: 'aibom:domain',
            value: modelMetadata.domain
        });
    }
    
    if (governanceInfo.count > 0) {
        bom.metadata.component.properties.push({
            name: 'aibom:governance:documented',
            value: 'true'
        });
        if (governanceInfo.hasLimitations) {
            bom.metadata.component.properties.push({
                name: 'aibom:governance:limitations',
                value: 'documented'
            });
        }
        if (governanceInfo.hasBiasFairness) {
            bom.metadata.component.properties.push({
                name: 'aibom:governance:bias-fairness',
                value: 'documented'
            });
        }
        if (governanceInfo.hasEthical) {
            bom.metadata.component.properties.push({
                name: 'aibom:governance:ethical',
                value: 'documented'
            });
        }
    }
    
    console.log(`[BOM Generator] Created ${modelRefs.length} ML model components`);
    console.log(`[BOM Generator] Created ${libraryRefs.length} library components`);
    console.log(`[BOM Generator] Created ${mcpRefs ? mcpRefs.length : 0} MCP server components`);
    modelRefs.forEach(m => {
        console.log(`  - Model: ${m.component.name} (${m.component.author})`);
    });
    libraryRefs.forEach(l => {
        console.log(`  - Library: ${l.name}`);
    });
    if (mcpRefs && mcpRefs.length > 0) {
        mcpRefs.forEach(mcp => {
            console.log(`  - MCP Server: ${mcp.name}`);
        });
    }
    
    bom.components = modelComponents;
    
    // Create dependency relationships
    const mainRef = `repo-${repository.owner}-${repository.repo}`;
    const libraryRefIds = libraryRefs.map(l => l['bom-ref']);
    
    // Main repo depends on all direct components
    bom.dependencies.push({
        ref: mainRef,
        dependsOn: bom.components.map(c => c['bom-ref'])
    });

    // External AI services: cloud models are consumed through third-party
    // inference APIs — represent them as CycloneDX services (trust boundary)
    // and wire the graph: repo → service, model → service.
    const serviceRefsByProvider = {};
    modelRefs.forEach(model => {
        const provider = model.component.author;
        const svcDef = provider && typeof AI_SERVICE_ENDPOINTS !== 'undefined'
            ? AI_SERVICE_ENDPOINTS[provider] : null;
        if (!svcDef) return;
        if (!serviceRefsByProvider[provider]) {
            const serviceRef = `service-${provider.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
            serviceRefsByProvider[provider] = serviceRef;
            bom.services.push({
                'bom-ref': serviceRef,
                provider: { name: provider },
                name: svcDef.service,
                description: `External ${provider} inference API consumed by this application (third-party trust boundary)`,
                endpoints: svcDef.endpoints.slice(),
                authenticated: true,
                externalReferences: [{ type: 'documentation', url: svcDef.docs }]
            });
        }
    });

    const serviceRefs = Object.values(serviceRefsByProvider);
    if (serviceRefs.length > 0) {
        bom.dependencies.find(d => d.ref === mainRef).dependsOn.push(...serviceRefs);
    }

    // ML models depend on their framework libraries and their inference service
    modelRefs.forEach(model => {
        const deps = [];

        // The model is accessed through the provider's external API
        const provider = model.component.author;
        if (provider && serviceRefsByProvider[provider]) {
            deps.push(serviceRefsByProvider[provider]);
        }

        // Check if model uses known libraries
        const modelComp = model.component;
        if (modelComp.properties) {
            const category = modelComp.properties.find(p => p.name === 'category')?.value;

            // Add library dependencies based on model type
            if (category === 'text-generation' || category === 'feature-extraction') {
                if (libraryRefIds.includes('lib-transformers')) deps.push('lib-transformers');
                if (libraryRefIds.includes('lib-pytorch')) deps.push('lib-pytorch');
            } else if (category === 'text-to-image') {
                if (libraryRefIds.includes('lib-diffusers')) deps.push('lib-diffusers');
                if (libraryRefIds.includes('lib-pytorch')) deps.push('lib-pytorch');
            }
        }

        bom.dependencies.push({
            ref: model.bomRef,
            dependsOn: deps
        });
    });
    
    // Libraries have no dependencies (or can depend on each other)
    libraryRefs.forEach(lib => {
        bom.dependencies.push({
            ref: lib['bom-ref'],
            dependsOn: []
        });
    });
    
    return JSON.stringify(bom, null, 2);
}

/**
 * Extract a string list from a structured model-card field (e.g.
 * intendedUse.primaryUses, limitations.knownLimitations). Returns [] when the
 * field is absent or carries no readable strings. Falls back to splitting a
 * plain string value on '; ' when `allowStringFallback` is set (off for
 * out-of-scope extraction — a flat intended-use string is never out-of-scope
 * data).
 * @param {Object|string|null} field Raw card field
 * @param {string[]} keys Object keys to read, in order
 * @param {boolean} [allowStringFallback=true] Split plain-string fields
 * @returns {string[]}
 */
function structuredCardList(field, keys, allowStringFallback = true) {
  if (field === null || field === undefined) return [];
  if (typeof field === 'string') {
    return allowStringFallback
      ? field.split(';').map((s) => s.trim()).filter(Boolean)
      : [];
  }
  if (typeof field !== 'object') return [];
  for (const key of keys) {
    const value = field[key];
    if (Array.isArray(value)) {
      const items = value.filter((v) => typeof v === 'string' && v.trim()).map((v) => v.trim());
      if (items.length > 0) return items;
    } else if (typeof value === 'string' && value.trim()) {
      return value.split(';').map((s) => s.trim()).filter(Boolean);
    }
  }
  return [];
}

/**
 * Resolve a clean library identity for a dependency finding. Prefers the
 * structured `dependencyInfo` the dependencies detector attaches; falls back
 * to parsing the "Dependency: <name>" title and "(version: <x>)" description.
 * Returns version: null when unknown — no invented versions.
 * @param {Object} finding
 * @returns {{name: string, version: string|null, ecosystem: string|null}}
 */
function resolveLibraryIdentity(finding) {
  const info = finding.dependencyInfo || null;
  let name = info?.name || null;
  let version = info?.version || null;
  let ecosystem = info?.ecosystem || null;

  if (!name) {
    const titleMatch = (finding.title || '').match(/^Dependency:\s*(.+)$/i);
    name = titleMatch ? titleMatch[1].trim() : finding.title;
  }
  if (!version || version === 'unknown' || version === 'detected') {
    const descMatch = (finding.description || '').match(/\(version:\s*([^)]+)\)/i);
    version = descMatch ? descMatch[1].trim() : null;
  }
  if (!version) version = null;

  return { name: String(name), version, ecosystem: ecosystem || null };
}

/**
 * Build a Package URL for a resolved library identity. Version omitted when
 * unknown. Maven names ("group:artifact") map to group/artifact layout.
 * @param {string} name Clean package name
 * @param {string|null} version Version or null
 * @param {string|null} ecosystem Ecosystem from the detector (python, npm, go, maven, rust...)
 * @returns {string|null} purl or null when the ecosystem is unknown
 */
function buildLibraryPurl(name, version, ecosystem) {
  if (!name || !ecosystem) return null;
  const eco = String(ecosystem).toLowerCase();
  const typeMap = {
    python: 'pypi',
    pypi: 'pypi',
    npm: 'npm',
    node: 'npm',
    go: 'golang',
    golang: 'golang',
    maven: 'maven',
    java: 'maven',
    gradle: 'maven',
    rust: 'cargo',
    cargo: 'cargo'
  };
  const type = typeMap[eco];
  if (!type) return null;

  let purl;
  if (type === 'maven' && name.includes(':')) {
    const [group, artifact] = name.split(':');
    purl = `pkg:maven/${group}/${artifact}`;
  } else if (type === 'golang') {
    purl = `pkg:golang/${name}`;
  } else if (type === 'npm' && name.startsWith('@')) {
    // purl spec: npm scopes encode the leading @ as %40 but keep '/' as the
    // namespace separator (pkg:npm/%40langchain/community@1.2.3)
    purl = `pkg:npm/${name.replace(/^@/, '%40')}`;
  } else {
    purl = `pkg:${type}/${name}`;
  }
  return version ? `${purl}@${encodeURIComponent(version)}` : purl;
}

/**
 * Build native CycloneDX evidence (identity + occurrences) from a finding.
 * Technique/confidence: structured manifest provenance → manifest-analysis
 * (0.9); source imports → source-code-analysis (0.7); code detections map
 * severity high/medium/low → 0.9/0.7/0.5. Occurrences come from evidence
 * entries that carry a real line number; snippets ride along as
 * additionalContext. Returns null when there is nothing usable.
 * @param {Object} finding
 * @returns {Object|null} CycloneDX evidence object
 */
function buildNativeEvidence(finding) {
  let technique;
  let confidence;
  if (finding.dependencyInfo?.source === 'github-sbom-api' || finding.dependencyInfo?.source === 'manual-parsing') {
    technique = 'manifest-analysis';
    confidence = 0.9;
  } else if (finding.dependencyInfo?.source === 'source-import-analysis') {
    technique = 'source-code-analysis';
    confidence = 0.7;
  } else {
    technique = 'source-code-analysis';
    confidence = finding.severity === 'high' ? 0.9 : (finding.severity === 'medium' ? 0.7 : 0.5);
  }

  const evidence = {
    identity: [{
      field: 'name',
      confidence,
      methods: [{ technique, confidence }]
    }]
  };

  const occurrences = (finding.evidence || [])
    .filter((ev) => ev.file && ev.line && ev.line > 0)
    .map((ev) => {
      const occ = { location: ev.file, line: ev.line };
      if (ev.snippet) occ.additionalContext = ev.snippet;
      return occ;
    });
  if (occurrences.length > 0) {
    evidence.occurrences = occurrences;
  }

  return evidence;
}

/**
 * Push a name/value property onto a modelCard.properties array only when the
 * same name+value pair is not already present (prevents duplicate
 * aibom:model-type etc. when both a local card and HF config provide it).
 */
function pushPropertyOnce(modelCard, name, value) {
  if (!modelCard.properties.some((p) => p.name === name && p.value === value)) {
    modelCard.properties.push({ name, value });
  }
}

/**
 * R1: score how strongly an artifact path matches a model name. Filename
 * token hit = 2, directory hit = 1. Generic path words (models/weights/
 * checkpoints…) can't vouch for identity — every artifact lives under them.
 * Tokens ≥3 chars so short ids like gpt-4o still match via 'gpt'.
 * @param {Object} artifact {path, ...}
 * @param {string} modelName
 * @returns {number}
 */
function artifactMatchScore(artifact, modelName) {
  const GENERIC = new Set(['models', 'model', 'weights', 'weight', 'checkpoints', 'checkpoint', 'artifacts', 'artifact', 'pretrained', 'saved']);
  const tokens = String(modelName)
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length >= 3 && !GENERIC.has(t));
  const pathLower = String(artifact.path).toLowerCase();
  const fileNameLower = pathLower.split('/').pop();
  let score = 0;
  for (const token of tokens) {
    if (fileNameLower.includes(token)) score += 2;
    else if (pathLower.includes(token)) score += 1;
  }
  return score;
}

/**
 * R1: pick the best-matching artifact for a model (score ≥ 2 required — a
 * filename hit or two directory hits — so a generic directory token alone
 * never produces a hash claim; emitting another file's hash as a model's
 * integrity claim is worse than emitting none).
 * @param {Array} artifacts [{path, sha256, sizeBytes, source}]
 * @param {string} modelName Model identifier from the finding
 * @returns {Object|null}
 */
function findArtifactForModel(artifacts, modelName) {
  if (!artifacts || artifacts.length === 0 || !modelName) return null;
  let best = null;
  let bestScore = 0;
  for (const artifact of artifacts) {
    const score = artifactMatchScore(artifact, modelName);
    if (score > bestScore) {
      bestScore = score;
      best = artifact;
    }
  }
  return bestScore >= 2 ? best : null;
}

/**
 * R4: attestation presence state for the scanned repository, recorded
 * explicitly in the BOM metadata (detected types or an honest "none found").
 * Derived from ALL scan findings — not the user's current selection — so
 * deselecting the attestation finding can never flip the recorded state to a
 * false "none found".
 * @param {Array} selectedFindings
 * @param {Object} [analysisResult] full analysis result (carries all findings)
 * @returns {string}
 */
function getAttestationState(selectedFindings, analysisResult) {
  const pool = (analysisResult && Array.isArray(analysisResult.findings) && analysisResult.findings.length > 0)
    ? analysisResult.findings
    : (selectedFindings || []);
  const attested = pool.find((f) => f.attestationInfo?.detected);
  if (attested) {
    return `detected: ${attested.attestationInfo.types.join(', ')}`;
  }
  return 'none found in repository scan';
}

async function createMLModelComponents(findings) {
    const components = [];
    const modelMap = new Map();
    const libraryDeps = new Set(); // Track required libraries
    
    // Extract hardware and infrastructure info for metadata
    const hardwareInfo = extractHardwareInfo(findings);
    const infraInfo = extractInfraInfo(findings);
    const governanceInfo = extractGovernanceInfo(findings);
    
    for (const finding of findings) {
        // Extract actual model information
        if (finding.modelInfo) {
            // This is a specific model finding
            const { provider, modelName, modelType, huggingface, files, detectionSource, relatedModels, modelCardData } = finding.modelInfo;
            const key = `${provider}-${modelName}`;
            
            if (!modelMap.has(key)) {
                const bomRef = `model-${generateShortId()}`;
                const component = {
                    type: 'machine-learning-model',
                    'bom-ref': bomRef,
                    author: provider,
                    name: modelName,
                    // No invented version: source identifiers don't pin one and
                    // local cards carry no version field. Unknown stays unknown
                    // (properties below record why), per model-identity guidance.
                    description: finding.description,
                    scope: 'required',
                    properties: [
                        {
                            name: 'aibom:model:version-status',
                            value: modelCardData?.version ? 'derived-from-model-card' : 'unpinned-in-source'
                        }
                    ]
                };
                if (modelCardData?.version) {
                    component.version = String(modelCardData.version);
                }
                
                // Add detection source if available
                if (detectionSource) {
                    component.properties.push({
                        name: 'cdx:detection:source',
                        value: detectionSource
                    });
                }
                
                // Add related models information if available
                if (relatedModels && relatedModels.length > 0) {
                    component.properties.push({
                        name: 'cdx:related:models',
                        value: JSON.stringify(relatedModels)
                    });
                }
                
                // Add ML category property (use explicit type if available)
                if (modelType && modelType !== 'unknown') {
                    component.properties.push({
                        name: 'category',
                        value: modelType
                    });
                } else if (huggingface?.pipeline_tag) {
                    component.properties.push({
                        name: 'category',
                        value: huggingface.pipeline_tag
                    });
                } else if (modelName.includes('gpt')) {
                    component.properties.push({ name: 'category', value: 'text-generation' });
                } else if (modelName.includes('embed')) {
                    component.properties.push({ name: 'category', value: 'embeddings' });
                }
                
                // Add purl if applicable
                if (provider === 'HuggingFace' && huggingface) {
                    component.purl = `pkg:huggingface/${modelName}`;
                    component.group = huggingface.author || modelName.split('/')[0];
                    component.name = modelName.split('/').pop();
                } else if (provider === 'OpenAI') {
                    component.purl = `pkg:ml/openai/${modelName}`;
                } else if (provider === 'Anthropic') {
                    component.purl = `pkg:ml/anthropic/${modelName}`;
                } else if (provider === 'Google') {
                    component.purl = `pkg:ml/google/${modelName}`;
                }
                
                // Add intended use based on model type and provider
                if (modelType === 'text-generation') {
                    component.properties.push({
                        name: 'intended-use',
                        value: 'Text generation, chat completion, and language understanding'
                    });
                } else if (modelType === 'embeddings') {
                    component.properties.push({
                        name: 'intended-use',
                        value: 'Text embeddings for semantic search, similarity, and vector databases'
                    });
                } else if (modelType === 'text-to-image') {
                    component.properties.push({
                        name: 'intended-use',
                        value: 'Image generation from text descriptions'
                    });
                } else if (provider === 'OpenAI') {
                    component.properties.push({
                        name: 'intended-use',
                        value: 'General purpose AI model from OpenAI'
                    });
                } else if (provider === 'Anthropic') {
                    component.properties.push({
                        name: 'intended-use',
                        value: 'Safe and helpful AI assistant for various text tasks'
                    });
                } else if (provider === 'Google') {
                    component.properties.push({
                        name: 'intended-use',
                        value: 'Google AI model for various AI tasks'
                    });
                }
                
                // Add licenses if available (HuggingFace)
                if (huggingface?.license) {
                    component.licenses = [{
                        license: {
                            id: huggingface.license
                        }
                    }];
                }
                
                // Add external references
                component.externalReferences = [];
                if (provider === 'HuggingFace') {
                    component.externalReferences.push({
                        comment: 'Model source',
                        type: 'vcs',
                        url: `https://huggingface.co/${modelName}`
                    });
                    // Detect framework and add dependency
                    if (huggingface?.library_name) {
                        libraryDeps.add(huggingface.library_name);
                    } else {
                        libraryDeps.add('transformers'); // Default for HF
                    }
                } else if (provider === 'OpenAI') {
                    component.externalReferences.push({
                        comment: 'API Documentation',
                        type: 'documentation',
                        url: 'https://platform.openai.com/docs/models'
                    });
                } else if (provider === 'Anthropic') {
                    component.externalReferences.push({
                        comment: 'Model Documentation',
                        type: 'documentation',
                        url: 'https://docs.anthropic.com/claude/docs/models-overview'
                    });
                } else if (provider === 'Google') {
                    component.externalReferences.push({
                        comment: 'Model Documentation',
                        type: 'documentation',
                        url: 'https://ai.google.dev/models'
                    });
                }
                
                // Add modelCard for ML models (CycloneDX 1.7 schema-valid shape:
                // modelParameters has no `tasks`/`modelType`/`contextLength`;
                // extra card data lives in modelCard.properties as aibom:* keys)
                const modelCard = {
                    modelParameters: {},
                    considerations: {},
                    properties: []
                };

                // Model card data is now loaded in UI, use it if available
                const localModelCardData = finding.modelInfo?.modelCardData || null;

                // Extract enhanced data from HuggingFace
                const cardData = huggingface?.cardData || {};
                const config = huggingface?.config || {};
                const evalResults = cardData.eval_results || modelCardData?.eval_results || null;
                const modelParams = huggingface?.modelParameters || {};

                // Integrate loaded model card data
                if (localModelCardData) {
                    console.log(`[ModelCard] Integrating data for ${provider}/${modelName}`);

                    // All modelCard/modelParameters/considerations fields below
                    // are CycloneDX 1.7 schema-valid names (modelCard has
                    // additionalProperties:false). Card data that has no native
                    // slot lands in modelCard.properties under the `aibom:`
                    // namespace so enrichment survives validation.

                    // Model parameters from local model card
                    if (localModelCardData.architecture && localModelCardData.architecture.contextLength) {
                        // `contextLength` is not a CycloneDX modelParameters field
                        modelCard.properties.push({
                            name: 'aibom:context-length',
                            value: String(localModelCardData.architecture.contextLength)
                        });
                    }
                    if (localModelCardData.modelType) {
                        // schema has no modelParameters.modelType — keep as property
                        pushPropertyOnce(modelCard, 'aibom:model-type', localModelCardData.modelType);
                    }

                    // Intended use → considerations.useCases[] (schema: array of
                    // strings); out-of-scope uses recorded as properties.
                    const intendedUses = structuredCardList(localModelCardData.intendedUse, ['primaryUses', 'primaryUseCases']);
                    const outOfScopeUses = structuredCardList(localModelCardData.intendedUse, ['outOfScope'], false);
                    if (intendedUses.length > 0) {
                        modelCard.considerations.useCases = [
                            ...(modelCard.considerations.useCases || []),
                            ...intendedUses
                        ];
                    }
                    outOfScopeUses.forEach((use) => {
                        modelCard.properties.push({
                            name: 'aibom:out-of-scope-use',
                            value: use
                        });
                    });

                    // Limitations → considerations.technicalLimitations[]
                    const knownLimitations = structuredCardList(localModelCardData.limitations, ['knownLimitations']);
                    if (knownLimitations.length > 0) {
                        modelCard.considerations.technicalLimitations = [
                            ...(modelCard.considerations.technicalLimitations || []),
                            ...knownLimitations
                        ];
                    }

                    // Training data → property (schema has no free-text slot)
                    const trainingDataText = formatModelCardField(localModelCardData.trainingData, {
                        description: ''
                    });
                    if (trainingDataText) {
                        modelCard.properties.push({
                            name: 'aibom:training-data',
                            value: trainingDataText
                        });
                    }

                    // Ethical considerations → ethicalConsiderations[] risk objects
                    const ec = localModelCardData.ethicalConsiderations;
                    if (ec) {
                        modelCard.considerations.ethicalConsiderations = [
                            ...(modelCard.considerations.ethicalConsiderations || [])
                        ];
                        if (ec.biasAndFairness) {
                            modelCard.considerations.ethicalConsiderations.push({
                                name: 'Bias & Fairness',
                                mitigationStrategy: ec.biasAndFairness
                            });
                        }
                        if (ec.safetyMeasures) {
                            modelCard.considerations.ethicalConsiderations.push({
                                name: 'Safety',
                                mitigationStrategy: ec.safetyMeasures
                            });
                        }
                        if (ec.privacyConsiderations) {
                            modelCard.considerations.ethicalConsiderations.push({
                                name: 'Privacy',
                                mitigationStrategy: ec.privacyConsiderations
                            });
                        }
                    }

                    // Capabilities → properties (no native field)
                    if (localModelCardData.capabilities && Array.isArray(localModelCardData.capabilities)) {
                        localModelCardData.capabilities.forEach((capability) => {
                            modelCard.properties.push({
                                name: 'aibom:capability',
                                value: capability
                            });
                        });
                    }

                    // Lifecycle status (e.g. "Deprecated - superseded by ...")
                    if (localModelCardData.access && localModelCardData.access.status) {
                        modelCard.properties.push({
                            name: 'aibom:lifecycle-status',
                            value: localModelCardData.access.status
                        });
                    }

                    // Enrichment provenance → property
                    modelCard.properties.push({
                        name: 'aibom:model-card-source',
                        value: `modelcards/${provider.toLowerCase()}/${modelName.toLowerCase().replace(/[^a-z0-9-]/g, '-')}.json`
                    });
                }

                if (huggingface) {
                    // Tasks (CycloneDX 1.7: modelParameters.task is a single string)
                    if (huggingface.pipeline_tag) {
                        if (!modelCard.modelParameters.task) {
                            modelCard.modelParameters.task = huggingface.pipeline_tag;
                        } else if (modelCard.modelParameters.task !== huggingface.pipeline_tag) {
                            modelCard.properties.push({
                                name: 'aibom:additional-task',
                                value: huggingface.pipeline_tag
                            });
                        }
                    }
                    
                    // Architecture from config or cardData
                    const modelType = config.model_type || cardData.model_type || huggingface.typeOfModel || 'transformer';
                    const architectures = config.architectures || huggingface.architectures || [];
                    
                    modelCard.modelParameters.architectureFamily = huggingface.library_name || 'transformers';
                    if (architectures.length > 0) {
                        modelCard.modelParameters.modelArchitecture = architectures[0];
                    } else if (huggingface.tags) {
                        const archTag = huggingface.tags.find(t => t.includes('gpt') || t.includes('bert') || t.includes('llama'));
                        if (archTag) {
                            modelCard.modelParameters.modelArchitecture = archTag;
                        }
                    }
                    
                    // Add model type (schema: no modelParameters.modelType — keep
                    // as property; local card wins, HF default 'transformer'
                    // without config evidence is not an assertion)
                    if (modelType && modelType !== 'transformer' &&
                        !modelCard.properties.some(p => p.name === 'aibom:model-type')) {
                        pushPropertyOnce(modelCard, 'aibom:model-type', modelType);
                    }

                    // Datasets from cardData or ModelCard
                    const datasets = cardData.datasets || modelCardData?.datasets || [];
                    if (datasets.length > 0) {
                        modelCard.modelParameters.datasets = Array.isArray(datasets)
                            ? datasets.map(ds => typeof ds === 'string' ? { type: 'dataset', name: ds } : ds)
                            : [{ type: 'dataset', name: String(datasets) }];
                    }

                    // Base model (schema: no modelParameters.baseModel — keep as property)
                    if (cardData.base_model || modelCardData?.base_model) {
                        modelCard.properties.push({
                            name: 'aibom:base-model',
                            value: String(cardData.base_model || modelCardData.base_model)
                        });
                    }
                    
                    // Inputs/Outputs based on pipeline
                    if (huggingface.pipeline_tag === 'text-generation') {
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'text' }];
                    } else if (huggingface.pipeline_tag === 'text-to-image') {
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'image' }];
                    } else if (huggingface.pipeline_tag === 'feature-extraction') {
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'vector' }];
                    }
                    
                    // Use cases from tags
                    const useCaseTags = huggingface.tags?.filter(t => 
                        !t.startsWith('license:') && 
                        !t.includes('pytorch') && 
                        !t.includes('tensorflow')
                    ) || [];
                    
                    if (useCaseTags.length > 0) {
                        // Merge with use cases already parsed from the local
                        // card — never overwrite card data with HF tags.
                        modelCard.considerations.useCases = [
                            ...new Set([
                                ...(modelCard.considerations.useCases || []),
                                ...useCaseTags
                            ])
                        ];
                    }
                    
                    // Enhanced ModelCard properties from cardData and ModelCard YAML
                    // Energy consumption
                    if (modelCardData?.energyConsumption || modelCardData?.energy_consumption) {
                        modelCard.properties.push({
                            name: 'energyConsumption',
                            value: String(modelCardData.energyConsumption || modelCardData.energy_consumption)
                        });
                    }
                    if (modelCardData?.energyQuantity || modelCardData?.energy_quantity) {
                        modelCard.properties.push({
                            name: 'energyQuantity',
                            value: String(modelCardData.energyQuantity || modelCardData.energy_quantity)
                        });
                    }
                    if (modelCardData?.energyUnit || modelCardData?.energy_unit) {
                        modelCard.properties.push({
                            name: 'energyUnit',
                            value: String(modelCardData.energyUnit || modelCardData.energy_unit)
                        });
                    }
                    
                    // Hyperparameters
                    if (modelCardData?.hyperparameter || modelCardData?.hyperparameters || config.hyperparameters) {
                        const hyperparams = modelCardData?.hyperparameter || modelCardData?.hyperparameters || config.hyperparameters;
                        modelCard.properties.push({
                            name: 'hyperparameter',
                            value: typeof hyperparams === 'object' ? JSON.stringify(hyperparams) : String(hyperparams)
                        });
                    }
                    
                    // Training information
                    if (modelCardData?.informationAboutTraining || modelCardData?.training_info) {
                        modelCard.properties.push({
                            name: 'informationAboutTraining',
                            value: String(modelCardData.informationAboutTraining || modelCardData.training_info)
                        });
                    }
                    
                    // Data preprocessing
                    if (modelCardData?.modelDataPreprocessing || modelCardData?.data_preprocessing) {
                        modelCard.properties.push({
                            name: 'modelDataPreprocessing',
                            value: String(modelCardData.modelDataPreprocessing || modelCardData.data_preprocessing)
                        });
                    }
                    
                    // Safety and risk assessment
                    if (modelCardData?.safetyRiskAssessment || modelCardData?.safety_risk_assessment) {
                        modelCard.properties.push({
                            name: 'safetyRiskAssessment',
                            value: String(modelCardData.safetyRiskAssessment || modelCardData.safety_risk_assessment)
                        });
                    }
                    
                    // Sensitive personal information
                    if (modelCardData?.useSensitivePersonalInformation || modelCardData?.sensitive_data) {
                        modelCard.properties.push({
                            name: 'useSensitivePersonalInformation',
                            value: String(modelCardData.useSensitivePersonalInformation || modelCardData.sensitive_data)
                        });
                    }
                    
                    // Model explainability
                    if (modelCardData?.modelExplainability || modelCardData?.explainability) {
                        modelCard.properties.push({
                            name: 'modelExplainability',
                            value: String(modelCardData.modelExplainability || modelCardData.explainability)
                        });
                    }
                    
                    // Application information
                    if (modelCardData?.informationAboutApplication || modelCardData?.application_info) {
                        modelCard.properties.push({
                            name: 'informationAboutApplication',
                            value: String(modelCardData.informationAboutApplication || modelCardData.application_info)
                        });
                    }
                    
                    // Model parameters extracted from config.json
                    if (modelParams.num_parameters) {
                        modelCard.properties.push({
                            name: 'num_parameters',
                            value: String(modelParams.num_parameters)
                        });
                    }
                    if (modelParams.vocab_size) {
                        modelCard.properties.push({
                            name: 'vocab_size',
                            value: String(modelParams.vocab_size)
                        });
                    }
                    if (modelParams.contextWindow) {
                        modelCard.properties.push({
                            name: 'contextWindow',
                            value: String(modelParams.contextWindow)
                        });
                    }
                    if (modelParams.hidden_size) {
                        modelCard.properties.push({
                            name: 'hidden_size',
                            value: String(modelParams.hidden_size)
                        });
                    }
                    if (modelParams.num_layers) {
                        modelCard.properties.push({
                            name: 'num_layers',
                            value: String(modelParams.num_layers)
                        });
                    }
                    if (modelParams.num_attention_heads) {
                        modelCard.properties.push({
                            name: 'num_attention_heads',
                            value: String(modelParams.num_attention_heads)
                        });
                    }

                    // Metrics and decision thresholds
                    if (modelCardData?.metric || modelCardData?.metrics) {
                        const metrics = modelCardData.metric || modelCardData.metrics;
                        modelCard.properties.push({
                            name: 'metric',
                            value: typeof metrics === 'object' ? JSON.stringify(metrics) : String(metrics)
                        });
                    }
                    if (modelCardData?.metricDecisionThreshold || modelCardData?.decision_threshold) {
                        modelCard.properties.push({
                            name: 'metricDecisionThreshold',
                            value: String(modelCardData.metricDecisionThreshold || modelCardData.decision_threshold)
                        });
                    }
                    
                    // Limitations from ModelCard considerations (merge with the
                    // structured parse above; guard against non-string shapes)
                    if (modelCardData?.limitations || modelCardData?.limitation) {
                        const limitations = modelCardData.limitations || modelCardData.limitation;
                        let entries = [];
                        if (typeof limitations === 'string') {
                            entries = limitations.split(';').map(s => s.trim()).filter(Boolean);
                        } else if (Array.isArray(limitations)) {
                            entries = limitations
                                .filter(x => typeof x === 'string' || typeof x === 'number')
                                .map(String);
                        }
                        if (entries.length > 0) {
                            modelCard.considerations.technicalLimitations = [
                                ...new Set([
                                    ...(modelCard.considerations.technicalLimitations || []),
                                    ...entries
                                ])
                            ];
                        }
                    }

                    // Ethical considerations (schema: array of risk objects)
                    if (modelCardData?.ethical_considerations || modelCardData?.ethics) {
                        const ethical = modelCardData.ethical_considerations || modelCardData.ethics;
                        modelCard.considerations.ethicalConsiderations = Array.isArray(ethical)
                            ? ethical.map((e) => typeof e === 'string' ? { name: e } : e)
                            : [{ name: String(ethical) }];
                    }

                    // Quantitative Analysis section with performance metrics
                    if (evalResults) {
                        const performanceMetrics = parseEvalResults(evalResults);
                        if (performanceMetrics.length > 0) {
                            modelCard.quantitativeAnalysis = {
                                performanceMetrics: performanceMetrics
                            };
                        }
                    }
                } else {
                    // Use explicit modelType from finding for better accuracy
                    if (modelType === 'text-generation') {
                        modelCard.modelParameters.task = 'text-generation';
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'text' }];
                        // Add architecture family if we can detect it from model name
                        if (modelName.includes('llama')) {
                            modelCard.modelParameters.architectureFamily = 'llama';
                        } else if (modelName.includes('mistral') || modelName.includes('mixtral')) {
                            modelCard.modelParameters.architectureFamily = 'mistral';
                        } else if (modelName.includes('gemma')) {
                            modelCard.modelParameters.architectureFamily = 'gemma';
                        } else if (modelName.includes('phi')) {
                            modelCard.modelParameters.architectureFamily = 'phi';
                        } else if (modelName.includes('qwen')) {
                            modelCard.modelParameters.architectureFamily = 'qwen';
                        } else if (modelName.includes('deepseek')) {
                            modelCard.modelParameters.architectureFamily = 'deepseek';
                        }
                    } else if (modelType === 'embeddings') {
                        modelCard.modelParameters.task = 'feature-extraction';
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'vector' }];
                    } else if (modelType === 'text-to-image') {
                        modelCard.modelParameters.task = 'text-to-image';
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'image' }];
                    } else if (modelType === 'multimodal') {
                        modelCard.modelParameters.task = 'multimodal';
                        modelCard.modelParameters.inputs = [{ format: 'text' }, { format: 'image' }];
                        modelCard.modelParameters.outputs = [{ format: 'text' }, { format: 'image' }];
                    } else {
                        // Fallback to name-based detection if type is unknown
                        if (modelName.includes('gpt') || modelName.includes('claude') || modelName.includes('gemini') ||
                            modelName.includes('llama') || modelName.includes('mistral') || modelName.includes('qwen')) {
                        modelCard.modelParameters.task = 'text-generation';
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'text' }];
                    } else if (modelName.includes('embedding')) {
                        modelCard.modelParameters.task = 'feature-extraction';
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'vector' }];
                        }
                    }
                }

                // Only add modelCard if it has content
                if (modelCard.modelParameters.task ||
                    Object.keys(modelCard.considerations).length > 0 ||
                    modelCard.modelParameters.architectureFamily ||
                    (modelCard.properties && modelCard.properties.length > 0) ||
                    modelCard.quantitativeAnalysis) {
                    // Remove empty containers (schema-valid but pure noise)
                    if (modelCard.properties && modelCard.properties.length === 0) {
                        delete modelCard.properties;
                    }
                    if (Object.keys(modelCard.modelParameters).length === 0) {
                        delete modelCard.modelParameters;
                    }
                    component.modelCard = modelCard;
                }
                
                // Add detection metadata to properties
                component.properties.push(
                    { name: 'cdx:detection:method', value: 'automated-code-analysis' },
                    { name: 'cdx:detection:confidence', value: finding.severity },
                    { name: 'cdx:detection:weight', value: finding.weight.toString() }
                );

                // Native CycloneDX evidence (identity + source occurrences)
                const modelEvidence = buildNativeEvidence(finding);
                if (modelEvidence) {
                    component.evidence = modelEvidence;
                }
                
                if (huggingface) {
                    component.properties.push(
                        { name: 'huggingface:downloads', value: huggingface.downloads?.toString() || '0' },
                        { name: 'huggingface:likes', value: huggingface.likes?.toString() || '0' }
                    );
                    
                    // Add enhanced metadata properties
                    if (huggingface.primaryPurpose) {
                        component.properties.push({
                            name: 'primaryPurpose',
                            value: huggingface.primaryPurpose
                        });
                    }
                    if (huggingface.suppliedBy) {
                        component.properties.push({
                            name: 'suppliedBy',
                            value: huggingface.suppliedBy
                        });
                    }
                    if (huggingface.typeOfModel) {
                        component.properties.push({
                            name: 'typeOfModel',
                            value: huggingface.typeOfModel
                        });
                    }
                    
                    // Extract domain from tags or description
                    const cardData = huggingface.cardData || {};
                    const modelSummary = cardData.model_summary || '';
                    const tags = huggingface.tags || [];
                    
                    // Infer domain from tags (e.g., medical, finance, legal)
                    const domainTags = tags.filter(t => 
                        ['medical', 'healthcare', 'finance', 'legal', 'education', 'research', 'nlp', 'cv', 'multimodal'].some(d => 
                            t.toLowerCase().includes(d)
                        )
                    );
                    if (domainTags.length > 0) {
                        component.properties.push({
                            name: 'domain',
                            value: domainTags[0]
                        });
                    }
                    
                    // Language from cardData
                    if (cardData.language) {
                        component.properties.push({
                            name: 'language',
                            value: Array.isArray(cardData.language) ? cardData.language.join(', ') : String(cardData.language)
                        });
                    }
                }
                
                // Add evidence with file locations and line numbers
                const locations = finding.modelInfo.locations || [];
                locations.forEach((loc, idx) => {
                    if (idx < 5) {
                        const location = loc.line > 0 ? `${loc.file}:${loc.line}` : loc.file;
                        component.properties.push({
                            name: `evidence:location:${idx + 1}`,
                            value: location
                        });
                        if (loc.snippet) {
                            component.properties.push({
                                name: `evidence:snippet:${idx + 1}`,
                                value: loc.snippet
                            });
                        }
                    }
                });
                
                modelMap.set(key, { component, bomRef });
            }
        } else if (finding.artifactInfo || finding.attestationInfo) {
            // R1/R4: hashed artifact + attestation findings are state metadata —
            // matched to model components / recorded as attestation state above;
            // not components of their own.
            continue;
        } else {
            // Generic finding - create a library/framework component with a
            // clean identity (name/version/purl from structured dependency
            // info — never "Dependency: <name>" with version "detected").
            const identity = resolveLibraryIdentity(finding);
            const component = {
                type: finding.category === 'dependencies' ? 'library' : 'framework',
                'bom-ref': `component-${generateShortId()}`,
                name: identity.name,
                description: finding.description,
                scope: 'required',
                properties: [
                    { name: 'cdx:detection:category', value: finding.category },
                    { name: 'cdx:detection:severity', value: finding.severity },
                    { name: 'cdx:detection:weight', value: finding.weight.toString() }
                ]
            };
            if (identity.version) {
                component.version = identity.version;
            }
            const purl = buildLibraryPurl(identity.name, identity.version, identity.ecosystem);
            if (purl) {
                component.purl = purl;
            }

            // Native CycloneDX evidence (identity + source occurrences)
            const evidence = buildNativeEvidence(finding);
            if (evidence) {
                component.evidence = evidence;
            }

            // Add evidence with line numbers
            finding.evidence?.forEach((ev, idx) => {
                if (idx < 3) {
                    // Include file path with line number for precise reference
                    const location = ev.line && ev.line > 0
                        ? `${ev.file}:${ev.line}`
                        : ev.file;

                    component.properties.push({
                        name: `cdx:evidence:location:${idx}`,
                        value: location
                    });

                    // Also add snippet if available
                    if (ev.snippet) {
                        component.properties.push({
                            name: `cdx:evidence:snippet:${idx}`,
                            value: ev.snippet
                        });
                    }
                }
            });

            components.push(component);
        }
    }
    
    // Add all identified models
    const models = Array.from(modelMap.values()).map(m => m.component);
    // R1: attach verified Git-LFS artifact hashes to matching model components.
    // One-to-one greedy assignment by score: an artifact can vouch for at most
    // one model, so two similar models never share one sha256 claim.
    const artifacts = findings.filter(f => f.artifactInfo).map(f => f.artifactInfo);
    if (artifacts.length > 0) {
        const pairs = [];
        for (const entry of modelMap.values()) {
            for (const artifact of artifacts) {
                const score = artifactMatchScore(artifact, entry.component.name);
                if (score >= 2) pairs.push({ entry, artifact, score });
            }
        }
        pairs.sort((a, b) => b.score - a.score);
        const usedArtifacts = new Set();
        const usedModels = new Set();
        for (const pair of pairs) {
            if (usedArtifacts.has(pair.artifact.path) || usedModels.has(pair.entry.bomRef)) continue;
            usedArtifacts.add(pair.artifact.path);
            usedModels.add(pair.entry.bomRef);
            pair.entry.component.hashes = [{ alg: 'SHA-256', content: pair.artifact.sha256 }];
            pair.entry.component.properties.push({
                name: 'aibom:artifact:path',
                value: pair.artifact.path
            });
            pair.entry.component.properties.push({
                name: 'aibom:hash-source',
                value: 'git-lfs-pointer'
            });
            console.log(`[BOM Generator] ✓ Hash attached: ${pair.artifact.path} → ${pair.entry.component.name}`);
        }
    }
    components.push(...models);
    
    // Add detected library dependencies
    const libraryComponents = createLibraryComponents(libraryDeps, findings);
    components.push(...libraryComponents);
    
    // Add MCP servers as components
    const mcpComponents = createMCPServerComponents(findings);
    components.push(...mcpComponents);
    
    // Extract protocol info for metadata
    const protocolInfo = extractProtocolInfo(findings);
    
    return { 
        components, 
        modelRefs: Array.from(modelMap.values()), 
        libraryRefs: libraryComponents,
        mcpRefs: mcpComponents,
        hardwareInfo,
        infraInfo,
        governanceInfo,
        protocolInfo
    };
}

/**
 * Create CycloneDX components for MCP servers
 */
function createMCPServerComponents(findings) {
    const components = [];
    const seenServers = new Set();
    
    // Find all protocol findings with MCP server details
    const protocolFindings = findings.filter(f => f.category === 'protocol');
    
    for (const finding of protocolFindings) {
        if (!finding.protocolInfo) continue;
        
        // Handle MCP config findings with parsed servers
        if (finding.protocolInfo.type === 'mcp' && finding.protocolInfo.parsedServers) {
            for (const server of finding.protocolInfo.parsedServers) {
                if (seenServers.has(server.name)) continue;
                seenServers.add(server.name);
                
                const component = createMCPServerComponent(server, finding);
                if (component) {
                    components.push(component);
                }
            }
        }
        
        // Handle individual MCP server findings
        if (finding.protocolInfo.type === 'mcp-server') {
            const serverName = finding.protocolInfo.serverName;
            if (seenServers.has(serverName)) continue;
            seenServers.add(serverName);
            
            const serverInfo = {
                name: serverName,
                category: finding.protocolInfo.serverCategory,
                provider: finding.protocolInfo.provider,
                capabilities: finding.protocolInfo.capabilities || [],
                description: finding.description
            };
            
            const component = createMCPServerComponent(serverInfo, finding);
            if (component) {
                components.push(component);
            }
        }
    }
    
    return components;
}

/**
 * Create a single MCP server component
 */
function createMCPServerComponent(serverInfo, finding) {
    const bomRef = `mcp-server-${serverInfo.name.replace(/[^a-zA-Z0-9]/g, '-')}`;
    
    // Determine the component type - MCP servers are essentially services/tools
    const component = {
        type: 'platform',  // CycloneDX type for services/platforms
        'bom-ref': bomRef,
        name: `mcp-server-${serverInfo.name}`,
        version: 'configured',
        description: serverInfo.description || `MCP server providing ${serverInfo.category || 'AI tool'} capabilities`,
        scope: 'required',
        properties: [
            { name: 'cdx:component:type', value: 'mcp-server' },
            { name: 'mcp:server:name', value: serverInfo.name },
            { name: 'mcp:server:category', value: serverInfo.category || 'unknown' }
        ]
    };
    
    // Add provider if available
    if (serverInfo.provider) {
        component.publisher = serverInfo.provider;
        component.properties.push({
            name: 'mcp:server:provider',
            value: serverInfo.provider
        });
    }
    
    // Add capabilities as properties
    if (serverInfo.capabilities && serverInfo.capabilities.length > 0) {
        component.properties.push({
            name: 'mcp:server:capabilities',
            value: serverInfo.capabilities.join(', ')
        });
    }
    
    // Add PURL based on server type
    const purl = getMCPServerPurl(serverInfo);
    if (purl) {
        component.purl = purl;
    }
    
    // Add external reference to MCP documentation
    component.externalReferences = [{
        type: 'documentation',
        url: 'https://modelcontextprotocol.io/docs',
        comment: 'Model Context Protocol Documentation'
    }];
    
    // Add specific external references based on category
    if (serverInfo.category === 'code-platform' && serverInfo.provider === 'GitHub') {
        component.externalReferences.push({
            type: 'website',
            url: 'https://github.com',
            comment: 'GitHub - Code hosting platform'
        });
    } else if (serverInfo.category === 'communication' && serverInfo.provider === 'Slack') {
        component.externalReferences.push({
            type: 'website',
            url: 'https://slack.com',
            comment: 'Slack - Team communication'
        });
    } else if (serverInfo.category === 'web-search' && serverInfo.provider === 'Brave') {
        component.externalReferences.push({
            type: 'website',
            url: 'https://search.brave.com',
            comment: 'Brave Search'
        });
    }
    
    // Add evidence from finding
    if (finding.evidence && finding.evidence.length > 0) {
        const ev = finding.evidence[0];
        component.properties.push({
            name: 'cdx:evidence:location',
            value: ev.file
        });
    }
    
    return component;
}

/**
 * Generate PURL for MCP server based on its type and name
 */
function getMCPServerPurl(serverInfo) {
    const name = serverInfo.name.toLowerCase();
    
    // Official MCP servers from modelcontextprotocol
    const officialServers = [
        'filesystem', 'github', 'gitlab', 'postgres', 'sqlite', 
        'slack', 'memory', 'brave-search', 'fetch', 'puppeteer',
        'sequential-thinking', 'google-drive', 'google-maps'
    ];
    
    for (const official of officialServers) {
        if (name.includes(official)) {
            return `pkg:npm/@modelcontextprotocol/server-${official}`;
        }
    }
    
    // NPM package pattern
    if (name.includes('mcp-') || name.includes('-mcp')) {
        return `pkg:npm/${name}`;
    }
    
    // Generic MCP server
    return `pkg:mcp/${serverInfo.name}`;
}

/**
 * Extract protocol information for BOM metadata
 */
function extractProtocolInfo(findings) {
    const protocolFindings = findings.filter(f => f.category === 'protocol');
    
    const info = {
        detected: protocolFindings.length > 0,
        mcpServers: [],
        mcpCapabilities: [],
        aiProviders: [],
        hasA2A: false,
        hasFunctionCalling: false
    };
    
    for (const finding of protocolFindings) {
        if (!finding.protocolInfo) continue;
        
        if (finding.protocolInfo.type === 'mcp') {
            if (finding.protocolInfo.servers) {
                info.mcpServers.push(...finding.protocolInfo.servers);
            }
            if (finding.protocolInfo.capabilities) {
                info.mcpCapabilities.push(...finding.protocolInfo.capabilities);
            }
            if (finding.protocolInfo.aiProviders) {
                info.aiProviders.push(...finding.protocolInfo.aiProviders);
            }
        } else if (finding.protocolInfo.type === 'a2a') {
            info.hasA2A = true;
        } else if (finding.protocolInfo.type === 'function-calling') {
            info.hasFunctionCalling = true;
        }
    }
    
    // Deduplicate
    info.mcpServers = [...new Set(info.mcpServers)];
    info.mcpCapabilities = [...new Set(info.mcpCapabilities)];
    info.aiProviders = [...new Set(info.aiProviders)];
    
    return info;
}

function createLibraryComponents(libraryDeps, findings) {
    const libraries = [];
    
    // Common ML libraries
    const knownLibraries = {
        'transformers': {
            name: 'Transformers',
            description: 'State-of-the-art Machine Learning for PyTorch, TensorFlow, and JAX',
            purl: 'pkg:pypi/transformers',
            url: 'https://huggingface.co/docs/transformers'
        },
        'pytorch': {
            name: 'PyTorch',
            description: 'Tensors and Dynamic neural networks in Python with strong GPU acceleration',
            purl: 'pkg:pypi/torch',
            url: 'https://pytorch.org'
        },
        'tensorflow': {
            name: 'TensorFlow',
            description: 'An Open Source Machine Learning Framework for Everyone',
            purl: 'pkg:pypi/tensorflow',
            url: 'https://tensorflow.org'
        },
        'diffusers': {
            name: 'Diffusers',
            description: 'State-of-the-art diffusion models for image and audio generation',
            purl: 'pkg:pypi/diffusers',
            url: 'https://huggingface.co/docs/diffusers'
        },
        'sentence-transformers': {
            name: 'Sentence Transformers',
            description: 'Compute dense vector representations for sentences, paragraphs, and images',
            purl: 'pkg:pypi/sentence-transformers',
            url: 'https://www.sbert.net'
        }
    };
    
    // Check for library usage in dependencies findings
    for (const finding of findings) {
        if (finding.category === 'dependencies') {
            const desc = finding.description.toLowerCase();
            if (desc.includes('transformers')) libraryDeps.add('transformers');
            if (desc.includes('torch') || desc.includes('pytorch')) libraryDeps.add('pytorch');
            if (desc.includes('tensorflow')) libraryDeps.add('tensorflow');
            if (desc.includes('diffusers')) libraryDeps.add('diffusers');
            if (desc.includes('sentence-transformers')) libraryDeps.add('sentence-transformers');
        }
    }
    
    for (const lib of libraryDeps) {
        const libInfo = knownLibraries[lib];
        if (libInfo) {
            libraries.push({
                type: 'library',
                'bom-ref': `lib-${lib}`,
                name: libInfo.name,
                description: libInfo.description,
                purl: libInfo.purl,
                externalReferences: [{
                    type: 'website',
                    url: libInfo.url
                }]
            });
        }
    }
    
    return libraries;
}

/**
 * Generate a cryptographically secure short ID
 * Uses Web Crypto API instead of Math.random()
 */
function generateShortId() {
    const array = new Uint8Array(6);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(36)).join('').substring(0, 10);
}

async function generateCycloneDXXml(analysisResult, selectedFindings) {
    const { repository, analyzedAt } = analysisResult;
    const uuid = generateUUID();
    
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += `<bom xmlns="http://cyclonedx.org/schema/bom/1.7" version="1" serialNumber="urn:uuid:${uuid}">\n`;
    
    // Metadata
    xml += '  <metadata>\n';
    xml += `    <timestamp>${escapeXml(analyzedAt)}</timestamp>\n`;
    // R3: generation context as a declared lifecycle phase
    xml += '    <lifecycles>\n      <lifecycle><phase>post-build</phase></lifecycle>\n    </lifecycles>\n';
    xml += '    <tools>\n';
    xml += '      <components>\n';
    xml += '        <component type="application" bom-ref="tool-aibom-generator">\n';
    xml += '          <name>AI BOM Generator</name>\n';
    xml += '          <version>1.0.0</version>\n';
    xml += '        </component>\n';
    xml += '      </components>\n';
    xml += '    </tools>\n';
    xml += `    <component type="application" bom-ref="repo-${escapeXml(repository.owner)}-${escapeXml(repository.repo)}">\n`;
    xml += `      <group>${escapeXml(repository.owner)}</group>\n`;
    xml += `      <name>${escapeXml(repository.repo)}</name>\n`;
    xml += '      <version>main</version>\n';
    if (repository.description) {
        xml += `      <description>${escapeXml(repository.description)}</description>\n`;
    }
    xml += `      <purl>pkg:github/${escapeXml(repository.owner)}/${escapeXml(repository.repo)}</purl>\n`;
    xml += '    </component>\n';
    // R3: header self-descriptions (properties close the metadata sequence)
    xml += '    <properties>\n';
    xml += `      <property name="aibom:scope">repository static source analysis (${escapeXml(repository.fullName)}@${escapeXml(repository.scannedRef || 'main')})</property>\n`;
    xml += '      <property name="aibom:completeness">partial — post-build source-level analysis; training-time observation not possible</property>\n';
    xml += '      <property name="aibom:generation-context">after-build</property>\n';
    xml += '      <property name="aibom:authorship">tool-generated</property>\n';
    xml += '      <property name="aibom:graph-type">static dependency graph (source + manifest + SBOM analysis)</property>\n';
    xml += `      <property name="aibom:attestation">${escapeXml(getAttestationState(selectedFindings, analysisResult))}</property>\n`;
    xml += '    </properties>\n';
    xml += '  </metadata>\n';
    
    // Components (single assembly — the dependency graph must reference the
    // SAME bom-refs as the component list)
    xml += '  <components>\n';
    const { components, modelRefs, libraryRefs } = await createMLModelComponents(selectedFindings);

    components.forEach(comp => {
        xml += `    <component type="${comp.type}" bom-ref="${escapeXml(comp['bom-ref'])}">\n`;
        if (comp.group) {
            xml += `      <group>${escapeXml(comp.group)}</group>\n`;
        }
        xml += `      <name>${escapeXml(comp.name)}</name>\n`;
        if (comp.version) {
            xml += `      <version>${escapeXml(comp.version)}</version>\n`;
        }
        if (comp.author) {
            xml += `      <author>${escapeXml(comp.author)}</author>\n`;
        }
        if (comp.description) {
            xml += `      <description>${escapeXml(comp.description)}</description>\n`;
        }
        if (comp.scope) {
            xml += `      <scope>${escapeXml(comp.scope)}</scope>\n`;
        }
        // R1: verified artifact hashes (XSD order: hashes before licenses/purl)
        if (comp.hashes && comp.hashes.length > 0) {
            xml += '      <hashes>\n';
            comp.hashes.forEach(hash => {
                xml += `        <hash alg="${escapeXml(hash.alg)}">${escapeXml(hash.content)}</hash>\n`;
            });
            xml += '      </hashes>\n';
        }
        if (comp.purl) {
            xml += `      <purl>${escapeXml(comp.purl)}</purl>\n`;
        }
        if (comp.publisher) {
            xml += `      <publisher>${escapeXml(comp.publisher)}</publisher>\n`;
        }
        
        // External references
        if (comp.externalReferences && comp.externalReferences.length > 0) {
            xml += '      <externalReferences>\n';
            comp.externalReferences.forEach(ref => {
                xml += `        <reference type="${escapeXml(ref.type)}">\n`;
                xml += `          <url>${escapeXml(ref.url)}</url>\n`;
                xml += '        </reference>\n';
            });
            xml += '      </externalReferences>\n';
        }
        
        // Properties
        if (comp.properties && comp.properties.length > 0) {
            xml += '      <properties>\n';
            comp.properties.forEach(prop => {
                xml += `        <property name="${escapeXml(prop.name)}">${escapeXml(prop.value)}</property>\n`;
            });
            xml += '      </properties>\n';
        }

        xml += '    </component>\n';
    });
    
    xml += '  </components>\n';

    // Services (external AI inference APIs — trust-boundary documentation,
    // mirrors the JSON generator)
    const serviceRefsByProvider = {};
    if (typeof AI_SERVICE_ENDPOINTS !== 'undefined') {
        modelRefs.forEach(model => {
            const provider = model.component.author;
            const svcDef = provider ? AI_SERVICE_ENDPOINTS[provider] : null;
            if (!svcDef) return;
            if (!serviceRefsByProvider[provider]) {
                const serviceRef = `service-${provider.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
                serviceRefsByProvider[provider] = serviceRef;
                xml += `    <service bom-ref="${escapeXml(serviceRef)}">\n`;
                xml += `      <provider>\n        <name>${escapeXml(provider)}</name>\n      </provider>\n`;
                xml += `      <name>${escapeXml(svcDef.service)}</name>\n`;
                xml += `      <description>${escapeXml(`External ${provider} inference API consumed by this application (third-party trust boundary)`)}</description>\n`;
                xml += '      <endpoints>\n';
                svcDef.endpoints.forEach(endpoint => {
                    xml += `        <endpoint>${escapeXml(endpoint)}</endpoint>\n`;
                });
                xml += '      </endpoints>\n';
                xml += '      <authenticated>true</authenticated>\n';
                xml += `      <externalReferences>\n        <reference type="documentation"><url>${escapeXml(svcDef.docs)}</url></reference>\n      </externalReferences>\n`;
                xml += '    </service>\n';
            }
        });
    }

    // Dependencies - reference the same bom-refs as the component list
    xml += '  <dependencies>\n';

    const libraryRefIds = libraryRefs.map(l => l['bom-ref']);

    // Main repo depends on all components and services
    xml += `    <dependency ref="repo-${escapeXml(repository.owner)}-${escapeXml(repository.repo)}">\n`;
    components.forEach(comp => {
        xml += `      <dependency ref="${escapeXml(comp['bom-ref'])}" />\n`;
    });
    Object.values(serviceRefsByProvider).forEach(serviceRef => {
        xml += `      <dependency ref="${escapeXml(serviceRef)}" />\n`;
    });
    xml += '    </dependency>\n';

    // ML models depend on their libraries and their inference service
    modelRefs.forEach(model => {
        xml += `    <dependency ref="${escapeXml(model.bomRef)}">\n`;

        const provider = model.component.author;
        if (provider && serviceRefsByProvider[provider]) {
            xml += `      <dependency ref="${escapeXml(serviceRefsByProvider[provider])}" />\n`;
        }

        const modelComp = model.component;
        if (modelComp.properties) {
            const category = modelComp.properties.find(p => p.name === 'category')?.value;

            if (category === 'text-generation' || category === 'feature-extraction') {
                if (libraryRefIds.includes('lib-transformers')) {
                    xml += '      <dependency ref="lib-transformers" />\n';
                }
                if (libraryRefIds.includes('lib-pytorch')) {
                    xml += '      <dependency ref="lib-pytorch" />\n';
                }
            } else if (category === 'text-to-image') {
                if (libraryRefIds.includes('lib-diffusers')) {
                    xml += '      <dependency ref="lib-diffusers" />\n';
                }
            }
        }

        xml += '    </dependency>\n';
    });
    
    // Libraries
    libraryRefs.forEach(lib => {
        xml += `    <dependency ref="${escapeXml(lib['bom-ref'])}" />\n`;
    });
    
    xml += '  </dependencies>\n';
    xml += '</bom>\n';
    
    return xml;
}

function generateSPDX(analysisResult, selectedFindings) {
    const { repository, analyzedAt } = analysisResult;
    const namespace = `https://github.com/${repository.owner}/${repository.repo}/spdx/${generateSPDXId()}`;
    const docId = `${namespace}/SpdxDocument`;
    
    // SPDX 3.0.1 uses JSON-LD format
    const spdx = {
        '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
        '@id': docId,
        'type': 'SpdxDocument',
        'spdxId': docId,
        'creationInfo': {
            'type': 'CreationInfo',
            'specVersion': '3.0.1',
            'created': analyzedAt,
            'createdBy': ['Tool: AI BOM Generator-1.0.0'],
            'profile': [
                'core',
                'software',
                'ai'
            ]
        },
        'name': `AI BOM for ${repository.fullName}`,
        'namespaceMap': [{
            'prefix': 'ex',
            'namespace': namespace
        }],
        // R3: header self-descriptions — scope + completeness declared on the
        // document itself (OWASP "silence becomes a producer assertion")
        'comment': [
            `Scope: repository static source analysis (${repository.fullName}@${repository.scannedRef || 'main'})`,
            'Completeness: partial — post-build source-level analysis; training-time observation not possible',
            'Generation context: after-build',
            'Authorship: tool-generated'
        ].join('\n'),
        'element': [],
        'rootElement': []
    };
    
    // Main repository element
    const repoId = `${namespace}/Repository`;
    const repoElement = {
        '@id': repoId,
        'type': 'software_Package',
        'spdxId': repoId,
        'creationInfo': {
            'type': 'CreationInfo',
            'specVersion': '3.0.1',
            'created': analyzedAt,
            'createdBy': ['Tool: AI BOM Generator-1.0.0']
        },
        'name': repository.repo,
        'summary': repository.description || '',
        'packageVersion': 'main',
        'downloadLocation': repository.htmlUrl,
        'homepage': repository.htmlUrl,
        'sourceInfo': `GitHub repository: ${repository.fullName}`,
        'primaryPurpose': 'application',
        // R4: attestation presence state recorded explicitly
        'comment': `Attestation state: ${getAttestationState(selectedFindings, analysisResult)}`,
        'externalIdentifier': [{
            'type': 'ExternalIdentifier',
            'externalIdentifierType': 'purl',
            'identifier': `pkg:github/${repository.owner}/${repository.repo}`
        }]
    };
    
    spdx.element.push(repoElement);
    spdx.rootElement.push(repoId);
    
    // Create relationships array
    const relationships = [];
    // R1: hashed model artifacts (matched to models by name tokens)
    const artifactInfos = (selectedFindings || [])
        .filter(f => f.artifactInfo)
        .map(f => f.artifactInfo);

    // Add AI packages and libraries for each finding
    selectedFindings.forEach((finding, idx) => {
        if (finding.modelInfo) {
            // Create AIPackage element
            const { provider, modelName, modelType, huggingface, detectionSource, relatedModels } = finding.modelInfo;
            const aiId = `${namespace}/AIPackage-${generateShortId()}`;
            
            const aiPackage = {
                '@id': aiId,
                'type': 'ai_AIPackage',
                'spdxId': aiId,
                'creationInfo': {
                    'type': 'CreationInfo',
                    'specVersion': '3.0.1',
                    'created': analyzedAt,
                    'createdBy': ['Tool: AI BOM Generator-1.0.0']
                },
                'name': modelName,
                'summary': finding.description,
                'suppliedBy': {
                    'type': 'Organization',
                    'name': provider
                }
            };
            // No invented version: omit packageVersion unless the model card
            // carries a real version (unknown stays unknown).
            if (finding.modelInfo.modelCardData?.version) {
                aiPackage.packageVersion = String(finding.modelInfo.modelCardData.version);
            }

            // Preserve detection evidence (source locations + snippets) as a
            // package comment — SPDX 3.0.1 Element.comment.
            const evidenceLines = (finding.evidence || [])
                .filter(ev => ev.file && ev.line && ev.line > 0)
                .map(ev => `Detected at ${ev.file}:${ev.line}${ev.snippet ? ` — ${ev.snippet}` : ''}`);
            // R1: attach verified artifact hash as an SPDX checksum
            const artifact = findArtifactForModel(artifactInfos, modelName);
            if (artifact) {
                aiPackage.checksum = [{
                    'type': 'Checksum',
                    'algorithm': 'sha256',
                    'checksumValue': artifact.sha256
                }];
                evidenceLines.push(`Artifact: ${artifact.path} (Git-LFS sha256 verified)`);
            }
            if (evidenceLines.length > 0) {
                aiPackage.comment = evidenceLines.join('\n');
            }
            
            // Add detection source if available
            if (detectionSource) {
                aiPackage.detectionMethod = detectionSource;
            }
            
            // Add related models information if available
            if (relatedModels && relatedModels.length > 0) {
                aiPackage.relatedElement = relatedModels.map(rm => ({
                    type: 'alternate',
                    provider: rm.provider,
                    modelName: rm.modelName
                }));
            }
            
            // AI-specific properties using explicit modelType
            if (modelType && modelType !== 'unknown') {
                aiPackage.typeOfModel = [modelType];
                
                // Set domain based on type
                if (modelType === 'text-generation') {
                    aiPackage.domain = ['natural-language-processing'];
                } else if (modelType === 'embeddings') {
                    aiPackage.domain = ['natural-language-processing', 'semantic-search'];
                } else if (modelType === 'text-to-image') {
                    aiPackage.domain = ['computer-vision', 'image-generation'];
                } else if (modelType === 'multimodal') {
                    aiPackage.domain = ['natural-language-processing', 'computer-vision'];
                }
            } else if (huggingface?.pipeline_tag) {
                aiPackage.typeOfModel = [huggingface.pipeline_tag];
                aiPackage.domain = huggingface.tags?.slice(0, 5) || [];
            }
            
            // HuggingFace-specific metadata
            if (huggingface) {
                if (huggingface.license) {
                    aiPackage.licenseConcluded = huggingface.license;
                }
                
                // Information about application
                aiPackage.informationAboutApplication = huggingface.verified
                    ? `HuggingFace model for ${huggingface.pipeline_tag || modelType || 'AI tasks'}. Downloads: ${huggingface.downloads?.toLocaleString()}, Likes: ${huggingface.likes}`
                    : `HuggingFace model: ${modelName} (unverified)`;
                
                // Hyperparameters (if available from tags)
                const hyperparams = huggingface.tags?.filter(t => 
                    t.includes('parameter') || t.includes('size') || t.includes('layers')
                );
                if (hyperparams && hyperparams.length > 0) {
                    aiPackage.hyperparameter = hyperparams.map(h => ({
                        'type': 'DictionaryEntry',
                        'key': 'parameter',
                        'value': h
                    }));
                }
                
                // Download location
                aiPackage.downloadLocation = `https://huggingface.co/${modelName}`;
                
                // External identifier
                aiPackage.externalIdentifier = [{
                    'type': 'ExternalIdentifier',
                    'externalIdentifierType': 'purl',
                    'identifier': `pkg:huggingface/${modelName}`
                }];
            } else {
                // Commercial model (OpenAI, Anthropic, Google, etc.)
                aiPackage.downloadLocation = 'NOASSERTION';
                
                // Set informationAboutApplication based on provider and type
                if (modelType === 'embeddings') {
                    aiPackage.informationAboutApplication = `${provider} embedding model for semantic search and vector operations`;
                } else if (modelType === 'text-to-image') {
                    aiPackage.informationAboutApplication = `${provider} image generation model`;
                } else {
                    aiPackage.informationAboutApplication = `Commercial AI model from ${provider}`;
                }
                
                aiPackage.externalIdentifier = [{
                    'type': 'ExternalIdentifier',
                    'externalIdentifierType': 'purl',
                    'identifier': `pkg:ml/${provider.toLowerCase()}/${modelName}`
                }];
            }
            
            // Add limitation if known
            if (finding.severity === 'medium' || finding.severity === 'low') {
                aiPackage.limitation = 'Detection confidence may vary. Manual verification recommended.';
            }
            
            spdx.element.push(aiPackage);
            
            // Create relationship: repository DEPENDS_ON aiPackage
            relationships.push({
                '@id': `${namespace}/Relationship-${idx}`,
                'type': 'Relationship',
                'spdxId': `${namespace}/Relationship-${idx}`,
                'creationInfo': {
                    'type': 'CreationInfo',
                    'specVersion': '3.0.1',
                    'created': analyzedAt,
                    'createdBy': ['Tool: AI BOM Generator-1.0.0']
                },
                'relationshipType': 'dependsOn',
                'from': repoId,
                'to': [aiId],
                'completeness': 'noAssertion'
            });
        } else if (finding.artifactInfo || finding.attestationInfo) {
            // R1/R4: state-metadata findings — handled via checksums and the
            // repository attestation comment; not packages of their own.
            return;
        } else {
            // Regular library package with clean identity (no "Dependency: "
            // prefix, no placeholder version; version omitted when unknown).
            const identity = resolveLibraryIdentity(finding);
            const libId = `${namespace}/Package-${generateShortId()}`;
            const libPackage = {
                '@id': libId,
                'type': 'software_Package',
                'spdxId': libId,
                'creationInfo': {
                    'type': 'CreationInfo',
                    'specVersion': '3.0.1',
                    'created': analyzedAt,
                    'createdBy': ['Tool: AI BOM Generator-1.0.0']
                },
                'name': identity.name,
                'summary': finding.description,
                'downloadLocation': 'NOASSERTION',
                'primaryPurpose': 'library'
            };
            if (identity.version) {
                libPackage.packageVersion = identity.version;
            }
            const purl = buildLibraryPurl(identity.name, identity.version, identity.ecosystem);
            if (purl) {
                libPackage.externalIdentifier = [{
                    'type': 'ExternalIdentifier',
                    'externalIdentifierType': 'purl',
                    'identifier': purl
                }];
            }

            // Preserve detection evidence as a package comment.
            const evidenceLines = (finding.evidence || [])
                .filter(ev => ev.file)
                .map(ev => `Detected at ${ev.file}${ev.line && ev.line > 0 ? `:${ev.line}` : ''}${ev.snippet ? ` — ${ev.snippet}` : ''}`);
            if (evidenceLines.length > 0) {
                libPackage.comment = evidenceLines.join('\n');
            }

            spdx.element.push(libPackage);
            
            relationships.push({
                '@id': `${namespace}/Relationship-lib-${idx}`,
                'type': 'Relationship',
                'spdxId': `${namespace}/Relationship-lib-${idx}`,
                'creationInfo': {
                    'type': 'CreationInfo',
                    'specVersion': '3.0.1',
                    'created': analyzedAt,
                    'createdBy': ['Tool: AI BOM Generator-1.0.0']
                },
                'relationshipType': 'dependsOn',
                'from': repoId,
                'to': [libId],
                'completeness': 'noAssertion'
            });
        }
    });
    
    // Add MCP servers as packages
    const mcpFindings = selectedFindings.filter(f => 
        f.category === 'protocol' && 
        (f.protocolInfo?.type === 'mcp' || f.protocolInfo?.type === 'mcp-server')
    );
    
    const seenMcpServers = new Set();
    let mcpIdx = 0;
    
    mcpFindings.forEach(finding => {
        // Handle MCP config with parsed servers
        if (finding.protocolInfo?.parsedServers) {
            for (const server of finding.protocolInfo.parsedServers) {
                if (seenMcpServers.has(server.name)) continue;
                seenMcpServers.add(server.name);
                
                const mcpId = `${namespace}/MCPServer-${generateShortId()}`;
                const mcpPackage = {
                    '@id': mcpId,
                    'type': 'software_Package',
                    'spdxId': mcpId,
                    'creationInfo': {
                        'type': 'CreationInfo',
                        'specVersion': '3.0.1',
                        'created': analyzedAt,
                        'createdBy': ['Tool: AI BOM Generator-1.0.0']
                    },
                    'name': `mcp-server-${server.name}`,
                    'summary': server.description || `MCP server providing ${server.category || 'AI tool'} capabilities`,
                    'packageVersion': 'configured',
                    'downloadLocation': 'NOASSERTION',
                    'primaryPurpose': 'application',
                    'comment': `MCP Server Category: ${server.category || 'unknown'}. Capabilities: ${(server.capabilities || []).join(', ') || 'N/A'}`
                };
                
                // Add provider if available
                if (server.provider) {
                    mcpPackage.suppliedBy = {
                        'type': 'Organization',
                        'name': server.provider
                    };
                }
                
                // Add PURL
                mcpPackage.externalIdentifier = [{
                    'type': 'ExternalIdentifier',
                    'externalIdentifierType': 'purl',
                    'identifier': getMCPServerPurl(server)
                }];
                
                spdx.element.push(mcpPackage);
                
                relationships.push({
                    '@id': `${namespace}/Relationship-mcp-${mcpIdx}`,
                    'type': 'Relationship',
                    'spdxId': `${namespace}/Relationship-mcp-${mcpIdx}`,
                    'creationInfo': {
                        'type': 'CreationInfo',
                        'specVersion': '3.0.1',
                        'created': analyzedAt,
                        'createdBy': ['Tool: AI BOM Generator-1.0.0']
                    },
                    'relationshipType': 'dependsOn',
                    'from': repoId,
                    'to': [mcpId],
                    'completeness': 'noAssertion'
                });
                
                mcpIdx++;
            }
        }
        
        // Handle individual MCP server finding
        if (finding.protocolInfo?.type === 'mcp-server') {
            const serverName = finding.protocolInfo.serverName;
            if (seenMcpServers.has(serverName)) return;
            seenMcpServers.add(serverName);
            
            const mcpId = `${namespace}/MCPServer-${generateShortId()}`;
            const mcpPackage = {
                '@id': mcpId,
                'type': 'software_Package',
                'spdxId': mcpId,
                'creationInfo': {
                    'type': 'CreationInfo',
                    'specVersion': '3.0.1',
                    'created': analyzedAt,
                    'createdBy': ['Tool: AI BOM Generator-1.0.0']
                },
                'name': `mcp-server-${serverName}`,
                'summary': finding.description,
                'packageVersion': 'configured',
                'downloadLocation': 'NOASSERTION',
                'primaryPurpose': 'application',
                'comment': `MCP Server Category: ${finding.protocolInfo.serverCategory || 'unknown'}. Capabilities: ${(finding.protocolInfo.capabilities || []).join(', ') || 'N/A'}`
            };
            
            if (finding.protocolInfo.provider) {
                mcpPackage.suppliedBy = {
                    'type': 'Organization',
                    'name': finding.protocolInfo.provider
                };
            }
            
            mcpPackage.externalIdentifier = [{
                'type': 'ExternalIdentifier',
                'externalIdentifierType': 'purl',
                'identifier': getMCPServerPurl({ name: serverName })
            }];
            
            spdx.element.push(mcpPackage);
            
            relationships.push({
                '@id': `${namespace}/Relationship-mcp-${mcpIdx}`,
                'type': 'Relationship',
                'spdxId': `${namespace}/Relationship-mcp-${mcpIdx}`,
                'creationInfo': {
                    'type': 'CreationInfo',
                    'specVersion': '3.0.1',
                    'created': analyzedAt,
                    'createdBy': ['Tool: AI BOM Generator-1.0.0']
                },
                'relationshipType': 'dependsOn',
                'from': repoId,
                'to': [mcpId],
                'completeness': 'noAssertion'
            });
            
            mcpIdx++;
        }
    });
    
    // Add all relationships to element array
    spdx.element.push(...relationships);
    
    return JSON.stringify(spdx, null, 2);
}

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

/**
 * Extract model metadata from findings for main component properties
 */
function extractModelMetadata(findings) {
    const modelFindings = findings.filter(f => f.modelInfo && f.modelInfo.huggingface);
    const metadata = {
        primaryPurpose: null,
        suppliedBy: null,
        typeOfModel: null,
        domain: null
    };
    
    if (modelFindings.length === 0) {
        return metadata;
    }
    
    // Extract from first HuggingFace model (most representative)
    const firstModel = modelFindings[0].modelInfo.huggingface;
    
    if (firstModel) {
        metadata.primaryPurpose = firstModel.primaryPurpose || firstModel.pipeline_tag || 'text-generation';
        metadata.suppliedBy = firstModel.suppliedBy || firstModel.author;
        metadata.typeOfModel = firstModel.typeOfModel || firstModel.config?.model_type || 'transformer';
        
        // Extract domain from tags
        const tags = firstModel.tags || [];
        const domainTags = tags.filter(t => 
            ['medical', 'healthcare', 'finance', 'legal', 'education', 'research', 'nlp', 'cv', 'multimodal'].some(d => 
                t.toLowerCase().includes(d)
            )
        );
        if (domainTags.length > 0) {
            metadata.domain = domainTags[0];
        }
    }
    
    return metadata;
}

/**
 * Extract hardware information from findings
 */
function extractHardwareInfo(findings) {
    const hardwareFindings = findings.filter(f => f.category === 'hardware');
    const info = {
        detected: hardwareFindings.length > 0,
        types: [],
        libraries: [],
        models: []  // Specific GPU/TPU models (A10G, H100, etc.)
    };
    
    for (const finding of hardwareFindings) {
        if (finding.hardwareInfo) {
            info.types.push(finding.hardwareInfo.type);
            if (finding.hardwareInfo.libraries) {
                info.libraries.push(...finding.hardwareInfo.libraries);
            }
            if (finding.hardwareInfo.models) {
                info.models.push(...finding.hardwareInfo.models);
            }
        }
    }
    
    info.types = [...new Set(info.types)];
    info.models = [...new Set(info.models)];
    info.libraries = [...new Set(info.libraries)];
    
    return info;
}

/**
 * Extract infrastructure information from findings
 */
function extractInfraInfo(findings) {
    const infraFindings = findings.filter(f => f.category === 'infrastructure');
    const info = {
        detected: infraFindings.length > 0,
        platforms: {
            containerization: [],
            orchestration: [],
            cloud: [],
            mlops: []
        }
    };
    
    for (const finding of infraFindings) {
        if (finding.infraInfo) {
            const type = finding.infraInfo.type;
            const platforms = finding.infraInfo.platforms || [];
            
            if (type in info.platforms) {
                info.platforms[type].push(...platforms);
            }
        }
    }
    
    // Deduplicate
    for (const key in info.platforms) {
        info.platforms[key] = [...new Set(info.platforms[key])];
    }
    
    return info;
}

/**
 * Extract governance information from findings
 */
function extractGovernanceInfo(findings) {
    const governanceFindings = findings.filter(f => f.category === 'governance');
    const info = {
        hasLimitations: false,
        hasBiasFairness: false,
        hasEthical: false,
        count: governanceFindings.length
    };
    
    for (const finding of governanceFindings) {
        if (finding.riskInfo) {
            if (finding.riskInfo.type === 'limitations') info.hasLimitations = true;
            if (finding.riskInfo.type === 'bias-fairness') info.hasBiasFairness = true;
            if (finding.riskInfo.type === 'ethical') info.hasEthical = true;
        }
    }
    
    return info;
}

function escapeXml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
