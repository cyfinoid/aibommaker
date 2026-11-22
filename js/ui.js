// Model Card Loading Utility for UI
// Cache for loaded model cards to avoid multiple fetches
const uiModelCardCache = new Map();

async function loadModelCardUI(modelName, provider) {
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
        if (uiModelCardCache.has(cacheKey)) {
            console.log(`[UI ModelCard] Using cached model card for ${modelName}`);
            return uiModelCardCache.get(cacheKey);
        }

        // Construct the path to the model card JSON file
        const modelCardPath = `modelcards/${normalizedProvider}/${normalizedModelName}.json`;

        console.log(`[UI ModelCard] Attempting to load: ${modelCardPath}`);

        // Fetch the model card JSON
        const response = await fetch(modelCardPath);

        if (!response.ok) {
            console.log(`[UI ModelCard] Model card not found: ${modelCardPath}`);
            return null;
        }

        const modelCardData = await response.json();
        console.log(`[UI ModelCard] Successfully loaded and cached model card for ${modelName}`);

        // Cache the result
        uiModelCardCache.set(cacheKey, modelCardData);

        return modelCardData;

    } catch (error) {
        console.log(`[UI ModelCard] Error loading model card for ${modelName}: ${error.message}`);
        return null;
    }
}

// UI rendering and interaction functions
// ============================================================================
// UI FUNCTIONS
// ============================================================================
function show(element) {
    element.classList.remove('hidden');
}

function hide(element) {
    element.classList.add('hidden');
}

function renderScoreBadge(score, confidence) {
    const badge = document.getElementById('score-badge');
    badge.className = `score-badge ${confidence.level}`;
    badge.textContent = `Score: ${score} - ${confidence.label}`;
}

function renderAnalysisNotes(findings, analysisResult, fileTree = null) {
    const container = document.getElementById('analysis-notes-list');
    container.innerHTML = '';

    // Scan-completeness warnings first (e.g. GitHub tree truncation)
    if (analysisResult?.warnings?.length > 0) {
        const warningSection = document.createElement('div');
        warningSection.className = 'analysis-note-section';
        warningSection.innerHTML = `
            <h3 class="subheading" style="margin-bottom: 1rem; color: var(--status-warning, #b45309);">⚠️ Scan Completeness Warnings</h3>
            ${analysisResult.warnings.map(w => `
                <div class="info-message" style="padding: 0.75rem 1rem; margin-bottom: 0.75rem; border-left: 3px solid var(--status-warning, #b45309); text-align: left;">
                    <p class="body" style="margin: 0;">${escapeHtml(w.message)}</p>
                </div>
            `).join('')}
        `;
        container.appendChild(warningSection);
    }

    // Scan-specific: What we looked for but didn't find in THIS repository
    const notFound = [];
    
    // Check actual file tree for documentation files (not just files referenced in findings)
    // This ensures we detect README.md even if it wasn't referenced in any finding's evidence
    const treeFiles = fileTree ? fileTree.map(f => f.path) : [];
    const allFilesFromFindings = findings.flatMap(f => f.evidence?.map(e => e.file) || []);
    
    // Combine tree files and findings files for comprehensive check
    const allFiles = [...new Set([...treeFiles, ...allFilesFromFindings])];
    
    const hasDependencies = findings.some(f => f.category === 'dependencies');
    const hasModels = findings.some(f => f.modelInfo);
    const hasHardware = findings.some(f => f.category === 'hardware');
    const hasInfrastructure = findings.some(f => f.category === 'infrastructure');
    const hasGovernance = findings.some(f => f.category === 'governance');
    const hasDataPipeline = findings.some(f => 
        f.dependencyInfo?.name?.match(/datasets|pandas|numpy|sklearn|spacy|nltk/)
    );
    
    // Documentation we scanned for but didn't find
    // Check actual file tree, not just files referenced in findings
    const hasReadme = allFiles.some(f => f && f.toLowerCase().includes('readme'));
    if (!hasReadme) {
        notFound.push({
            category: 'Documentation',
            item: 'README.md',
            searched: 'Scanned repository root and subdirectories',
            benefit: 'Would provide project overview, usage instructions, and model documentation'
        });
    }
    
    if (hasModels && !allFiles.some(f => f && f.toLowerCase().includes('model'))) {
        notFound.push({
            category: 'Documentation',
            item: 'MODEL_CARD.md',
            searched: 'Scanned for model card files in repository',
            benefit: 'Would document model intended use, limitations, performance, and ethical considerations'
        });
    }
    
    const hasSecurity = allFiles.some(f => {
        const lower = f.toLowerCase();
        return lower.includes('security') || lower.endsWith('security.txt');
    });
    if (!hasSecurity) {
        notFound.push({
            category: 'Documentation',
            item: 'SECURITY.md or security.txt (RFC 9116)',
            searched: 'Scanned repository root and .well-known/ directory for security policy',
            benefit: 'Would provide vulnerability reporting procedures and security contacts (RFC 9116 standard)'
        });
    }
    
    // Hardware we scanned for but didn't find
    if (!hasHardware && hasDependencies) {
        notFound.push({
            category: 'Hardware',
            item: 'GPU/TPU/Specialized Compute',
            searched: 'Scanned dependencies and code for CUDA, TensorRT, TPU patterns',
            benefit: 'Would document compute requirements and infrastructure needs'
        });
    }
    
    // Infrastructure we scanned for but didn't find
    if (!hasInfrastructure && (hasModels || hasDependencies)) {
        notFound.push({
            category: 'Infrastructure',
            item: 'Deployment Configuration',
            searched: 'Scanned for Dockerfile, docker-compose.yml, Kubernetes configs, cloud platform usage',
            benefit: 'Would document deployment environment and operational requirements'
        });
    }
    
    // Governance we scanned for but didn't find
    if (hasModels && !hasGovernance) {
        notFound.push({
            category: 'Governance',
            item: 'Model Governance Documentation',
            searched: 'Scanned for limitations, ethical considerations, bias/fairness documentation',
            benefit: 'Would document responsible AI practices and model constraints'
        });
    }
    
    // Data pipeline we scanned for but didn't find
    if (hasModels && !hasDataPipeline) {
        notFound.push({
            category: 'Data Pipeline',
            item: 'Data Processing Libraries',
            searched: 'Scanned dependencies for data loading, preprocessing, feature engineering tools',
            benefit: 'Would document data transformation and feature engineering process'
        });
    }
    
    // If everything was found (and no warnings), show a positive message
    if (notFound.length === 0 && !analysisResult?.warnings?.length) {
        container.innerHTML = `
            <div class="info-message" style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">✅ Comprehensive detection achieved</p>
                <p style="font-size: 0.9rem;">All detectable components were found in this repository.</p>
            </div>
        `;
        return;
    }

    // Render what we looked for but didn't find in THIS scan as a compact
    // table: one row per gap, grouped visually by category chip.
    if (notFound.length > 0) {
        const CATEGORY_ICONS = {
            Documentation: '📄',
            Hardware: '🖥️',
            Infrastructure: '☁️',
            Governance: '⚖️',
            'Data Pipeline': '🗂️'
        };
        const rows = notFound.map(item => `
            <tr>
                <td>
                    <span class="analysis-category-chip">${escapeHtml(item.category)}</span>
                    <div class="analysis-gap-item">${CATEGORY_ICONS[item.category] || '🔍'} ${escapeHtml(item.item)}</div>
                </td>
                <td class="analysis-gap-searched">${escapeHtml(item.searched)}</td>
                <td class="analysis-gap-benefit">${escapeHtml(item.benefit)}</td>
            </tr>
        `).join('');

        const notFoundSection = document.createElement('div');
        notFoundSection.className = 'analysis-note-section';
        notFoundSection.innerHTML = `
            <h3 class="subheading" style="margin-bottom: 0.25rem;">🔍 Not Detected in This Repository (${notFound.length})</h3>
            <p class="caption" style="margin-bottom: 1rem;">Each row is an area the scanner actively searched. "Not detected" means the repository shows no trace — the AIBOM omits it rather than guessing.</p>
            <div class="analysis-notes-tablewrap">
                <table class="analysis-notes-table">
                    <thead>
                        <tr><th>Missing</th><th>What we searched</th><th>What it would add</th></tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
        container.appendChild(notFoundSection);
    }
}

async function renderFindings(findings, repoUrl) {
    const container = document.getElementById('findings-list');
    container.innerHTML = '';
    
    if (findings.length === 0) {
        container.innerHTML = '<p class="body" style="text-align: center; color: var(--text-secondary);">No findings</p>';
        return;
    }
    
    // Load model card data for model findings that don't have it:
    // bundled local card first, then the HuggingFace API for HF models
    // (e.g. when the scan-time fetch failed or was rate-limited).
    const hfCardCache = new Map();
    await Promise.all(findings.map(async (finding) => {
        if (finding.modelInfo && !finding.modelInfo.modelCardData &&
            finding.modelInfo.provider && finding.modelInfo.modelName) {
            try {
                let modelCardData = await loadModelCardUI(finding.modelInfo.modelName, finding.modelInfo.provider);

                // Fall back to the HuggingFace API when the model id looks
                // like an HF slug (org/repo) or is HF-attributed — provider
                // signatures like DeepSeek can claim HF-slug models too, and
                // the API 404s honestly for names that aren't on the hub.
                if (!modelCardData &&
                    (finding.modelInfo.provider === 'HuggingFace' || finding.modelInfo.modelName.includes('/'))) {
                    const cacheKey = finding.modelInfo.modelName.toLowerCase();
                    if (hfCardCache.has(cacheKey)) {
                        modelCardData = hfCardCache.get(cacheKey);
                    } else {
                        console.log(`[UI ModelCard] Local card not found, querying HuggingFace API: ${finding.modelInfo.modelName}`);
                        const hfInfo = await fetchHuggingFaceModelInfo(finding.modelInfo.modelName);
                        modelCardData = buildModelCardDataFromHuggingFace(hfInfo, finding.modelInfo.modelName);
                        hfCardCache.set(cacheKey, modelCardData);
                    }
                }

                if (modelCardData) {
                    finding.modelInfo.modelCardData = modelCardData;
                }
            } catch (error) {
                console.log(`[UI] Failed to load model card for finding ${finding.id}: ${error.message}`);
            }
        }
    }));

    findings.forEach((finding, index) => {
        const item = document.createElement('div');
        item.className = 'finding-item';
        item.dataset.category = finding.category;
        item.dataset.findingIndex = index;
        
        const collapseIcon = document.createElement('span');
        collapseIcon.className = 'finding-collapse-icon';
        collapseIcon.textContent = '▼';
        collapseIcon.onclick = () => toggleFinding(item);
        
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'finding-checkbox';
        checkbox.checked = true;
        checkbox.dataset.findingId = finding.id;
        
        const titleRow = document.createElement('div');
        titleRow.className = 'finding-title-row';
        titleRow.style.cursor = 'pointer';
        titleRow.onclick = (e) => {
            if (e.target !== checkbox) toggleFinding(item);
        };
        
        titleRow.innerHTML = `
            <div class="finding-title">${finding.title}</div>
            <span class="category-badge ${finding.category}">${finding.category}</span>
            <span class="severity-badge ${finding.severity}">${finding.severity}</span>
        `;
        
        const details = document.createElement('div');
        details.className = 'finding-details';
        // Check if this is a model finding with model card data
        let modelCardHtml = '';
        if (finding.modelInfo && finding.modelInfo.modelCardData) {
            const modelCard = finding.modelInfo.modelCardData;
            const intendedUseText = formatModelCardField(modelCard.intendedUse, {
                primaryUses: '',
                primaryUseCases: '',
                outOfScope: 'Out of scope'
            });
            const limitationsText = formatModelCardField(modelCard.limitations, {
                knownLimitations: ''
            });
            const trainingDataText = formatModelCardField(modelCard.trainingData, {
                description: ''
            });
            modelCardHtml = `
                <div class="model-card-section">
                    <h4>📋 Model Card Information</h4>
                    <div class="model-card-content">
                        ${modelCard.description ? `<p><strong>Description:</strong> ${escapeHtml(String(modelCard.description))}</p>` : ''}
                        ${intendedUseText ? `<p><strong>Intended Use:</strong> ${escapeHtml(intendedUseText)}</p>` : ''}
                        ${limitationsText ? `<p><strong>Limitations:</strong> ${escapeHtml(limitationsText)}</p>` : ''}
                        ${trainingDataText ? `<p><strong>Training Data:</strong> ${escapeHtml(trainingDataText)}</p>` : ''}
                        ${modelCard.architecture && modelCard.architecture.contextLength ? `<p><strong>Context Length:</strong> ${modelCard.architecture.contextLength}</p>` : ''}
                        ${modelCard.capabilities && modelCard.capabilities.length > 0 ? `<p><strong>Capabilities:</strong> ${modelCard.capabilities.join(', ')}</p>` : ''}
                        ${modelCard.ethicalConsiderations ? `
                            <div class="ethical-considerations">
                                <strong>Ethical Considerations:</strong>
                                ${modelCard.ethicalConsiderations.biasAndFairness ? `<p><strong>Bias & Fairness:</strong> ${modelCard.ethicalConsiderations.biasAndFairness}</p>` : ''}
                                ${modelCard.ethicalConsiderations.safetyMeasures ? `<p><strong>Safety Measures:</strong> ${modelCard.ethicalConsiderations.safetyMeasures}</p>` : ''}
                                ${modelCard.ethicalConsiderations.privacyConsiderations ? `<p><strong>Privacy:</strong> ${modelCard.ethicalConsiderations.privacyConsiderations}</p>` : ''}
                            </div>
                        ` : ''}
                        ${(() => {
                            if (!modelCard.references || typeof modelCard.references !== 'object') return '';
                            const REFERENCE_LABELS = {
                                modelPage: '🌐 Model Page',
                                pricing: '💰 Pricing',
                                announcement: '📣 Announcement',
                                huggingFace: '🤗 HuggingFace',
                                paper: '📄 Paper',
                                modelSpecificDocs: '📖 Official Documentation',
                                officialDocs: '🏢 Provider Documentation',
                                securityContact: '🔐 Security Contact'
                            };
                            const links = Object.entries(modelCard.references)
                                .filter(([, url]) => typeof url === 'string' && /^https?:\/\//i.test(url))
                                .map(([key, url]) => {
                                    const label = REFERENCE_LABELS[key] ||
                                        key.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, c => c.toUpperCase());
                                    const safeUrl = escapeHtml(url).replace(/"/g, '&quot;');
                                    return `<p><a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${label}</a></p>`;
                                })
                                .join('');
                            return links ? `
                                <div class="model-references">
                                    <strong>References:</strong>
                                    ${links}
                                </div>
                            ` : '';
                        })()}
                    </div>
                </div>
            `;
        }

        details.innerHTML = `
            <p class="finding-description">${finding.description}</p>
            ${finding.evidence && finding.evidence.length > 0 ? `
                <div class="finding-evidence">
                    ${finding.evidence.slice(0, 5).map(ev => {
                        // Build GitHub link with line number anchor
                        let fileUrl = ev.url;

                        // If we have a direct URL from GitHub API, use it (preserves commit SHA)
                        if (!fileUrl) {
                            // Build URL from repo URL and file path (fallback)
                            fileUrl = `${repoUrl}/blob/main/${ev.file}`;
                        }

                        // Ensure URL has line anchor if we have line number
                        if (ev.line && ev.line > 0) {
                            // Remove existing line anchor if present, add correct one
                            fileUrl = fileUrl.replace(/#L\d+$/, '') + `#L${ev.line}`;
                        }

                        const fileDisplay = ev.line && ev.line > 0
                            ? `${ev.file}:${ev.line}`
                            : ev.file;

                        // Use snippet if available - show actual code, not generic message
                        let snippetText = null;
                        if (ev.snippet) {
                            // Only show snippet if it's actual code (not generic messages)
                            if (ev.snippet !== 'Found via GitHub Code Search' &&
                                ev.snippet !== 'Found at line ' + ev.line &&
                                ev.snippet.trim().length > 0) {
                                snippetText = ev.snippet;
                            }
                        }

                        // If no snippet but we have line number, show that
                        if (!snippetText && ev.line) {
                            snippetText = `Found at line ${ev.line}`;
                        }

                        return `
                        <div class="evidence-item">
                            <a class="evidence-file" href="${fileUrl}" target="_blank">${fileDisplay}</a>
                            ${snippetText ? `<pre class="evidence-snippet">${escapeHtml(snippetText)}</pre>` : ''}
                        </div>
                    `;
                    }).join('')}
                </div>
            ` : ''}
            ${modelCardHtml}
        `;
        
        const header = document.createElement('div');
        header.className = 'finding-header';
        header.appendChild(collapseIcon);
        header.appendChild(checkbox);
        
        const info = document.createElement('div');
        info.className = 'finding-info';
        info.appendChild(titleRow);
        info.appendChild(details);
        
        header.appendChild(info);
        item.appendChild(header);
        container.appendChild(item);
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function toggleFinding(item) {
    item.classList.toggle('collapsed');
}

function filterFindings(category) {
    const items = document.querySelectorAll('.finding-item');
    items.forEach(item => {
        if (category === 'all' || item.dataset.category === category) {
            show(item);
        } else {
            hide(item);
        }
    });
}

function selectAllFindings(selected) {
    const checkboxes = document.querySelectorAll('.finding-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = selected;
        cb.dispatchEvent(new Event('change'));
    });
}

function getSelectedFindings(allFindings) {
    const checkboxes = document.querySelectorAll('.finding-checkbox:checked');
    const selectedIds = new Set(Array.from(checkboxes).map(cb => cb.dataset.findingId));
    return allFindings.filter(f => selectedIds.has(f.id));
}

/**
 * Download one generated BOM document by format key.
 * @param {string} format 'cyclonedx-json' | 'cyclonedx-xml' | 'spdx' | 'extended-aibom'
 */
function downloadBOMFile(format) {
    const content = generatedBOMs[format];
    if (!content) return;
    const repo = currentAnalysis.repository.repo;
    const date = new Date().toISOString().split('T')[0];
    let ext, name;

    if (format === 'extended-aibom') {
        ext = 'json';
        name = 'extended-aibom';
    } else {
        ext = format.includes('xml') ? 'xml' : 'json';
        name = format.includes('spdx') ? 'spdx' : 'cyclonedx';
    }

    downloadFile(content, `${repo}-aibom-${name}-${date}.${ext}`,
               ext === 'xml' ? 'application/xml' : 'application/json');
    showToast('Downloaded!');
}

function renderBOMPreview(format, content) {
    const preview = document.getElementById(`${format}-preview`);
    if (!preview) return;
    
    // For JSON formats, add syntax highlighting
    if (format.includes('json') || format === 'spdx') {
        preview.innerHTML = highlightJSON(content);
    } else if (format.includes('xml')) {
        preview.innerHTML = highlightXML(content);
    } else {
        preview.textContent = content;
    }
}

function highlightJSON(json) {
    return json
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?)/g, (match) => {
            let cls = 'json-string';
            if (/:$/.test(match)) {
                cls = 'json-key';
            }
            return `<span class="${cls}">${match}</span>`;
        })
        .replace(/\b(true|false|null)\b/g, '<span class="json-boolean">$1</span>')
        .replace(/\b(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b/g, '<span class="json-number">$1</span>');
}

function highlightXML(xml) {
    return xml
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/(&lt;\/?)([\w-:]+)/g, '$1<span class="xml-tag">$2</span>')
        .replace(/([\w-:]+)=(".*?")/g, '<span class="xml-attr">$1</span>=<span class="xml-value">$2</span>');
}

function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    document.querySelectorAll('.tab-content').forEach(content => {
        if (content.id === tabName) {
            content.classList.add('active');
        } else {
            content.classList.remove('active');
        }
    });
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        return false;
    }
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed; bottom: 20px; right: 20px; padding: 1rem 2rem;
        background: ${type === 'success' ? 'var(--text-primary)' : 'var(--accent-red)'};
        color: ${type === 'success' ? 'var(--bg-primary)' : 'var(--text-light)'};
        border-radius: 4px; font-family: var(--font-family); font-size: var(--font-body);
        font-weight: 700; z-index: 1000;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => document.body.removeChild(toast), 3000);
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================
let currentAnalysis = null;
let currentFindings = [];
let generatedBOMs = { 'cyclonedx-json': null, 'cyclonedx-xml': null, 'spdx': null };

document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeToggle(savedTheme);
    
    // Theme toggle
    document.getElementById('theme-toggle').addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeToggle(newTheme);
    });
    
    const form = document.getElementById('analysis-form');
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const repoInput = document.getElementById('repo-input').value.trim();
        const token = document.getElementById('token-input').value.trim();
        
        if (!repoInput) {
            alert('Please enter a repository');
            return;
        }
        
        if (!token) {
            alert('GitHub token is required. Please provide a GitHub Personal Access Token.');
            return;
        }
        
        try {
            hide(document.getElementById('findings-section'));
            hide(document.getElementById('bom-section'));
            hide(document.getElementById('compliance-section'));
            hide(form);
            show(document.getElementById('loading-state'));
            document.getElementById('loading-message').textContent = 'Parsing input...';
            
            const scanStartTime = new Date();
            console.log('\n' + '🚀'.repeat(40));
            console.log('🔍 AI BOM Generator - Scan Started');
            console.log(`📅 Date: ${scanStartTime.toLocaleDateString()}`);
            console.log(`⏰ Time: ${scanStartTime.toLocaleTimeString()}`);
            console.log('🚀'.repeat(40) + '\n');
            
            const { owner, repo, ref } = parseRepoInput(repoInput);
            
            document.getElementById('loading-message').textContent = 'Fetching repository...';
            const repoMeta = await fetchRepoMeta(owner, repo, token);
            
            document.getElementById('loading-message').textContent = 'Fetching file tree...';
            const tree = await fetchRepoTree(owner, repo, ref || repoMeta.defaultBranch, token);
            
            const getFileContent = createFileContentFetcher(owner, repo, ref || repoMeta.defaultBranch, token);
            
            const result = await analyzeRepository(
                { owner, repo, repoMeta, tree, getFileContent, token, ref: ref || repoMeta.defaultBranch },
                (progress) => {
                    document.getElementById('loading-message').textContent = 
                        `${progress.message} (${progress.step}/${progress.total})`;
                }
            );
            
            currentAnalysis = result;
            currentFindings = result.findings;
            
            const scanEndTime = new Date();
            const scanDuration = scanEndTime - scanStartTime;
            const scanDurationSec = (scanDuration / 1000).toFixed(2);
            
            console.log('\n' + '✅'.repeat(40));
            console.log('✅ Scan Complete - Summary');
            console.log('✅'.repeat(40));
            console.log(`📦 Repository:     ${result.repository.fullName}`);
            console.log(`⏱️  Total Duration: ${scanDuration}ms (${scanDurationSec}s)`);
            console.log(`📝 Findings:       ${result.findings.length} total`);
            console.log(`🏷️  Categories:     ${new Set(result.findings.map(f => f.category)).size} unique`);
            console.log(`⏰ Completed:      ${scanEndTime.toLocaleTimeString()}`);
            console.log('✅'.repeat(40) + '\n');
            
            hide(document.getElementById('loading-state'));
            show(form);
            show(document.getElementById('findings-section'));
            show(document.getElementById('analysis-notes-section'));
            show(document.getElementById('bom-section'));
            show(document.getElementById('compliance-section'));
            
            // Score badge removed - AIBOM focuses on what's found, not scoring
            // renderScoreBadge(result.score, result.confidence);
            await renderFindings(result.findings, result.repository.htmlUrl);
            // Pass file tree to check for documentation files that may not be in findings evidence
            renderAnalysisNotes(result.findings, result, tree);
            await regenerateBOMs();
            
            document.getElementById('findings-section').scrollIntoView({ behavior: 'smooth' });
        } catch (error) {
            hide(document.getElementById('loading-state'));
            show(document.getElementById('error-state'));
            document.getElementById('error-message').textContent = error.message;
        }
    });
    
    document.getElementById('retry-btn').addEventListener('click', () => {
        hide(document.getElementById('error-state'));
        show(document.getElementById('analysis-form'));
    });
    
    document.getElementById('select-all-btn').addEventListener('click', async () => {
        selectAllFindings(true);
        await regenerateBOMs();
    });

    document.getElementById('deselect-all-btn').addEventListener('click', async () => {
        selectAllFindings(false);
        await regenerateBOMs();
    });
    
    document.getElementById('category-filter').addEventListener('change', (e) => {
        filterFindings(e.target.value);
    });
    
    document.addEventListener('change', async (e) => {
        if (e.target.classList.contains('finding-checkbox')) {
            await regenerateBOMs();
        }
    });
    
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
    
    document.addEventListener('click', (e) => {
        if (e.target.dataset.action === 'copy') {
            const content = generatedBOMs[e.target.dataset.format];
            if (content) {
                copyToClipboard(content).then(ok => {
                    showToast(ok ? 'Copied!' : 'Copy failed', ok ? 'success' : 'error');
                });
            }
        } else if (e.target.dataset.action === 'download') {
            downloadBOMFile(e.target.dataset.format);
        } else if (e.target.dataset.action === 'toggle-content') {
            // Previews are collapsed by default — the actions row is the
            // primary surface. Toggle the raw document view on demand.
            const format = e.target.dataset.format;
            const pre = document.getElementById(`${format}-preview`);
            if (pre) {
                const collapsed = pre.classList.toggle('collapsed');
                e.target.textContent = collapsed ? 'Show content' : 'Hide content';
                e.target.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
            }
        }
    });
    
    // Collapse/Expand the Analysis Results section (collapsed by default —
    // the review flow is: scan → review findings → generate BOM below)
    document.getElementById('collapse-all-findings').addEventListener('click', function() {
        const content = document.getElementById('findings-content');
        const collapsed = content.classList.toggle('collapsed');
        this.textContent = collapsed ? 'Expand' : 'Collapse';
    });
    
    // Collapse/Expand Analysis Notes section
    document.getElementById('collapse-analysis-notes').addEventListener('click', function() {
        const content = document.getElementById('analysis-notes-content');
        content.classList.toggle('collapsed');
        this.textContent = content.classList.contains('collapsed') ? 'Expand' : 'Collapse';
    });
    
    // Collapse/Expand BOM section
    document.getElementById('collapse-bom').addEventListener('click', function() {
        const content = document.getElementById('bom-content-wrapper');
        content.classList.toggle('collapsed');
        this.textContent = content.classList.contains('collapsed') ? 'Expand' : 'Collapse';
    });

    // Collapse/Expand Standards Compliance section
    document.getElementById('collapse-compliance').addEventListener('click', function() {
        const content = document.getElementById('compliance-wrapper');
        content.classList.toggle('collapsed');
        this.textContent = content.classList.contains('collapsed') ? 'Expand' : 'Collapse';
    });

    // Download all four BOM formats at once (staggered — browsers throttle
    // multiple simultaneous programmatic downloads)
    document.getElementById('download-all-bom').addEventListener('click', function() {
        const formats = ['cyclonedx-json', 'cyclonedx-xml', 'spdx', 'extended-aibom'];
        const isPlaceholder = (c) => {
            const t = c.trim();
            return t.startsWith('//') || t.startsWith('<!--');
        };
        formats.forEach((format, index) => {
            if (generatedBOMs[format] && !isPlaceholder(generatedBOMs[format])) {
                setTimeout(() => downloadBOMFile(format), index * 400);
            }
        });
        showToast('Downloading all BOM formats…', 'success');
    });
});

async function regenerateBOMs() {
    if (!currentAnalysis) return;
    
    const selected = getSelectedFindings(currentFindings);
    
    console.log('\n' + '📄'.repeat(40));
    console.log('📄 BOM Generation Started');
    console.log(`📊 Selected Findings: ${selected.length}`);
    
    if (selected.length === 0) {
        // Keep generatedBOMs in sync with the previews so the compliance tab
        // (and copy/download) never validate stale documents from a previous
        // selection.
        generatedBOMs['cyclonedx-json'] = '// No findings selected';
        generatedBOMs['cyclonedx-xml'] = '<!-- No findings selected -->';
        generatedBOMs['spdx'] = '// No findings selected';
        generatedBOMs['extended-aibom'] = '// No findings selected';
        renderBOMPreview('cyclonedx-json', generatedBOMs['cyclonedx-json']);
        renderBOMPreview('cyclonedx-xml', generatedBOMs['cyclonedx-xml']);
        renderBOMPreview('spdx', generatedBOMs['spdx']);
        renderBOMPreview('extended-aibom', generatedBOMs['extended-aibom']);
        renderComplianceSection();
        console.log('[BOM] ⚠️  No findings selected, showing placeholder');
        console.log('📄'.repeat(40) + '\n');
        return;
    }
    
    try {
        const startTime = performance.now();
        
        console.log('[BOM] Generating CycloneDX JSON...');
        generatedBOMs['cyclonedx-json'] = await generateCycloneDXJson(currentAnalysis, selected);
        renderBOMPreview('cyclonedx-json', generatedBOMs['cyclonedx-json']);
        const jsonSize = (generatedBOMs['cyclonedx-json'].length / 1024).toFixed(2);
        console.log(`[BOM] ✓ CycloneDX JSON generated (${jsonSize} KB)`);
        
        console.log('[BOM] Generating CycloneDX XML...');
        generatedBOMs['cyclonedx-xml'] = await generateCycloneDXXml(currentAnalysis, selected);
        renderBOMPreview('cyclonedx-xml', generatedBOMs['cyclonedx-xml']);
        const xmlSize = (generatedBOMs['cyclonedx-xml'].length / 1024).toFixed(2);
        console.log(`[BOM] ✓ CycloneDX XML generated (${xmlSize} KB)`);
        
        console.log('[BOM] Generating SPDX...');
        generatedBOMs['spdx'] = generateSPDX(currentAnalysis, selected);
        renderBOMPreview('spdx', generatedBOMs['spdx']);
        const spdxSize = (generatedBOMs['spdx'].length / 1024).toFixed(2);
        console.log(`[BOM] ✓ SPDX generated (${spdxSize} KB)`);
        
        console.log('[BOM] Generating Extended AIBOM...');
        generatedBOMs['extended-aibom'] = await generateExtendedAIBOM(currentAnalysis, selected);
        renderBOMPreview('extended-aibom', generatedBOMs['extended-aibom']);
        const extendedSize = (generatedBOMs['extended-aibom'].length / 1024).toFixed(2);
        console.log(`[BOM] ✓ Extended AIBOM generated (${extendedSize} KB)`);
        
        const elapsed = (performance.now() - startTime).toFixed(2);
        console.log(`\n[BOM] ⏱️  Generation time: ${elapsed}ms`);
        console.log(`[BOM] 📊 Total size: ${(parseFloat(jsonSize) + parseFloat(xmlSize) + parseFloat(spdxSize)).toFixed(2)} KB`);
        console.log('📄'.repeat(40) + '\n');

        renderComplianceSection();
    } catch (error) {
        console.error('[BOM] ❌ Error generating BOMs:', error);
        console.log('📄'.repeat(40) + '\n');
        showToast('Error generating BOM: ' + error.message, 'error');
    }
}

// ============================================================================
// STANDARDS COMPLIANCE TAB
// ============================================================================

const COMPLIANCE_STATUS_META = {
    pass:   { icon: '✓', cls: 'pass',  label: 'PASS' },
    met:    { icon: '✓', cls: 'pass',  label: 'MET' },
    warn:   { icon: '△', cls: 'warn',  label: 'PARTIAL' },
    partial:{ icon: '△', cls: 'warn',  label: 'PARTIAL' },
    fail:   { icon: '✗', cls: 'fail',  label: 'MISSING' },
    unmet:  { icon: '✗', cls: 'fail',  label: 'MISSING' }
};

function complianceStatusPill(status) {
    const meta = COMPLIANCE_STATUS_META[status] || COMPLIANCE_STATUS_META.fail;
    return `<span class="status-pill ${meta.cls}">${meta.icon} ${meta.label}</span>`;
}

function complianceReportHtml(report, index) {
    const passed = report.checks.filter((c) => c.status === 'pass').length;
    const warned = report.checks.filter((c) => c.status === 'warn').length;
    const failed = report.checks.filter((c) => c.status === 'fail').length;
    const open = index === 0 ? ' open' : '';
    const rows = report.checks.map((check) => `
        <tr>
            <td class="compliance-check-label">${check.label}</td>
            <td>${complianceStatusPill(check.status)}</td>
            <td class="compliance-check-detail">${escapeHtml(check.detail || '')}</td>
        </tr>
    `).join('');
    return `
        <details class="compliance-report" ${open}>
            <summary>
                <strong>${report.standard}</strong>
                <span class="compliance-report-format">(${report.format})</span>
                <span class="compliance-report-tally">
                    ${passed} pass · ${warned} partial · ${failed} missing
                </span>
            </summary>
            <table class="compliance-table">
                <tbody>${rows}</tbody>
            </table>
        </details>
    `;
}

function complianceScorecardHtml() {
    const headline = AIBOM_SCORECARD.map((docEntry) => {
        const stats = computeScorecardStats(docEntry);
        return `
            <tr>
                <td>${docEntry.name}</td>
                <td><strong>${stats.weightedPct.toFixed(1)}%</strong> (${stats.score}/${stats.total})</td>
                <td>${stats.strictPct.toFixed(1)}% (${stats.met}/${stats.total})</td>
                <td>${complianceStatusPill('met')} ${stats.met}</td>
                <td>${complianceStatusPill('partial')} ${stats.partial}</td>
                <td>${complianceStatusPill('unmet')} ${stats.unmet}${stats.structural ? ` <span class="compliance-structural">(${stats.structural} structural)</span>` : ''}</td>
            </tr>
        `;
    }).join('');

    const details = AIBOM_SCORECARD.map((docEntry) => {
        const stats = computeScorecardStats(docEntry);
        let lastCluster = null;
        const rows = docEntry.rows.map((row) => {
            const clusterCell = row.cluster && row.cluster !== lastCluster
                ? `<td class="compliance-cluster">${escapeHtml(row.cluster)}</td>`
                : '<td class="compliance-cluster"></td>';
            if (row.cluster) lastCluster = row.cluster;
            const structural = row.structural
                ? ' <span class="compliance-structural" title="Not derivable by a post-hoc, browser-only scanner">⛔</span>'
                : '';
            return `
                <tr>
                    <td class="compliance-num">${row.n}</td>
                    ${docEntry.clusters ? clusterCell : ''}
                    <td class="compliance-check-label">${escapeHtml(row.element)}</td>
                    <td>${complianceStatusPill(row.status)}${structural}</td>
                    <td class="compliance-check-detail">${escapeHtml(row.note || '')}</td>
                </tr>
            `;
        }).join('');
        const columns = docEntry.clusters
            ? '<th>#</th><th>Cluster</th><th>Element</th><th>Status</th><th>Where / Why</th>'
            : '<th>#</th><th>Element</th><th>Status</th><th>Where / Why</th>';
        return `
            <details class="compliance-report">
                <summary>
                    <strong>${docEntry.name}</strong>
                    <span class="compliance-report-tally">
                        weighted ${stats.weightedPct.toFixed(1)}% · strict ${stats.strictPct.toFixed(1)}%
                    </span>
                </summary>
                <table class="compliance-table">
                    <thead><tr>${columns}</tr></thead>
                    <tbody>${rows}</tbody>
                </table>
                <p class="compliance-source">Source: ${docEntry.ref} · scoring ✅ 1.0 / 🟡 0.5 / ❌ 0 · ⛔ = structural limit for a post-hoc, browser-only scanner</p>
            </details>
        `;
    }).join('');

    return `
        <h4 class="compliance-heading">AIBOM standards scorecard — this tool's output surface</h4>
        <table class="compliance-table compliance-headline">
            <thead>
                <tr><th>Standard</th><th>Weighted</th><th>Strict</th><th colspan="3">Elements</th></tr>
            </thead>
            <tbody>${headline}</tbody>
        </table>
        ${details}
    `;
}

/**
 * Render the Standards Compliance section: dynamic validation of the freshly
 * generated CycloneDX/SPDX/NTIA documents plus the static AIBOM scorecard.
 */
function renderComplianceSection() {
    const dynamicEl = document.getElementById('compliance-dynamic');
    const scorecardEl = document.getElementById('compliance-scorecard');
    if (!dynamicEl || !scorecardEl) return;

    try {
        const reports = buildComplianceReports(generatedBOMs);
        dynamicEl.innerHTML = `
            <h4 class="compliance-heading">Generated documents</h4>
            ${reports.map((report, index) => complianceReportHtml(report, index)).join('')}
        `;
        scorecardEl.innerHTML = complianceScorecardHtml();
    } catch (error) {
        console.error('[Compliance] Failed to render compliance section:', error);
        dynamicEl.innerHTML = `<p class="compliance-error">Compliance check failed: ${escapeHtml(error.message)}</p>`;
        scorecardEl.innerHTML = '';
    }
}

function updateThemeToggle(theme) {
    const toggle = document.getElementById('theme-toggle');
    if (theme === 'dark') {
        toggle.textContent = '☀️ Light Mode';
    } else {
        toggle.textContent = '🌙 Dark Mode';
    }
}

