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
    
    // If everything was found, show a positive message
    if (notFound.length === 0) {
        container.innerHTML = `
            <div class="info-message" style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">✅ Comprehensive detection achieved</p>
                <p style="font-size: 0.9rem;">All detectable components were found in this repository.</p>
            </div>
        `;
        return;
    }
    
    // Render what we looked for but didn't find in THIS scan
    const notFoundSection = document.createElement('div');
    notFoundSection.className = 'analysis-note-section';
    notFoundSection.innerHTML = `
        <h3 class="subheading" style="margin-bottom: 1rem;">🔍 Components Not Found in This Scan</h3>
        <p class="caption" style="margin-bottom: 1rem;">We scanned for these components but did not find them in this repository. If present, they would enhance the AIBOM:</p>
        <div class="analysis-notes-grid">
            ${notFound.map(item => `
                <div class="analysis-note-card">
                    <div class="analysis-note-header">
                        <strong>${item.category}: ${item.item}</strong>
                    </div>
                    <div class="analysis-note-body">
                        <p><strong>What We Scanned:</strong> ${item.searched}</p>
                        <p><strong>AIBOM Benefit:</strong> ${item.benefit}</p>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
    container.appendChild(notFoundSection);
}

function renderFindings(findings, repoUrl) {
    const container = document.getElementById('findings-list');
    container.innerHTML = '';
    
    if (findings.length === 0) {
        container.innerHTML = '<p class="body" style="text-align: center; color: var(--text-secondary);">No findings</p>';
        return;
    }
    
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
                { owner, repo, repoMeta, tree, getFileContent, token },
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
            
            // Score badge removed - AIBOM focuses on what's found, not scoring
            // renderScoreBadge(result.score, result.confidence);
            renderFindings(result.findings, result.repository.htmlUrl);
            // Pass file tree to check for documentation files that may not be in findings evidence
            renderAnalysisNotes(result.findings, result, tree);
            regenerateBOMs();
            
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
    
    document.getElementById('select-all-btn').addEventListener('click', () => {
        selectAllFindings(true);
        regenerateBOMs();
    });
    
    document.getElementById('deselect-all-btn').addEventListener('click', () => {
        selectAllFindings(false);
        regenerateBOMs();
    });
    
    document.getElementById('category-filter').addEventListener('change', (e) => {
        filterFindings(e.target.value);
    });
    
    document.addEventListener('change', (e) => {
        if (e.target.classList.contains('finding-checkbox')) {
            regenerateBOMs();
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
            const format = e.target.dataset.format;
            const content = generatedBOMs[format];
            if (content) {
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
        }
    });
    
    // Collapse/Expand all findings
    document.getElementById('collapse-all-findings').addEventListener('click', function() {
        const items = document.querySelectorAll('.finding-item');
        const allCollapsed = Array.from(items).every(item => item.classList.contains('collapsed'));
        
        items.forEach(item => {
            if (allCollapsed) {
                item.classList.remove('collapsed');
            } else {
                item.classList.add('collapsed');
            }
        });
        
        this.textContent = allCollapsed ? 'Collapse All' : 'Expand All';
    });
    
    // Collapse/Expand findings section
    document.getElementById('collapse-all-findings').addEventListener('dblclick', function(e) {
        e.preventDefault();
        const content = document.getElementById('findings-content');
        content.classList.toggle('collapsed');
        this.textContent = content.classList.contains('collapsed') ? 'Expand Section' : 'Collapse All';
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
});

function regenerateBOMs() {
    if (!currentAnalysis) return;
    
    const selected = getSelectedFindings(currentFindings);
    
    console.log('\n' + '📄'.repeat(40));
    console.log('📄 BOM Generation Started');
    console.log(`📊 Selected Findings: ${selected.length}`);
    
    if (selected.length === 0) {
        renderBOMPreview('cyclonedx-json', '// No findings selected');
        renderBOMPreview('cyclonedx-xml', '<!-- No findings selected -->');
        renderBOMPreview('spdx', '// No findings selected');
        console.log('[BOM] ⚠️  No findings selected, showing placeholder');
        console.log('📄'.repeat(40) + '\n');
        return;
    }
    
    try {
        const startTime = performance.now();
        
        console.log('[BOM] Generating CycloneDX JSON...');
        generatedBOMs['cyclonedx-json'] = generateCycloneDXJson(currentAnalysis, selected);
        renderBOMPreview('cyclonedx-json', generatedBOMs['cyclonedx-json']);
        const jsonSize = (generatedBOMs['cyclonedx-json'].length / 1024).toFixed(2);
        console.log(`[BOM] ✓ CycloneDX JSON generated (${jsonSize} KB)`);
        
        console.log('[BOM] Generating CycloneDX XML...');
        generatedBOMs['cyclonedx-xml'] = generateCycloneDXXml(currentAnalysis, selected);
        renderBOMPreview('cyclonedx-xml', generatedBOMs['cyclonedx-xml']);
        const xmlSize = (generatedBOMs['cyclonedx-xml'].length / 1024).toFixed(2);
        console.log(`[BOM] ✓ CycloneDX XML generated (${xmlSize} KB)`);
        
        console.log('[BOM] Generating SPDX...');
        generatedBOMs['spdx'] = generateSPDX(currentAnalysis, selected);
        renderBOMPreview('spdx', generatedBOMs['spdx']);
        const spdxSize = (generatedBOMs['spdx'].length / 1024).toFixed(2);
        console.log(`[BOM] ✓ SPDX generated (${spdxSize} KB)`);
        
        console.log('[BOM] Generating Extended AIBOM...');
        generatedBOMs['extended-aibom'] = generateExtendedAIBOM(currentAnalysis, selected);
        renderBOMPreview('extended-aibom', generatedBOMs['extended-aibom']);
        const extendedSize = (generatedBOMs['extended-aibom'].length / 1024).toFixed(2);
        console.log(`[BOM] ✓ Extended AIBOM generated (${extendedSize} KB)`);
        
        const elapsed = (performance.now() - startTime).toFixed(2);
        console.log(`\n[BOM] ⏱️  Generation time: ${elapsed}ms`);
        console.log(`[BOM] 📊 Total size: ${(parseFloat(jsonSize) + parseFloat(xmlSize) + parseFloat(spdxSize)).toFixed(2)} KB`);
        console.log('📄'.repeat(40) + '\n');
    } catch (error) {
        console.error('[BOM] ❌ Error generating BOMs:', error);
        console.log('📄'.repeat(40) + '\n');
        showToast('Error generating BOM: ' + error.message, 'error');
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

