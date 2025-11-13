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
                    ${finding.evidence.slice(0, 5).map(ev => `
                        <div class="evidence-item">
                            <a class="evidence-file" href="${repoUrl}/blob/main/${ev.file}" target="_blank">${ev.file}</a>
                            ${ev.snippet ? `<pre class="evidence-snippet">${escapeHtml(ev.snippet)}</pre>` : ''}
                        </div>
                    `).join('')}
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
        const token = document.getElementById('token-input').value.trim() || null;
        
        if (!repoInput) {
            alert('Please enter a repository');
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
            console.log(`🎯 Score:          ${result.score} - ${result.confidence.label}`);
            console.log(`📝 Findings:       ${result.findings.length} total`);
            console.log(`🏷️  Categories:     ${new Set(result.findings.map(f => f.category)).size} unique`);
            console.log(`⏰ Completed:      ${scanEndTime.toLocaleTimeString()}`);
            console.log('✅'.repeat(40) + '\n');
            
            hide(document.getElementById('loading-state'));
            show(form);
            show(document.getElementById('findings-section'));
            show(document.getElementById('bom-section'));
            
            renderScoreBadge(result.score, result.confidence);
            renderFindings(result.findings, result.repository.htmlUrl);
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
                const ext = format.includes('xml') ? 'xml' : 'json';
                const name = format.includes('spdx') ? 'spdx' : 'cyclonedx';
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

