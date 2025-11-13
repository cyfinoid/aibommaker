// Analysis & Scoring functions
function calculateScore(findings) {
    return findings.reduce((sum, finding) => sum + finding.weight, 0);
}

/**
 * Merge dependency findings with code findings when they refer to the same package
 * Creates unified findings showing "Package X is used at location Y"
 */
function mergeDependencyAndCodeFindings(findings, repoMeta) {
    const merged = [];
    const dependencyMap = new Map(); // package name -> dependency finding
    const codeMap = new Map(); // package name -> code findings
    
    // First pass: collect all dependency findings
    findings.forEach(finding => {
        if (finding.category === 'dependencies' && finding.dependencyInfo) {
            const pkgName = finding.dependencyInfo.name.toLowerCase();
            dependencyMap.set(pkgName, finding);
        }
    });
    
    // Second pass: match code findings to dependencies
    findings.forEach(finding => {
        if (finding.category === 'code' && finding.title) {
            const title = finding.title.toLowerCase();
            
            // Skip "OpenAI-compatible" findings - these are API endpoints, not SDK usage
            // They might be used through litellm or other libraries, not the OpenAI SDK directly
            if (title.includes('openai-compatible') || title.includes('compatible')) {
                return; // Don't match compatible API endpoints to SDK dependencies
            }
            
            // Try to match against all dependency names
            dependencyMap.forEach((depFinding, depPkgName) => {
                const depNameLower = depPkgName.toLowerCase();
                
                // Match if code finding title mentions the package name
                // e.g., "LangChain SDK Usage" matches "langchain", "langchain-google-genai"
                // e.g., "Google SDK Usage" matches "langchain-google-genai", "google-generativeai"
                // IMPORTANT: Only match direct SDK usage, not compatible API endpoints
                const matches = 
                    (title.includes('langchain') && depNameLower.includes('langchain')) ||
                    // Only match "OpenAI SDK Usage", not "OpenAI-compatible" (which uses litellm)
                    (title.includes('openai') && !title.includes('compatible') && depNameLower.includes('openai')) ||
                    (title.includes('anthropic') && depNameLower.includes('anthropic')) ||
                    (title.includes('google') && depNameLower.includes('google')) ||
                    (title.includes('cohere') && depNameLower.includes('cohere')) ||
                    (title.includes('mistral') && depNameLower.includes('mistral')) ||
                    (title.includes('huggingface') && (depNameLower.includes('transformers') || depNameLower.includes('huggingface'))) ||
                    // Match litellm code findings to litellm dependency (not openai)
                    (title.includes('litellm') && depNameLower.includes('litellm'));
                
                if (matches) {
                    if (!codeMap.has(depPkgName)) {
                        codeMap.set(depPkgName, []);
                    }
                    codeMap.get(depPkgName).push(finding);
                }
            });
        }
    });
    
    // Merge: if we have both dependency and code findings for same package
    const processedDeps = new Set();
    const processedCode = new Set();
    
    dependencyMap.forEach((depFinding, pkgName) => {
        const codeFindings = codeMap.get(pkgName) || [];
        
        if (codeFindings.length > 0) {
            // Merge: Create unified finding
            const mergedFinding = {
                id: depFinding.id,
                title: `${depFinding.dependencyInfo.name} - Usage Detected`,
                category: 'dependencies',
                severity: 'high',
                weight: depFinding.weight,
                description: `${depFinding.dependencyInfo.name}${depFinding.dependencyInfo.version ? ` (${depFinding.dependencyInfo.version})` : ''} is installed and used in code`,
                evidence: [
                    // Keep dependency evidence
                    ...depFinding.evidence,
                    // Add code usage evidence with line numbers
                    ...codeFindings.flatMap(cf => cf.evidence || [])
                ],
                dependencyInfo: depFinding.dependencyInfo,
                codeUsage: {
                    files: codeFindings.flatMap(cf => cf.evidence?.map(e => e.file) || []),
                    locations: codeFindings.flatMap(cf => cf.evidence || [])
                }
            };
            
            merged.push(mergedFinding);
            processedDeps.add(pkgName);
            codeFindings.forEach(cf => processedCode.add(cf.id));
        } else {
            // No code usage found, keep dependency finding as-is
            merged.push(depFinding);
            processedDeps.add(pkgName);
        }
    });
    
    // Add code findings that don't match any dependency
    findings.forEach(finding => {
        if (finding.category === 'code' && !processedCode.has(finding.id)) {
            merged.push(finding);
        } else if (finding.category !== 'dependencies' && finding.category !== 'code') {
            // Keep all non-dependency/non-code findings
            merged.push(finding);
        }
    });
    
    return merged;
}

function getConfidenceLevel(score) {
    if (score >= 10) {
        return { level: 'very-high', label: 'Very High Confidence', description: 'Strong evidence detected' };
    } else if (score >= 5) {
        return { level: 'high', label: 'High Confidence', description: 'Likely LLM usage' };
    } else if (score >= 1) {
        return { level: 'low', label: 'Low Confidence', description: 'Weak signals detected' };
    } else {
        return { level: 'none', label: 'No Detection', description: 'No LLM usage detected' };
    }
}

// ============================================================================
// ANALYZER
// ============================================================================
async function analyzeRepository(input, onProgress = null) {
    const startTimestamp = new Date();
    const startTime = performance.now();
    
    console.log('='.repeat(80));
    console.log('[Analyzer] Starting repository analysis');
    console.log('[Analyzer] Repository:', input.repoMeta.fullName);
    console.log('[Analyzer] Start Time:', startTimestamp.toISOString());
    console.log('[Analyzer] Local Time:', startTimestamp.toLocaleString());
    console.log('='.repeat(80));
    
    const { repoMeta, tree, getFileContent, owner, repo, token } = input;
    const detectorInput = { repoMeta, tree, getFileContent, owner, repo, token };
    
    const detectors = [
        { name: 'Dependencies', fn: dependenciesDetector }, // Run SBOM first to know what's installed
        { name: 'Code', fn: codeDetector, canResume: true, needsDependencies: true }, // Use SBOM info for targeted search
        { name: 'Metadata', fn: metadataDetector },
        { name: 'AI Models', fn: modelsIdentifierDetector, needsAIFiles: true },
        { name: 'Configuration', fn: configDetector },
        { name: 'CI/CD', fn: ciDetector },
        { name: 'Model Files', fn: modelsDetector },
        { name: 'Prompts', fn: promptsDetector },
        { name: 'Hardware', fn: hardwareDetector, needsAllFindings: true },
        { name: 'Infrastructure', fn: infrastructureDetector, needsAllFindings: true },
        { name: 'Documentation', fn: documentationParser, isParser: true }, // Parser, not detector
        { name: 'Risk Assessment', fn: riskDetector, needsAllFindings: true, needsParsedDocs: true }
    ];
    
    console.log(`[Analyzer] Running ${detectors.length} detectors (Dependencies first for SBOM intelligence)...`);
    const allFindings = [];
    let codeResumeState = null;
    let codeDetectorPaused = false;
    let aiFilesFound = []; // Track files with AI usage
    let sbomAvailable = false; // Track if SBOM was successfully retrieved
    let detectedDependencies = []; // Track what dependencies were found
    let parsedDocs = null; // Track parsed documentation for risk detector
    
    for (let i = 0; i < detectors.length; i++) {
        const detector = detectors[i];
        const detectorStart = performance.now();
        
        console.log(`\n[Analyzer] [${i+1}/${detectors.length}] Running ${detector.name} detector...`);
        
        if (onProgress) {
            onProgress({
                step: i + 1,
                total: detectors.length,
                detector: detector.name,
                message: `Running ${detector.name} detector...`
            });
        }
        
        try {
            // Build detector input with context from previous detectors
            let input = { ...detectorInput };
            
            // Pass aiFilesFound and allFindings to detectors that need it
            if (detector.needsAIFiles) {
                input = { ...input, aiFilesFound, allFindings };
            }
            
            // Pass SBOM info and dependencies to Code detector for targeted search
            if (detector.needsDependencies) {
                input = { ...input, sbomAvailable, detectedDependencies };
            }
            
            // Pass allFindings to detectors that need access to all previous findings
            if (detector.needsAllFindings) {
                input = { ...input, allFindings };
            }
            
            // Pass parsedDocs to detectors that need documentation data
            if (detector.needsParsedDocs) {
                input = { ...input, parsedDocs };
            }
            
            const result = await detector.fn(input);
            const detectorTime = (performance.now() - detectorStart).toFixed(2);
            
            // Handle parsers (documentation parser returns parsed data, not findings)
            if (detector.isParser) {
                parsedDocs = result;
                console.log(`[Analyzer] ${detector.name} completed in ${detectorTime}ms`);
            }
            // Handle detectors that can pause or return object with findings
            else if (result && typeof result === 'object' && 'findings' in result) {
                allFindings.push(...result.findings);
                console.log(`[Analyzer] ${detector.name} detector completed in ${detectorTime}ms - ${result.findings.length} findings`);
                
                // Capture AI files found
                if (result.aiFilesFound) {
                    aiFilesFound = result.aiFilesFound;
                    console.log(`[Analyzer] 📁 Captured ${aiFilesFound.length} files with AI usage for later analysis`);
                }
                
                // Capture SBOM availability from Dependencies detector
                if (detector.name === 'Dependencies' && result.sbomAvailable !== undefined) {
                    sbomAvailable = result.sbomAvailable;
                    detectedDependencies = result.dependencies || [];
                    if (sbomAvailable) {
                        console.log(`[Analyzer] ✅ SBOM available with ${detectedDependencies.length} dependencies - Code search will be optimized`);
                    } else {
                        console.log(`[Analyzer] ⚠️  SBOM not available - Code search will use broad pattern matching`);
                    }
                }
                
                // Capture parsed documentation from risk detector
                if (detector.name === 'Risk Assessment' && result.parsedDocs) {
                    parsedDocs = result.parsedDocs;
                }
                
                // Check if paused
                if (result.paused && detector.canResume) {
                    console.log(`[Analyzer] 🔄 ${detector.name} detector paused, will resume after other detectors`);
                    codeResumeState = result.resumeState;
                    codeDetectorPaused = true;
                }
            } else {
                // Old-style detector returning array directly
                const findings = Array.isArray(result) ? result : [];
                allFindings.push(...findings);
                console.log(`[Analyzer] ${detector.name} detector completed in ${detectorTime}ms - ${findings.length} findings`);
            }
        } catch (error) {
            console.error(`[Analyzer] ❌ Error in ${detector.name} detector:`, error);
        }
    }
    
    // Resume code detector if it was paused
    if (codeDetectorPaused && codeResumeState) {
        console.log('\n[Analyzer] 🔄 Resuming Code detector...');
        
        // Wait for rate limit to reset if needed
        if (codeResumeState.lastRateLimit?.resetTime) {
            const waitMs = codeResumeState.lastRateLimit.resetTime - new Date();
            if (waitMs > 0 && waitMs < 120000) {
                const waitSec = Math.ceil(waitMs / 1000);
                console.log(`[Analyzer] ⏳ Waiting ${waitSec}s for rate limit reset before resuming...`);
                
                if (onProgress) {
                    onProgress({
                        step: detectors.length,
                        total: detectors.length + 1,
                        detector: 'Code (Resumed)',
                        message: `Waiting ${waitSec}s for rate limit...`
                    });
                }
                
                await new Promise(resolve => setTimeout(resolve, waitMs + 1000));
                console.log(`[Analyzer] ✓ Rate limit reset, resuming Code detector...`);
            }
        }
        
        if (onProgress) {
            onProgress({
                step: detectors.length + 1,
                total: detectors.length + 1,
                detector: 'Code (Resumed)',
                message: 'Resuming Code detector...'
            });
        }
        
        try {
            const resumedResult = await codeDetector({
                ...detectorInput,
                resumeState: codeResumeState
            });
            
            if (resumedResult?.findings) {
                // Merge resumed findings (avoid duplicates)
                const existingIds = new Set(allFindings.map(f => f.id));
                const newFindings = resumedResult.findings.filter(f => !existingIds.has(f.id));
                allFindings.push(...newFindings);
                console.log(`[Analyzer] Code detector resumed - added ${newFindings.length} new findings`);
            }
        } catch (error) {
            console.error(`[Analyzer] ❌ Error resuming Code detector:`, error);
        }
    }
    
    // Merge dependency findings with code findings (same package = single finding)
    console.log('\n[Analyzer] 🔗 Merging dependency and code findings...');
    const mergedFindings = mergeDependencyAndCodeFindings(allFindings, input.repoMeta);
    const mergeCount = allFindings.length - mergedFindings.length;
    if (mergeCount > 0) {
        console.log(`[Analyzer] ✓ Merged ${mergeCount} duplicate findings (dependency + code usage)`);
    }
    
    const score = calculateScore(mergedFindings);
    const confidence = getConfidenceLevel(score);
    
    const endTimestamp = new Date();
    const endTime = performance.now();
    const totalTimeMs = (endTime - startTime).toFixed(2);
    const totalTimeSec = (totalTimeMs / 1000).toFixed(2);
    const durationMs = endTimestamp - startTimestamp;
    
    console.log('\n' + '='.repeat(80));
    console.log('[Analyzer] 🎉 Analysis Complete!');
    console.log('='.repeat(80));
    console.log('[Analyzer] ⏱️  TIMING SUMMARY');
    console.log(`[Analyzer]   Start Time:    ${startTimestamp.toLocaleTimeString()}`);
    console.log(`[Analyzer]   End Time:      ${endTimestamp.toLocaleTimeString()}`);
    console.log(`[Analyzer]   Duration:      ${totalTimeMs}ms (${totalTimeSec}s)`);
    console.log(`[Analyzer]   Avg per detector: ${(totalTimeMs / detectors.length).toFixed(2)}ms`);
    console.log('-'.repeat(80));
    console.log('[Analyzer] 📊 RESULTS SUMMARY');
    console.log(`[Analyzer]   Repository:    ${input.repoMeta.fullName}`);
    console.log(`[Analyzer]   Total Files:   ${tree.length.toLocaleString()}`);
    console.log(`[Analyzer]   Total Findings: ${mergedFindings.length}${mergeCount > 0 ? ` (${mergeCount} merged)` : ''}`);
    console.log(`[Analyzer]   Score:         ${score} (${confidence.label})`);
    console.log(`[Analyzer]   Confidence:    ${confidence.description}`);
    console.log('-'.repeat(80));
    console.log('[Analyzer] 📁 Findings by category:');
    
    const byCategory = {};
    allFindings.forEach(f => {
        byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    });
    
    const byCategoryMerged = {};
    mergedFindings.forEach(f => {
        byCategoryMerged[f.category] = (byCategoryMerged[f.category] || 0) + 1;
    });
    
    const sortedCategories = Object.entries(byCategoryMerged).sort((a, b) => b[1] - a[1]);
    sortedCategories.forEach(([cat, count]) => {
        const percentage = ((count / mergedFindings.length) * 100).toFixed(1);
        console.log(`[Analyzer]   • ${cat.padEnd(15)} : ${count} findings (${percentage}%)`);
    });
    
    console.log('='.repeat(80));
    
    return {
        score,
        confidence,
        findings: mergedFindings,
        repository: {
            owner: input.owner,
            repo: input.repo,
            fullName: repoMeta.fullName,
            htmlUrl: repoMeta.htmlUrl,
            description: repoMeta.description,
            topics: repoMeta.topics,
            languages: repoMeta.languages
        },
        analyzedAt: new Date().toISOString()
    };
}

// ============================================================================
// BOM GENERATORS
// ============================================================================
