// Analysis & Scoring functions
function calculateScore(findings) {
    return findings.reduce((sum, finding) => sum + finding.weight, 0);
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
        { name: 'Prompts', fn: promptsDetector }
    ];
    
    console.log(`[Analyzer] Running ${detectors.length} detectors (Dependencies first for SBOM intelligence)...`);
    const allFindings = [];
    let codeResumeState = null;
    let codeDetectorPaused = false;
    let aiFilesFound = []; // Track files with AI usage
    let sbomAvailable = false; // Track if SBOM was successfully retrieved
    let detectedDependencies = []; // Track what dependencies were found
    
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
            
            const result = await detector.fn(input);
            const detectorTime = (performance.now() - detectorStart).toFixed(2);
            
            // Handle detectors that can pause
            if (result && typeof result === 'object' && 'findings' in result) {
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
    
    const score = calculateScore(allFindings);
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
    console.log(`[Analyzer]   Total Findings: ${allFindings.length}`);
    console.log(`[Analyzer]   Score:         ${score} (${confidence.label})`);
    console.log(`[Analyzer]   Confidence:    ${confidence.description}`);
    console.log('-'.repeat(80));
    console.log('[Analyzer] 📁 Findings by category:');
    
    const byCategory = {};
    allFindings.forEach(f => {
        byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    });
    
    const sortedCategories = Object.entries(byCategory).sort((a, b) => b[1] - a[1]);
    sortedCategories.forEach(([cat, count]) => {
        const percentage = ((count / allFindings.length) * 100).toFixed(1);
        console.log(`[Analyzer]   • ${cat.padEnd(15)} : ${count} findings (${percentage}%)`);
    });
    
    console.log('='.repeat(80));
    
    return {
        score,
        confidence,
        findings: allFindings,
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
