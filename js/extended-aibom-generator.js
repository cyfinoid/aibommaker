// Extended AI BOM Generator
// Generates comprehensive AI Bill of Materials with enhanced metadata

/**
 * Generate Extended AIBOM format
 * Includes standard CycloneDX BOM plus extended metadata sections
 */
function generateExtendedAIBOM(analysisResult, selectedFindings) {
    const { repository, analyzedAt } = analysisResult;
    
    console.log('[Extended AIBOM] Generating extended AI BOM...');
    
    // Generate standard CycloneDX BOM as base
    const standardBom = JSON.parse(generateCycloneDXJson(analysisResult, selectedFindings));
    
    // Extract extended metadata from findings
    const extendedMetadata = extractExtendedMetadata(selectedFindings, analysisResult);
    
    const extendedAIBOM = {
        format: 'extended-aibom',
        version: '1.0.0',
        generatedAt: analyzedAt,
        generator: {
            tool: 'AI BOM Generator',
            version: '1.0.0',
            vendor: 'Cyfinoid Research'
        },
        repository: {
            owner: repository.owner,
            name: repository.repo,
            fullName: repository.fullName,
            url: repository.htmlUrl,
            description: repository.description,
            topics: repository.topics,
            languages: repository.languages
        },
        standard_bom: standardBom,
        extended_metadata: extendedMetadata,
        summary: generateSummary(extendedMetadata, selectedFindings)
    };
    
    console.log('[Extended AIBOM] Extended AI BOM generated successfully');
    return JSON.stringify(extendedAIBOM, null, 2);
}

/**
 * Extract extended metadata from findings
 */
function extractExtendedMetadata(findings, analysisResult) {
    console.log('[Extended AIBOM] Extracting extended metadata...');
    
    return {
        hardware: extractHardwareMetadata(findings),
        infrastructure: extractInfrastructureMetadata(findings),
        model_governance: extractGovernanceMetadata(findings, analysisResult),
        risk_assessment: extractRiskAssessment(findings),
        data_pipeline: extractDataPipeline(findings),
        analysis_notes: extractAnalysisNotes(findings, analysisResult)
    };
}

/**
 * Extract hardware information
 */
function extractHardwareMetadata(findings) {
    const hardwareFindings = findings.filter(f => f.category === 'hardware');
    
    if (hardwareFindings.length === 0) {
        return {
            detected: false,
            note: 'No specialized hardware requirements detected'
        };
    }
    
    const hardware = {
        detected: true,
        compute_types: [],
        details: []
    };
    
    for (const finding of hardwareFindings) {
        if (finding.hardwareInfo) {
            hardware.compute_types.push(finding.hardwareInfo.type);
            hardware.details.push({
                type: finding.hardwareInfo.type,
                libraries: finding.hardwareInfo.libraries || [],
                description: finding.description,
                evidence: finding.evidence.map(e => ({
                    file: e.file,
                    snippet: e.snippet
                }))
            });
        }
    }
    
    return hardware;
}

/**
 * Extract infrastructure information
 */
function extractInfrastructureMetadata(findings) {
    const infraFindings = findings.filter(f => f.category === 'infrastructure');
    
    if (infraFindings.length === 0) {
        return {
            detected: false,
            note: 'No infrastructure or deployment configuration detected'
        };
    }
    
    const infrastructure = {
        detected: true,
        deployment: {
            containerization: [],
            orchestration: [],
            cloud_platforms: [],
            mlops_tools: []
        },
        details: []
    };
    
    for (const finding of infraFindings) {
        if (finding.infraInfo) {
            const type = finding.infraInfo.type;
            const platforms = finding.infraInfo.platforms || [];
            
            if (type === 'containerization') {
                infrastructure.deployment.containerization.push(...platforms);
            } else if (type === 'orchestration') {
                infrastructure.deployment.orchestration.push(...platforms);
            } else if (type === 'cloud') {
                infrastructure.deployment.cloud_platforms.push(...platforms);
            } else if (type === 'mlops') {
                infrastructure.deployment.mlops_tools.push(...platforms);
            }
            
            infrastructure.details.push({
                type: type,
                platforms: platforms,
                description: finding.description,
                evidence: finding.evidence.map(e => ({
                    file: e.file,
                    snippet: e.snippet
                }))
            });
        }
    }
    
    // Deduplicate arrays
    infrastructure.deployment.containerization = [...new Set(infrastructure.deployment.containerization)];
    infrastructure.deployment.orchestration = [...new Set(infrastructure.deployment.orchestration)];
    infrastructure.deployment.cloud_platforms = [...new Set(infrastructure.deployment.cloud_platforms)];
    infrastructure.deployment.mlops_tools = [...new Set(infrastructure.deployment.mlops_tools)];
    
    return infrastructure;
}

/**
 * Extract model governance information
 */
function extractGovernanceMetadata(findings, analysisResult) {
    const governanceFindings = findings.filter(f => f.category === 'governance');
    const modelFindings = findings.filter(f => f.modelInfo);
    
    const governance = {
        models: [],
        documentation_status: {
            intended_use_documented: false,
            limitations_documented: false,
            ethical_considerations_documented: false,
            bias_fairness_documented: false
        },
        transparency: {
            model_cards_present: false,
            security_documentation: false,
            readme_present: false
        },
        detected_considerations: []
    };
    
    // Extract model information
    for (const finding of modelFindings) {
        if (finding.modelInfo) {
            governance.models.push({
                provider: finding.modelInfo.provider,
                name: finding.modelInfo.modelName,
                type: finding.modelInfo.modelType,
                intended_use: finding.description,
                detection_source: finding.modelInfo.detectionSource || 'code-analysis',
                locations: finding.modelInfo.locations || []
            });
        }
    }
    
    // Check documentation status
    for (const finding of governanceFindings) {
        if (finding.riskInfo) {
            const type = finding.riskInfo.type;
            
            if (type === 'limitations') {
                governance.documentation_status.limitations_documented = true;
                governance.detected_considerations.push({
                    type: 'limitations',
                    count: finding.riskInfo.count,
                    description: finding.description
                });
            } else if (type === 'bias-fairness') {
                governance.documentation_status.bias_fairness_documented = true;
                governance.detected_considerations.push({
                    type: 'bias_fairness',
                    count: finding.riskInfo.count,
                    description: finding.description
                });
            } else if (type === 'ethical') {
                governance.documentation_status.ethical_considerations_documented = true;
                governance.detected_considerations.push({
                    type: 'ethical',
                    count: finding.riskInfo.count,
                    description: finding.description
                });
            }
        }
    }
    
    // Check for README and documentation files from all findings
    const allFiles = findings.flatMap(f => f.evidence?.map(e => e.file) || []);
    governance.transparency.readme_present = allFiles.some(f => f && f.toLowerCase().includes('readme'));
    governance.transparency.model_cards_present = allFiles.some(f => f && f.toLowerCase().includes('model'));
    governance.transparency.security_documentation = allFiles.some(f => f && f.toLowerCase().includes('security'));
    
    return governance;
}

/**
 * Extract risk assessment information
 */
function extractRiskAssessment(findings) {
    const riskFindings = findings.filter(f => f.category === 'risk');
    const governanceFindings = findings.filter(f => f.category === 'governance');
    
    const risks = {
        overall_risk_level: 'low',
        missing_documentation: [],
        identified_risks: [],
        positive_indicators: [],
        recommendations: []
    };
    
    let riskScore = 0;
    
    // Process risk findings (only actual risks, not missing documentation)
    for (const finding of riskFindings) {
        // Missing documentation findings are no longer created, but keeping this for backwards compatibility
        if (finding.riskInfo && finding.riskInfo.type === 'missing-documentation') {
            risks.missing_documentation.push(...finding.riskInfo.items);
            // Don't add to risk score - missing docs is an analysis note, not a risk
        } else {
            // Actual risk finding
            risks.identified_risks.push({
                title: finding.title,
                severity: finding.severity,
                description: finding.description,
                evidence_count: finding.evidence?.length || 0
            });
            // Only score actual identified risks
            riskScore += finding.weight || 2;
        }
    }
    
    // Process positive governance indicators
    for (const finding of governanceFindings) {
        risks.positive_indicators.push({
            title: finding.title,
            description: finding.description
        });
        riskScore -= 1; // Reduce risk score for positive indicators
    }
    
    // Determine overall risk level
    if (riskScore <= 0) {
        risks.overall_risk_level = 'low';
    } else if (riskScore <= 3) {
        risks.overall_risk_level = 'medium';
    } else {
        risks.overall_risk_level = 'high';
    }
    
    // Generate recommendations based on what was found (not what's missing)
    // Note: Missing documentation is tracked separately but doesn't generate recommendations in AIBOM
    
    if (risks.positive_indicators.length === 0) {
        // Only recommend if we found models but no governance docs
        const hasModels = findings.some(f => f.modelInfo);
        if (hasModels) {
            risks.recommendations.push({
                priority: 'medium',
                category: 'governance',
                recommendation: 'Consider documenting model limitations, intended use, and ethical considerations',
                details: 'Models detected but no governance documentation found'
            });
        }
    }
    
    if (risks.identified_risks.length > 0 && risks.positive_indicators.length === 0) {
        risks.recommendations.push({
            priority: 'high',
            category: 'risk-management',
            recommendation: 'Address identified risks and improve documentation',
            details: `${risks.identified_risks.length} risks identified without corresponding governance documentation`
        });
    }
    
    return risks;
}

/**
 * Extract data pipeline information
 */
function extractDataPipeline(findings) {
    const depFindings = findings.filter(f => f.category === 'dependencies');
    
    const dataPipeline = {
        detected: false,
        data_loading: [],
        preprocessing: [],
        feature_engineering: [],
        frameworks: []
    };
    
    // Check dependencies for data pipeline libraries
    for (const finding of depFindings) {
        const depName = finding.dependencyInfo?.name?.toLowerCase() || finding.title.toLowerCase();
        
        // Data loading libraries
        if (depName.includes('datasets') || depName.includes('pandas') || depName.includes('numpy')) {
            dataPipeline.detected = true;
            dataPipeline.data_loading.push({
                library: finding.dependencyInfo?.name || finding.title,
                version: finding.dependencyInfo?.version
            });
        }
        
        // Preprocessing libraries
        if (depName.includes('sklearn') || depName.includes('scikit-learn') || 
            depName.includes('nltk') || depName.includes('spacy') ||
            depName.includes('torchvision') || depName.includes('albumentations')) {
            dataPipeline.detected = true;
            dataPipeline.preprocessing.push({
                library: finding.dependencyInfo?.name || finding.title,
                version: finding.dependencyInfo?.version
            });
        }
        
        // ML frameworks
        if (depName.includes('torch') || depName.includes('tensorflow') || 
            depName.includes('jax') || depName.includes('keras')) {
            dataPipeline.detected = true;
            dataPipeline.frameworks.push({
                library: finding.dependencyInfo?.name || finding.title,
                version: finding.dependencyInfo?.version
            });
        }
    }
    
    // Deduplicate
    dataPipeline.data_loading = deduplicateByLibrary(dataPipeline.data_loading);
    dataPipeline.preprocessing = deduplicateByLibrary(dataPipeline.preprocessing);
    dataPipeline.frameworks = deduplicateByLibrary(dataPipeline.frameworks);
    
    if (!dataPipeline.detected) {
        return {
            detected: false,
            note: 'No data pipeline components detected'
        };
    }
    
    return dataPipeline;
}

/**
 * Helper function to deduplicate by library name
 */
function deduplicateByLibrary(items) {
    const seen = new Set();
    return items.filter(item => {
        const key = item.library.toLowerCase();
        if (seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}

/**
 * Generate summary statistics
 */
function generateSummary(metadata, findings) {
    return {
        total_findings: findings.length,
        categories: {
            dependencies: findings.filter(f => f.category === 'dependencies').length,
            models: findings.filter(f => f.modelInfo).length,
            hardware: findings.filter(f => f.category === 'hardware').length,
            infrastructure: findings.filter(f => f.category === 'infrastructure').length,
            governance: findings.filter(f => f.category === 'governance').length,
            risks: findings.filter(f => f.category === 'risk').length
        },
        hardware_detected: metadata.hardware.detected,
        infrastructure_detected: metadata.infrastructure.detected,
        data_pipeline_detected: metadata.data_pipeline.detected,
        risk_level: metadata.risk_assessment.overall_risk_level,
        documentation_completeness: calculateDocumentationCompleteness(metadata.model_governance)
    };
}

/**
 * Extract analysis notes about missing or undetectable components
 */
function extractAnalysisNotes(findings, analysisResult) {
    const notes = {
        missing_documentation: [],
        undetectable_components: [],
        detection_limitations: [],
        suggested_improvements: []
    };
    
    // Check for missing documentation files from risk detector logs
    const allFiles = findings.flatMap(f => f.evidence?.map(e => e.file) || []);
    
    if (!allFiles.some(f => f && f.toLowerCase().includes('readme'))) {
        notes.missing_documentation.push({
            file: 'README.md',
            purpose: 'Project overview and usage instructions',
            impact: 'Difficult to understand project purpose and usage'
        });
    }
    
    if (!allFiles.some(f => f && f.toLowerCase().includes('model'))) {
        notes.missing_documentation.push({
            file: 'MODEL_CARD.md',
            purpose: 'Model documentation including intended use, limitations, and performance',
            impact: 'Incomplete model governance and transparency'
        });
    }
    
    if (!allFiles.some(f => f && f.toLowerCase().includes('security'))) {
        notes.missing_documentation.push({
            file: 'SECURITY.md',
            purpose: 'Security policy and vulnerability reporting procedures',
            impact: 'No clear security disclosure process'
        });
    }
    
    // Undetectable components (always true for code-based analysis)
    notes.undetectable_components = [
        {
            component: 'Training Data',
            reason: 'Training datasets are typically not stored in code repositories',
            alternative: 'May be referenced in documentation or configuration files'
        },
        {
            component: 'Model Weights',
            reason: 'Model weights are usually too large for git repositories',
            alternative: 'Check for model file references or download scripts'
        },
        {
            component: 'Runtime Performance',
            reason: 'Performance metrics require running the model',
            alternative: 'Look for performance benchmarks in documentation'
        },
        {
            component: 'Actual Training Infrastructure',
            reason: 'Training may happen on different infrastructure than deployment',
            alternative: 'Deployment infrastructure detected from configs'
        },
        {
            component: 'Model Bias/Fairness Metrics',
            reason: 'Bias metrics require evaluation on representative data',
            alternative: 'Documented bias considerations may be found in model cards'
        }
    ];
    
    // Detection limitations based on what we found
    const hasModels = findings.some(f => f.modelInfo);
    const hasHardware = findings.some(f => f.category === 'hardware');
    const hasInfra = findings.some(f => f.category === 'infrastructure');
    const hasGovernance = findings.some(f => f.category === 'governance');
    
    if (hasModels && !hasGovernance) {
        notes.detection_limitations.push({
            area: 'Model Governance',
            limitation: 'Models detected but no governance documentation found',
            note: 'Governance documentation may exist but not in standard file names'
        });
    }
    
    if (hasModels && !hasHardware) {
        notes.detection_limitations.push({
            area: 'Hardware Requirements',
            limitation: 'Models detected but no specific hardware requirements found',
            note: 'May use CPU-only inference or hardware not explicitly declared in dependencies'
        });
    }
    
    // Generate suggested improvements
    if (notes.missing_documentation.length > 0) {
        notes.suggested_improvements.push({
            priority: 'high',
            action: 'Add missing documentation files',
            files: notes.missing_documentation.map(d => d.file),
            benefit: 'Improves transparency and enables more complete AIBOM generation'
        });
    }
    
    if (hasModels && !hasGovernance) {
        notes.suggested_improvements.push({
            priority: 'high',
            action: 'Create model documentation',
            files: ['MODEL_CARD.md'],
            benefit: 'Documents intended use, limitations, ethical considerations, and bias mitigation'
        });
    }
    
    if (hasModels && notes.missing_documentation.some(d => d.file === 'SECURITY.md')) {
        notes.suggested_improvements.push({
            priority: 'medium',
            action: 'Establish security policy',
            files: ['SECURITY.md'],
            benefit: 'Provides clear process for reporting AI-related security issues'
        });
    }
    
    return notes;
}

/**
 * Calculate documentation completeness score
 */
function calculateDocumentationCompleteness(governance) {
    const checks = [
        governance.transparency.readme_present,
        governance.transparency.model_cards_present,
        governance.transparency.security_documentation,
        governance.documentation_status.limitations_documented,
        governance.documentation_status.ethical_considerations_documented
    ];
    
    const passed = checks.filter(c => c).length;
    const percentage = Math.round((passed / checks.length) * 100);
    
    return {
        score: percentage,
        level: percentage >= 80 ? 'excellent' : percentage >= 60 ? 'good' : percentage >= 40 ? 'fair' : 'poor',
        checks_passed: passed,
        total_checks: checks.length
    };
}

