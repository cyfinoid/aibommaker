// Extended AI BOM Generator
// Generates comprehensive AI Bill of Materials with enhanced metadata

/**
 * Calculate detailed compliance scores for EU AI Act and NIST AI RMF
 * @param {Array} findings - All findings from analysis
 * @param {string} riskLevel - EU AI Act risk level
 * @returns {Object} Detailed compliance scores
 */
function calculateComplianceScores(findings, riskLevel) {
    const scores = {
        euAIAct: { score: 0, maxScore: 10, breakdown: {} },
        nistAIRMF: { score: 0, maxScore: 16, breakdown: {} }
    };

    // EU AI Act scoring (simplified)
    scores.euAIAct.breakdown = {
        riskAssessment: riskLevel === 'high' ? 3 : riskLevel === 'limited' ? 2 : 1,
        documentation: findings.filter(f => f.category === 'governance').length > 0 ? 3 : 1,
        transparency: findings.some(f => f.category === 'governance') ? 2 : 0,
        accountability: findings.some(f => f.category === 'governance') ? 2 : 0
    };
    scores.euAIAct.score = Object.values(scores.euAIAct.breakdown).reduce((a, b) => a + b, 0);

    // NIST AI RMF scoring
    const nistBreakdown = { govern: 0, map: 0, measure: 0, manage: 0 };

    findings.forEach(finding => {
        const text = `${finding.title} ${finding.description}`.toLowerCase();

        // GOVERN function
        NIST_AI_RMF_COMPLIANCE.govern.indicators.forEach(indicator => {
            if (indicator.pattern.test(text)) {
                nistBreakdown.govern = Math.min(nistBreakdown.govern + indicator.weight, 4);
            }
        });

        // MAP function
        NIST_AI_RMF_COMPLIANCE.map.indicators.forEach(indicator => {
            if (indicator.pattern.test(text)) {
                nistBreakdown.map = Math.min(nistBreakdown.map + indicator.weight, 4);
            }
        });

        // MEASURE function
        NIST_AI_RMF_COMPLIANCE.measure.indicators.forEach(indicator => {
            if (indicator.pattern.test(text)) {
                nistBreakdown.measure = Math.min(nistBreakdown.measure + indicator.weight, 4);
            }
        });

        // MANAGE function
        NIST_AI_RMF_COMPLIANCE.manage.indicators.forEach(indicator => {
            if (indicator.pattern.test(text)) {
                nistBreakdown.manage = Math.min(nistBreakdown.manage + indicator.weight, 4);
            }
        });
    });

    scores.nistAIRMF.breakdown = nistBreakdown;
    scores.nistAIRMF.score = Object.values(nistBreakdown).reduce((a, b) => a + b, 0);

    return scores;
}

/**
 * Assess EU AI Act compliance and risk classification
 * @param {Array} findings - All findings from analysis
 * @param {Array} models - Model information from governance
 * @returns {Object} EU AI Act compliance assessment
 */
function assessEUAIActCompliance(findings, models) {
    let riskLevel = 'minimal';
    let riskReasons = [];
    let complianceScore = 0;

    // Check for high-risk indicators in findings
    for (const finding of findings) {
        const text = `${finding.title} ${finding.description}`.toLowerCase();

        for (const pattern of EU_AI_ACT_RISK_INDICATORS.highRisk.patterns) {
            if (pattern.pattern.test(text)) {
                if (riskLevel !== 'high') {
                    riskLevel = 'high';
                    riskReasons.push(pattern.reason);
                }
                break;
            }
        }

        if (riskLevel === 'high') break;
    }

    // Check for limited-risk indicators if not high-risk
    if (riskLevel === 'minimal') {
        for (const finding of findings) {
            const text = `${finding.title} ${finding.description}`.toLowerCase();

            for (const pattern of EU_AI_ACT_RISK_INDICATORS.limitedRisk.patterns) {
                if (pattern.pattern.test(text)) {
                    riskLevel = 'limited';
                    riskReasons.push(pattern.reason);
                    break;
                }
            }

            if (riskLevel === 'limited') break;
        }
    }

    // Check model types for additional risk assessment
    for (const model of models || []) {
        const modelText = `${model.name} ${model.type} ${model.intended_use || ''}`.toLowerCase();

        // Biometric models are high-risk
        if (modelText.includes('facial') || modelText.includes('biometric') || modelText.includes('recognition')) {
            riskLevel = 'high';
            riskReasons.push('Biometric identification system');
        }

        // Large language models used for critical decisions
        if (model.type === 'text-generation' && (modelText.includes('decision') || modelText.includes('assessment'))) {
            if (riskLevel !== 'high') {
                riskLevel = 'limited';
                riskReasons.push('Generative AI for decision-making');
            }
        }
    }

    // Calculate comprehensive compliance scores
    const complianceScores = calculateComplianceScores(findings, riskLevel);

    const docFindings = findings.filter(f => f.category === 'governance');
    const hasDocumentation = docFindings.length > 0;

    // EU AI Act compliance score (basic)
    if (riskLevel === 'high') {
        complianceScore = hasDocumentation ? 0.7 : 0.3;
    } else if (riskLevel === 'limited') {
        complianceScore = hasDocumentation ? 0.8 : 0.5;
    } else {
        complianceScore = hasDocumentation ? 0.9 : 0.6;
    }

    return {
        riskCategory: riskLevel,
        riskReasons: [...new Set(riskReasons)], // Remove duplicates
        complianceScore: complianceScore,
        detailedCompliance: complianceScores,
        requiresTransparency: riskLevel === 'high' || riskLevel === 'limited',
        requiresConformity: riskLevel === 'high',
        assessmentBasis: 'EU AI Act Annex III risk classification based on detected components and intended use'
    };
}

/**
 * Calculate carbon footprint estimate for a model
 * Based on model parameters and conservative estimates
 * @param {Object} modelParameters - Model parameters from config.json
 * @returns {Object} Carbon footprint estimate
 */
function calculateCarbonFootprint(modelParameters) {
    if (!modelParameters || !modelParameters.num_parameters) {
        return null;
    }

    const numParams = modelParameters.num_parameters;
    const paramsInBillions = numParams / 1e9;

    // Conservative estimate: ~0.5 kg CO2 per billion parameters for training
    // This is a rough estimate based on industry reports
    // Actual carbon footprint depends on many factors including hardware, location, etc.
    const co2PerBillionParams = 0.5; // kg CO2
    const estimatedCO2 = paramsInBillions * co2PerBillionParams;

    return {
        estimatedCO2: estimatedCO2,
        unit: 'kg',
        methodology: 'conservative-estimate',
        parametersUsed: numParams,
        note: 'Estimate based on model parameters. Actual carbon footprint depends on training hardware, location, and optimization techniques.',
        sources: [
            'Based on industry estimates of ~0.5 kg CO2 per billion parameters',
            'Does not account for inference emissions or data center efficiency variations'
        ]
    };
}

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
        protocols: extractProtocolMetadata(findings),
        ai_development_tools: extractAiDevToolsMetadata(findings),
        model_governance: extractGovernanceMetadata(findings, analysisResult),
        risk_assessment: extractRiskAssessment(findings, analysisResult),
        data_pipeline: extractDataPipelineMetadata(findings),
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
        details: [],
        distributed_training: []
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

        // Extract distributed training information
        if (finding.hardwareInfo?.type === 'distributed_training') {
            hardware.distributed_training.push({
                frameworks: finding.hardwareInfo.frameworks || [],
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
 * Extract protocol information (MCP, A2A, function calling)
 */
function extractProtocolMetadata(findings) {
    const protocolFindings = findings.filter(f => f.category === 'protocol');
    
    if (protocolFindings.length === 0) {
        return {
            detected: false,
            note: 'No AI protocol implementations detected (MCP, A2A, function calling)'
        };
    }
    
    const protocols = {
        detected: true,
        mcp: {
            detected: false,
            servers: [],
            server_details: [],
            capabilities: [],
            ai_providers: [],
            implementations: []
        },
        a2a: {
            detected: false,
            implementations: []
        },
        function_calling: {
            detected: false,
            implementations: []
        },
        details: []
    };
    
    for (const finding of protocolFindings) {
        if (finding.protocolInfo) {
            const type = finding.protocolInfo.type;
            
            if (type === 'mcp') {
                protocols.mcp.detected = true;
                if (finding.protocolInfo.servers) {
                    protocols.mcp.servers.push(...finding.protocolInfo.servers);
                }
                if (finding.protocolInfo.capabilities) {
                    protocols.mcp.capabilities.push(...finding.protocolInfo.capabilities);
                }
                if (finding.protocolInfo.aiProviders) {
                    protocols.mcp.ai_providers.push(...finding.protocolInfo.aiProviders);
                }
                if (finding.protocolInfo.parsedServers) {
                    protocols.mcp.server_details.push(...finding.protocolInfo.parsedServers.map(s => ({
                        name: s.name,
                        category: s.category,
                        provider: s.provider,
                        description: s.description,
                        capabilities: s.capabilities
                    })));
                }
                protocols.mcp.implementations.push({
                    subType: finding.protocolInfo.subType || 'config',
                    file: finding.evidence?.[0]?.file,
                    description: finding.description
                });
            } else if (type === 'mcp-server') {
                // Individual MCP server finding
                protocols.mcp.detected = true;
                protocols.mcp.server_details.push({
                    name: finding.protocolInfo.serverName,
                    category: finding.protocolInfo.serverCategory,
                    provider: finding.protocolInfo.provider,
                    capabilities: finding.protocolInfo.capabilities,
                    has_env_vars: finding.protocolInfo.hasEnvVars
                });
            } else if (type === 'a2a') {
                protocols.a2a.detected = true;
                protocols.a2a.implementations.push({
                    subType: finding.protocolInfo.subType || 'general',
                    file: finding.evidence?.[0]?.file,
                    description: finding.description
                });
            } else if (type === 'function-calling') {
                protocols.function_calling.detected = true;
                protocols.function_calling.implementations.push({
                    subType: finding.protocolInfo.subType || 'general',
                    file: finding.evidence?.[0]?.file,
                    description: finding.description
                });
            }
            
            protocols.details.push({
                type: type,
                title: finding.title,
                description: finding.description,
                evidence: finding.evidence?.map(e => ({
                    file: e.file,
                    snippet: e.snippet
                })) || []
            });
        }
    }
    
    // Deduplicate
    protocols.mcp.servers = [...new Set(protocols.mcp.servers)];
    protocols.mcp.capabilities = [...new Set(protocols.mcp.capabilities)];
    protocols.mcp.ai_providers = [...new Set(protocols.mcp.ai_providers)];
    
    // Deduplicate server_details by name
    const seenServers = new Set();
    protocols.mcp.server_details = protocols.mcp.server_details.filter(s => {
        if (seenServers.has(s.name)) return false;
        seenServers.add(s.name);
        return true;
    });
    
    return protocols;
}

/**
 * Extract AI development tools metadata (Cursor, Copilot, Aider, etc.)
 */
function extractAiDevToolsMetadata(findings) {
    const devToolFindings = findings.filter(f => f.category === 'ai-dev-tools');
    
    if (devToolFindings.length === 0) {
        return {
            detected: false,
            note: 'No AI development tool configurations detected'
        };
    }
    
    const devTools = {
        detected: true,
        confidence: 'low', // These are low confidence findings by design
        note: 'AI development tools indicate AI-assisted development, not AI functionality in the project',
        tools: [],
        details: []
    };
    
    for (const finding of devToolFindings) {
        if (finding.devToolInfo) {
            devTools.tools.push(finding.devToolInfo.tool);
            devTools.details.push({
                tool: finding.devToolInfo.tool,
                configFile: finding.devToolInfo.configFile,
                description: finding.description,
                dependencies: finding.devToolInfo.dependencies || [],
                extensions: finding.devToolInfo.extensions || []
            });
        }
    }
    
    // Deduplicate tools
    devTools.tools = [...new Set(devTools.tools)];
    
    return devTools;
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
    
    // Get parsed documentation from README.md if available
    const parsedDocs = analysisResult.parsedDocs || null;
    
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
        detected_considerations: [],
        quantitative_analysis: {
            performance_metrics: [],
            carbon_footprints: []
        },
        // Include extracted documentation text from README.md
        extracted_documentation: parsedDocs ? {
            intended_use: parsedDocs.intendedUse || [],
            limitations: parsedDocs.limitations || [],
            ethical_considerations: parsedDocs.ethicalConsiderations || [],
            bias_information: parsedDocs.biasInformation || [],
            security_notes: parsedDocs.securityNotes || [],
            // RFC 9116 security.txt parsed data
            security_txt: parsedDocs.securityTxt || null,
            source_files: parsedDocs.files || []
        } : null
    };
    
    // Extract model information
    for (const finding of modelFindings) {
        if (finding.modelInfo) {
            const modelInfo = finding.modelInfo;
            governance.models.push({
                provider: modelInfo.provider,
                name: modelInfo.modelName,
                type: modelInfo.modelType,
                intended_use: finding.description,
                detection_source: modelInfo.detectionSource || 'code-analysis',
                locations: modelInfo.locations || []
            });

            // Extract performance metrics from HuggingFace data
            if (modelInfo.huggingface?.cardData?.eval_results) {
                const evalResults = modelInfo.huggingface.cardData.eval_results;
                governance.quantitative_analysis.performance_metrics.push({
                    model: `${modelInfo.provider}/${modelInfo.modelName}`,
                    metrics: evalResults,
                    source: 'huggingface-eval-results',
                    detection_source: modelInfo.detectionSource || 'code-analysis'
                });
            }

            // Calculate carbon footprint if model parameters are available
            if (modelInfo.huggingface?.modelParameters) {
                const carbonFootprint = calculateCarbonFootprint(modelInfo.huggingface.modelParameters);
                if (carbonFootprint) {
                    governance.quantitative_analysis.carbon_footprints.push({
                        model: `${modelInfo.provider}/${modelInfo.modelName}`,
                        carbonFootprint: carbonFootprint,
                        detection_source: modelInfo.detectionSource || 'code-analysis'
                    });
                }
            }
        }
    }
    
    // Check documentation status from findings
    for (const finding of governanceFindings) {
        if (finding.riskInfo) {
            const type = finding.riskInfo.type;
            
            if (type === 'intended-use') {
                governance.documentation_status.intended_use_documented = true;
                governance.detected_considerations.push({
                    type: 'intended_use',
                    count: finding.riskInfo.count,
                    description: finding.description
                });
            } else if (type === 'limitations') {
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
    
    // Also check parsedDocs directly for documentation status
    if (parsedDocs) {
        if (parsedDocs.intendedUse && parsedDocs.intendedUse.length > 0) {
            governance.documentation_status.intended_use_documented = true;
        }
        if (parsedDocs.limitations && parsedDocs.limitations.length > 0) {
            governance.documentation_status.limitations_documented = true;
        }
        if (parsedDocs.ethicalConsiderations && parsedDocs.ethicalConsiderations.length > 0) {
            governance.documentation_status.ethical_considerations_documented = true;
        }
        if (parsedDocs.biasInformation && parsedDocs.biasInformation.length > 0) {
            governance.documentation_status.bias_fairness_documented = true;
        }
        
        // Check for README and documentation files from parsed docs
        governance.transparency.readme_present = parsedDocs.files.some(f => f && f.toLowerCase().includes('readme'));
        governance.transparency.model_cards_present = parsedDocs.files.some(f => f && f.toLowerCase().includes('model'));
        // Check for SECURITY.md or security.txt (RFC 9116)
        governance.transparency.security_documentation = parsedDocs.files.some(f => {
            const lower = f.toLowerCase();
            return lower.includes('security') || lower.endsWith('security.txt');
        }) || (parsedDocs.securityTxt !== null);
    }
    
    // Fallback: Check for README and documentation files from all findings if parsedDocs not available
    if (!parsedDocs) {
        const allFiles = findings.flatMap(f => f.evidence?.map(e => e.file) || []);
        governance.transparency.readme_present = allFiles.some(f => f && f.toLowerCase().includes('readme'));
        governance.transparency.model_cards_present = allFiles.some(f => f && f.toLowerCase().includes('model'));
        governance.transparency.security_documentation = allFiles.some(f => f && f.toLowerCase().includes('security'));
    }
    
    return governance;
}

/**
 * Extract risk assessment information
 */
function extractRiskAssessment(findings, analysisResult) {
    const riskFindings = findings.filter(f => f.category === 'risk');
    const governanceFindings = findings.filter(f => f.category === 'governance');

    // Extract model information for EU AI Act assessment
    const models = findings.filter(f => f.modelInfo).map(f => f.modelInfo);

    const risks = {
        overall_risk_level: 'low',
        missing_documentation: [],
        identified_risks: [],
        positive_indicators: [],
        recommendations: [],
        eu_ai_act: assessEUAIActCompliance(findings, models)
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
function extractDataPipelineMetadata(findings) {
    const depFindings = findings.filter(f => f.category === 'dependencies');
    const dataPipelineFindings = findings.filter(f => f.category === 'data-pipeline');

    const dataPipeline = {
        detected: false,
        data_loading: [],
        preprocessing: [],
        feature_engineering: [],
        data_versioning: [],
        datasets: [],
        frameworks: []
    };

    // Process data pipeline detector findings
    for (const finding of dataPipelineFindings) {
        if (finding.dataPipelineInfo) {
            dataPipeline.detected = true;
            const info = finding.dataPipelineInfo;

            // Add datasets
            if (info.datasets && info.datasets.length > 0) {
                dataPipeline.datasets.push(...info.datasets);
            }

            // Categorize tools
            const toolEntry = {
                tool: info.tool,
                category: info.category,
                evidence: finding.evidence?.[0] ? `${finding.evidence[0].file}:${finding.evidence[0].line}` : null
            };

            switch (info.category) {
                case 'loading':
                    dataPipeline.data_loading.push(toolEntry);
                    break;
                case 'preprocessing':
                    dataPipeline.preprocessing.push(toolEntry);
                    break;
                case 'feature_engineering':
                    dataPipeline.feature_engineering.push(toolEntry);
                    break;
                case 'data_versioning':
                    dataPipeline.data_versioning.push(toolEntry);
                    break;
            }
        }
    }

    // Check dependencies for data pipeline libraries (fallback)
    for (const finding of depFindings) {
        const depName = finding.dependencyInfo?.name?.toLowerCase() || finding.title.toLowerCase();

        // Data loading libraries
        if (depName.includes('datasets') || depName.includes('pandas') || depName.includes('numpy') ||
            depName.includes('kaggle')) {
            if (!dataPipeline.data_loading.some(item => item.library === finding.dependencyInfo?.name)) {
                dataPipeline.detected = true;
                dataPipeline.data_loading.push({
                    library: finding.dependencyInfo?.name || finding.title,
                    version: finding.dependencyInfo?.version,
                    source: 'dependency'
                });
            }
        }

        // Preprocessing libraries
        if (depName.includes('sklearn') || depName.includes('scikit-learn') ||
            depName.includes('nltk') || depName.includes('spacy') ||
            depName.includes('torchvision') || depName.includes('albumentations')) {
            if (!dataPipeline.preprocessing.some(item => item.library === finding.dependencyInfo?.name)) {
                dataPipeline.detected = true;
                dataPipeline.preprocessing.push({
                    library: finding.dependencyInfo?.name || finding.title,
                    version: finding.dependencyInfo?.version,
                    source: 'dependency'
                });
            }
        }

        // ML frameworks
        if (depName.includes('torch') || depName.includes('tensorflow') ||
            depName.includes('jax') || depName.includes('keras')) {
            if (!dataPipeline.frameworks.some(item => item.library === finding.dependencyInfo?.name)) {
                dataPipeline.detected = true;
                dataPipeline.frameworks.push({
                    library: finding.dependencyInfo?.name || finding.title,
                    version: finding.dependencyInfo?.version,
                    source: 'dependency'
                });
            }
        }

        // Data versioning
        if (depName.includes('dvc') || depName.includes('pachyderm')) {
            if (!dataPipeline.data_versioning.some(item => item.library === finding.dependencyInfo?.name)) {
                dataPipeline.detected = true;
                dataPipeline.data_versioning.push({
                    library: finding.dependencyInfo?.name || finding.title,
                    version: finding.dependencyInfo?.version,
                    source: 'dependency'
                });
            }
        }
    }

    // Deduplicate datasets
    dataPipeline.datasets = dataPipeline.datasets.filter((dataset, index, self) =>
        index === self.findIndex(d => d.name === dataset.name && d.source === dataset.source)
    );

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
            protocols: findings.filter(f => f.category === 'protocol').length,
            ai_dev_tools: findings.filter(f => f.category === 'ai-dev-tools').length,
            hardware: findings.filter(f => f.category === 'hardware').length,
            infrastructure: findings.filter(f => f.category === 'infrastructure').length,
            governance: findings.filter(f => f.category === 'governance').length,
            risks: findings.filter(f => f.category === 'risk').length
        },
        hardware_detected: metadata.hardware.detected,
        infrastructure_detected: metadata.infrastructure.detected,
        data_pipeline_detected: metadata.data_pipeline.detected,
        protocols_detected: findings.some(f => f.category === 'protocol'),
        ai_dev_tools_detected: findings.some(f => f.category === 'ai-dev-tools'),
        risk_level: metadata.risk_assessment.overall_risk_level,
        documentation_completeness: calculateDocumentationCompleteness(metadata.model_governance)
    };
}

/**
 * Extract analysis notes about components not found in this scan
 * PRACTICAL: What we scanned for but didn't find (scan-specific)
 * NOT: Philosophical limitations that apply to all scans
 */
function extractAnalysisNotes(findings, analysisResult) {
    const notes = {
        not_found_in_scan: [],
        suggested_improvements: []
    };
    
    // Check what we scanned for but didn't find
    const allFiles = findings.flatMap(f => f.evidence?.map(e => e.file) || []);
    const hasDependencies = findings.some(f => f.category === 'dependencies');
    const hasModels = findings.some(f => f.modelInfo);
    const hasHardware = findings.some(f => f.category === 'hardware');
    const hasInfrastructure = findings.some(f => f.category === 'infrastructure');
    const hasGovernance = findings.some(f => f.category === 'governance');
    const hasDataPipeline = findings.some(f => 
        f.dependencyInfo?.name?.match(/datasets|pandas|numpy|sklearn|spacy|nltk/)
    );
    
    // Documentation we scanned for but didn't find
    if (!allFiles.some(f => f && f.toLowerCase().includes('readme'))) {
        notes.not_found_in_scan.push({
            category: 'Documentation',
            item: 'README.md',
            searched: 'Scanned repository root and subdirectories',
            benefit: 'Would provide project overview, usage instructions, and model documentation'
        });
    }
    
    if (hasModels && !allFiles.some(f => f && f.toLowerCase().includes('model'))) {
        notes.not_found_in_scan.push({
            category: 'Documentation',
            item: 'MODEL_CARD.md',
            searched: 'Scanned for model card files in repository',
            benefit: 'Would document model intended use, limitations, performance, and ethical considerations'
        });
    }
    
    if (!allFiles.some(f => f && f.toLowerCase().includes('security'))) {
        notes.not_found_in_scan.push({
            category: 'Documentation',
            item: 'SECURITY.md',
            searched: 'Scanned repository root for security policy',
            benefit: 'Would provide vulnerability reporting procedures and security contacts'
        });
    }
    
    // Hardware we scanned for but didn't find
    if (!hasHardware && hasDependencies) {
        notes.not_found_in_scan.push({
            category: 'Hardware',
            item: 'GPU/TPU/Specialized Compute',
            searched: 'Scanned dependencies and code for CUDA, TensorRT, TPU patterns',
            benefit: 'Would document compute requirements and infrastructure needs'
        });
    }
    
    // Infrastructure we scanned for but didn't find
    if (!hasInfrastructure && (hasModels || hasDependencies)) {
        notes.not_found_in_scan.push({
            category: 'Infrastructure',
            item: 'Deployment Configuration',
            searched: 'Scanned for Dockerfile, docker-compose.yml, Kubernetes configs, cloud platform usage',
            benefit: 'Would document deployment environment and operational requirements'
        });
    }
    
    // Governance we scanned for but didn't find
    if (hasModels && !hasGovernance) {
        notes.not_found_in_scan.push({
            category: 'Governance',
            item: 'Model Governance Documentation',
            searched: 'Scanned for limitations, ethical considerations, bias/fairness documentation',
            benefit: 'Would document responsible AI practices and model constraints'
        });
    }
    
    // Data pipeline we scanned for but didn't find
    if (hasModels && !hasDataPipeline) {
        notes.not_found_in_scan.push({
            category: 'Data Pipeline',
            item: 'Data Processing Libraries',
            searched: 'Scanned dependencies for data loading, preprocessing, feature engineering tools',
            benefit: 'Would document data transformation and feature engineering process'
        });
    }
    
    // Generate suggested improvements based on what wasn't found
    const missingDocs = notes.not_found_in_scan.filter(n => n.category === 'Documentation');
    const missingGovernance = notes.not_found_in_scan.find(n => n.category === 'Governance');
    const missingInfra = notes.not_found_in_scan.find(n => n.category === 'Infrastructure');
    
    if (missingDocs.length > 0) {
        notes.suggested_improvements.push({
            priority: 'high',
            action: 'Add missing documentation files',
            files: missingDocs.map(d => d.item),
            benefit: 'Improves transparency and enables more complete AIBOM generation'
        });
    }
    
    if (missingGovernance) {
        notes.suggested_improvements.push({
            priority: 'high',
            action: 'Create model documentation',
            files: ['MODEL_CARD.md', 'LIMITATIONS.md'],
            benefit: 'Documents intended use, limitations, ethical considerations, and bias mitigation'
        });
    }
    
    if (missingInfra && hasModels) {
        notes.suggested_improvements.push({
            priority: 'medium',
            action: 'Add deployment configuration',
            files: ['Dockerfile', 'docker-compose.yml'],
            benefit: 'Documents runtime environment and makes deployment reproducible'
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

