// BOM Generator functions (CycloneDX & SPDX)
function generateCycloneDXJson(analysisResult, selectedFindings) {
    const { repository, analyzedAt } = analysisResult;
    const uuid = generateUUID();
    
    const bom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        version: 1,
        serialNumber: `urn:uuid:${uuid}`,
        metadata: {
            timestamp: analyzedAt,
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
        dependencies: []
    };
    
    // Group findings to create proper ML model components
    console.log('[BOM Generator] Creating components from findings...');
    const { components: modelComponents, modelRefs, libraryRefs, hardwareInfo, infraInfo, governanceInfo } = createMLModelComponents(selectedFindings);
    
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
    modelRefs.forEach(m => {
        console.log(`  - Model: ${m.component.name} (${m.component.author})`);
    });
    libraryRefs.forEach(l => {
        console.log(`  - Library: ${l.name}`);
    });
    
    bom.components = modelComponents;
    
    // Create dependency relationships
    const mainRef = `repo-${repository.owner}-${repository.repo}`;
    const libraryRefIds = libraryRefs.map(l => l['bom-ref']);
    
    // Main repo depends on all direct components
    bom.dependencies.push({
        ref: mainRef,
        dependsOn: bom.components.map(c => c['bom-ref'])
    });
    
    // ML models depend on their framework libraries
    modelRefs.forEach(model => {
        const deps = [];
        
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

function createMLModelComponents(findings) {
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
            const { provider, modelName, modelType, huggingface, files, detectionSource, relatedModels } = finding.modelInfo;
            const key = `${provider}-${modelName}`;
            
            if (!modelMap.has(key)) {
                const bomRef = `model-${generateShortId()}`;
                const component = {
                    type: 'machine-learning-model',
                    'bom-ref': bomRef,
                    author: provider,
                    name: modelName,
                    version: 'latest',
                    description: finding.description,
                    scope: 'required',
                    properties: []
                };
                
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
                
                // Add modelCard for ML models
                const modelCard = {
                    modelParameters: {
                        tasks: []
                    },
                    considerations: {}
                };
                
                if (huggingface) {
                    // Tasks
                    if (huggingface.pipeline_tag) {
                        modelCard.modelParameters.tasks.push({
                            task: huggingface.pipeline_tag
                        });
                    }
                    
                    // Architecture
                    modelCard.modelParameters.architectureFamily = huggingface.library_name || 'transformers';
                    if (huggingface.tags) {
                        const archTag = huggingface.tags.find(t => t.includes('gpt') || t.includes('bert') || t.includes('llama'));
                        if (archTag) {
                            modelCard.modelParameters.modelArchitecture = archTag;
                        }
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
                        modelCard.considerations.useCases = useCaseTags;
                    }
                } else {
                    // Use explicit modelType from finding for better accuracy
                    if (modelType === 'text-generation') {
                        modelCard.modelParameters.tasks.push({ task: 'text-generation' });
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
                        modelCard.modelParameters.tasks.push({ task: 'feature-extraction' });
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'vector' }];
                    } else if (modelType === 'text-to-image') {
                        modelCard.modelParameters.tasks.push({ task: 'text-to-image' });
                        modelCard.modelParameters.inputs = [{ format: 'text' }];
                        modelCard.modelParameters.outputs = [{ format: 'image' }];
                    } else if (modelType === 'multimodal') {
                        modelCard.modelParameters.tasks.push({ task: 'multimodal' });
                        modelCard.modelParameters.inputs = [{ format: 'text' }, { format: 'image' }];
                        modelCard.modelParameters.outputs = [{ format: 'text' }, { format: 'image' }];
                    } else {
                        // Fallback to name-based detection if type is unknown
                        if (modelName.includes('gpt') || modelName.includes('claude') || modelName.includes('gemini') || 
                            modelName.includes('llama') || modelName.includes('mistral') || modelName.includes('qwen')) {
                            modelCard.modelParameters.tasks.push({ task: 'text-generation' });
                            modelCard.modelParameters.inputs = [{ format: 'text' }];
                            modelCard.modelParameters.outputs = [{ format: 'text' }];
                        } else if (modelName.includes('embedding')) {
                            modelCard.modelParameters.tasks.push({ task: 'feature-extraction' });
                            modelCard.modelParameters.inputs = [{ format: 'text' }];
                            modelCard.modelParameters.outputs = [{ format: 'vector' }];
                        }
                    }
                }
                
                // Only add modelCard if it has content
                if (modelCard.modelParameters.tasks.length > 0 || 
                    Object.keys(modelCard.considerations).length > 0 ||
                    modelCard.modelParameters.architectureFamily) {
                    component.modelCard = modelCard;
                }
                
                // Add detection metadata to properties
                component.properties.push(
                    { name: 'cdx:detection:method', value: 'automated-code-analysis' },
                    { name: 'cdx:detection:confidence', value: finding.severity },
                    { name: 'cdx:detection:weight', value: finding.weight.toString() }
                );
                
                if (huggingface) {
                    component.properties.push(
                        { name: 'huggingface:downloads', value: huggingface.downloads?.toString() || '0' },
                        { name: 'huggingface:likes', value: huggingface.likes?.toString() || '0' }
                    );
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
        } else {
            // Generic finding - create a library/framework component
            const component = {
                type: finding.category === 'dependencies' ? 'library' : 'framework',
                'bom-ref': `component-${generateShortId()}`,
                name: finding.title,
                version: 'detected',
                description: finding.description,
                scope: 'required',
                properties: [
                    { name: 'cdx:detection:category', value: finding.category },
                    { name: 'cdx:detection:severity', value: finding.severity },
                    { name: 'cdx:detection:weight', value: finding.weight.toString() }
                ]
            };
            
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
    components.push(...models);
    
    // Add detected library dependencies
    const libraryComponents = createLibraryComponents(libraryDeps, findings);
    components.push(...libraryComponents);
    
    return { 
        components, 
        modelRefs: Array.from(modelMap.values()), 
        libraryRefs: libraryComponents,
        hardwareInfo,
        infraInfo,
        governanceInfo
    };
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

function generateCycloneDXXml(analysisResult, selectedFindings) {
    const { repository, analyzedAt } = analysisResult;
    const uuid = generateUUID();
    
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += `<bom xmlns="http://cyclonedx.org/schema/bom/1.7" version="1" serialNumber="urn:uuid:${uuid}">\n`;
    
    // Metadata
    xml += '  <metadata>\n';
    xml += `    <timestamp>${escapeXml(analyzedAt)}</timestamp>\n`;
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
    xml += '  </metadata>\n';
    
    // Components
    xml += '  <components>\n';
    const { components } = createMLModelComponents(selectedFindings);
    
    components.forEach(comp => {
        xml += `    <component type="${comp.type}" bom-ref="${escapeXml(comp['bom-ref'])}">\n`;
        if (comp.group) {
            xml += `      <group>${escapeXml(comp.group)}</group>\n`;
        }
        xml += `      <name>${escapeXml(comp.name)}</name>\n`;
        xml += `      <version>${escapeXml(comp.version)}</version>\n`;
        if (comp.description) {
            xml += `      <description>${escapeXml(comp.description)}</description>\n`;
        }
        if (comp.scope) {
            xml += `      <scope>${escapeXml(comp.scope)}</scope>\n`;
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
    
    // Dependencies - need to regenerate to match JSON structure
    xml += '  <dependencies>\n';
    
    const { modelRefs, libraryRefs } = createMLModelComponents(selectedFindings);
    const libraryRefIds = libraryRefs.map(l => l['bom-ref']);
    
    // Main repo depends on all components
    xml += `    <dependency ref="repo-${escapeXml(repository.owner)}-${escapeXml(repository.repo)}">\n`;
    components.forEach(comp => {
        xml += `      <dependency ref="${escapeXml(comp['bom-ref'])}" />\n`;
    });
    xml += '    </dependency>\n';
    
    // ML models depend on their libraries
    modelRefs.forEach(model => {
        xml += `    <dependency ref="${escapeXml(model.bomRef)}">\n`;
        
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
                'packageVersion': 'latest',
                'suppliedBy': {
                    'type': 'Organization',
                    'name': provider
                }
            };
            
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
        } else {
            // Regular library package
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
                'name': finding.title,
                'summary': finding.description,
                'packageVersion': 'detected',
                'downloadLocation': 'NOASSERTION',
                'primaryPurpose': 'library'
            };
            
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
 * Extract hardware information from findings
 */
function extractHardwareInfo(findings) {
    const hardwareFindings = findings.filter(f => f.category === 'hardware');
    const info = {
        detected: hardwareFindings.length > 0,
        types: [],
        libraries: []
    };
    
    for (const finding of hardwareFindings) {
        if (finding.hardwareInfo) {
            info.types.push(finding.hardwareInfo.type);
            if (finding.hardwareInfo.libraries) {
                info.libraries.push(...finding.hardwareInfo.libraries);
            }
        }
    }
    
    info.types = [...new Set(info.types)];
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
