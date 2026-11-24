// Node E2E harness: run the REAL generators (constants + utils + detectors helpers +
// bom-generators) against a finding set mirroring the KhanFaheed/chatAssistant
// scan (post Snyk-comparison uplift), then validate structure + compliance.
// Reproducible: `node scripts/tests/verify-e2e.js`
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
// Literal whitelist — src() is only called with these names, so the path
// join cannot be steered by any external input.
const SCRIPT_WHITELIST = [
  'constants.js', 'utils.js', 'bom-generators.js'
];
const src = (f) => {
  if (!SCRIPT_WHITELIST.includes(f)) {
    throw new Error(`Unexpected script name: ${f}`);
  }
  return fs.readFileSync(`${ROOT}/js/${f}`, 'utf8');
};

const realFetch = (p) => {
  const clean = String(p).split('?')[0].replace(/^\.\//, '');
  const abs = path.join(ROOT, clean);
  if (!fs.existsSync(abs)) {
    return Promise.resolve({ ok: false, status: 404, json: () => Promise.reject(new Error('404')) });
  }
  const text = fs.readFileSync(abs, 'utf8');
  return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(JSON.parse(text)) });
};

const ctx = {
  console: { log: () => {}, warn: console.warn, error: console.error },
  fetch: realFetch,
  performance: { now: () => Date.now() },
  crypto: require('crypto').webcrypto,
  setTimeout,
  clearTimeout,
};
vm.createContext(ctx);
for (const f of ['constants.js', 'utils.js', 'bom-generators.js']) {
  vm.runInContext(src(f), ctx, { filename: f });
}
const compliance = require(path.join(ROOT, 'js/compliance.js'));

const cardData = JSON.parse(fs.readFileSync(path.join(ROOT, 'modelcards/google/models-embedding-001.json'), 'utf8'));
const geminiCard = JSON.parse(fs.readFileSync(path.join(ROOT, 'modelcards/google/gemini-pro.json'), 'utf8'));

const findings = [
  {
    id: 'f-gemini', category: 'models', title: 'Google AI model: gemini-pro (text-generation)',
    description: 'Detected Google model gemini-pro', severity: 'high', weight: 5,
    modelInfo: {
      provider: 'Google', modelName: 'gemini-pro', modelType: 'text-generation', modelCardData: geminiCard,
      detectionSource: 'pattern',
      files: [{ path: 'app/utils/chatbot.py', line: 23, snippet: 'llm = ChatGoogleGenerativeAI(model="gemini-pro", temperature=0.2)' }]
    },
    evidence: [{ file: 'app/utils/chatbot.py', line: 23, snippet: 'llm = ChatGoogleGenerativeAI(model="gemini-pro")' }]
  },
  {
    id: 'f-embed-001', category: 'models', title: 'Google AI model: models/embedding-001 (embeddings)',
    description: 'Detected Google embedding model', severity: 'medium', weight: 5,
    modelInfo: {
      provider: 'Google', modelName: 'models/embedding-001', modelType: 'embeddings', modelCardData: cardData,
      detectionSource: 'pattern',
      files: [{ path: 'app/utils/prepare_vectordb.py', line: 52, snippet: 'embedding = GoogleGenerativeAIEmbeddings(model="models/embedding-001")' }]
    },
    evidence: [{ file: 'app/utils/prepare_vectordb.py', line: 52, snippet: 'embedding = GoogleGenerativeAIEmbeddings(model="models/embedding-001")' }]
  },
  {
    id: 'dep-python-langchain', category: 'dependencies', title: 'Dependency: langchain',
    description: 'LLM-related dependency: langchain (version: 0.1.13)', severity: 'high', weight: 5,
    dependencyInfo: { name: 'langchain', version: '0.1.13', ecosystem: 'python', source: 'github-sbom-api' },
    evidence: [{ file: 'GitHub Dependency Graph (SBOM)', snippet: 'SPDX Package: langchain@0.1.13' }]
  },
  {
    id: 'import-py-langchain-community', category: 'dependencies', title: 'Dependency: langchain-community',
    description: 'AI package imported in source but not declared in manifests: langchain-community (version unknown)',
    severity: 'medium', weight: 3,
    dependencyInfo: { name: 'langchain-community', version: 'unknown', ecosystem: 'python', source: 'source-import-analysis' },
    evidence: [{ file: 'app/utils/prepare_vectordb.py', line: 1, snippet: 'from langchain_community.document_loaders import PyPDFLoader' }]
  },
  {
    // HuggingFace model with API-synthesized card (no bundled local card)
    id: 'f-hf-bert', category: 'models', title: 'HuggingFace model: bert-base-uncased (fill-mask)',
    description: 'HuggingFace model: bert-base-uncased - 4200 downloads, License: apache-2.0',
    severity: 'high', weight: 5,
    modelInfo: {
      provider: 'HuggingFace', modelName: 'bert-base-uncased', modelType: 'fill-mask',
      detectionSource: 'HuggingFace Pattern Match',
      huggingface: {
        verified: true, id: 'bert-base-uncased', author: 'google-research',
        sha: 'f9c2dc59097785ff138a64bb2e313997894bca53',
        lastModified: '2026-06-01T00:00:00.000Z',
        downloads: 4200, likes: 250, license: 'apache-2.0', library_name: 'transformers',
        pipeline_tag: 'fill-mask',
        tags: ['fill-mask', 'en', 'license:apache-2.0', 'dataset:bookcorpus', 'arxiv:1810.04805', 'transformers'],
        architectures: ['BertForMaskedLM'],
        modelParameters: { contextWindow: 512, tokenizerClass: 'BertTokenizer' },
        cardData: { datasets: ['bookcorpus', 'wikipedia'] }
      },
      // Exactly what buildModelCardDataFromHuggingFace synthesizes when the
      // remote README has no parseable YAML
      modelCardData: {
        modelName: 'bert-base-uncased', provider: 'HuggingFace',
        source: 'huggingface-api', origin: 'open-source-hub',
        modelType: 'fill-mask',
        capabilities: ['fill-mask', 'en', 'transformers'],
        architecture: { type: 'BertForMaskedLM', contextLength: 512 },
        access: { license: 'apache-2.0', origin: 'open-source-hub' },
        references: { modelPage: 'https://huggingface.co/bert-base-uncased' }
      },
      files: [{ path: 'app/utils/embeddings.py', line: 8, snippet: 'model = AutoModel.from_pretrained("bert-base-uncased")' }]
    },
    evidence: [{ file: 'app/utils/embeddings.py', line: 8, snippet: 'AutoModel.from_pretrained("bert-base-uncased")' }]
  },
  {
    // Same model as 'models/embedding-001' detected via a bare name — must
    // merge into the attributed component (base-name dedup)
    id: 'f-embed-bare', category: 'models', title: 'Google AI model: embedding-001 (embeddings)',
    description: 'Bare-name detection of embedding-001', severity: 'medium', weight: 3,
    modelInfo: {
      provider: 'Google', modelName: 'embedding-001', modelType: 'embeddings',
      detectionSource: 'pattern',
      files: [{ path: 'app/utils/embed.py', line: 3, snippet: 'model = "embedding-001"' }]
    },
    evidence: [{ file: 'app/utils/embed.py', line: 3, snippet: 'model = "embedding-001"' }]
  },
  {
    // R5-lite: datasets captured by the data-pipeline detector
    id: 'f-data-pipeline', category: 'data-pipeline', title: 'HuggingFace Datasets Data Pipeline Detected',
    description: 'Found HuggingFace Datasets usage for data loading in 2 location(s)',
    severity: 'info', weight: 4,
    evidence: [{ file: 'app/data/load.py', line: 1, snippet: 'load_dataset("squad")' }],
    dataPipelineInfo: {
      tool: 'HuggingFace Datasets', category: 'data_loading',
      datasets: [
        { name: 'rajpurkar/squad', source: 'huggingface', location: 'app/data/load.py:1',
          hf: { id: 'rajpurkar/squad', license: 'apache-2.0', description: 'Stanford Question Answering Dataset.',
                lastModified: '2026-05-01T00:00:00.000Z', downloads: 98000 } },
        { name: 'bookcorpus', source: 'huggingface', location: 'app/data/load.py:2' }
      ]
    }
  },
  {
    // Local quantized model: version + quantization declared in the identifier
    id: 'f-meta-llama-v3-q4', category: 'models', title: 'Local model: meta-llama-v3-q4',
    description: 'Locally quantized model referenced by name',
    severity: 'medium', weight: 4,
    modelInfo: {
      provider: 'Ollama', modelName: 'meta-llama-v3-q4', modelType: 'text-generation',
      detectionSource: 'pattern',
      files: [{ path: 'scripts/run.sh', line: 5, snippet: 'MODEL=meta-llama-v3-q4' }]
    },
    evidence: [{ file: 'scripts/run.sh', line: 5, snippet: 'MODEL=meta-llama-v3-q4' }]
  },
  {
    // R1: hashed model artifact (matched to gemini-pro by name token)
    id: 'artifact-3f79bb7b435b', category: 'models', title: 'Model Artifact: gemini-pro-7b.safetensors (sha256 verified)',
    description: 'Model artifact with verified integrity: weights/gemini-pro-7b/model.safetensors',
    severity: 'medium', weight: 3,
    evidence: [{ file: 'weights/gemini-pro-7b/model.safetensors', snippet: 'Git-LFS pointer' }],
    artifactInfo: {
      path: 'weights/gemini-pro-7b/model.safetensors',
      sha256: '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea',
      sizeBytes: 1234567, source: 'git-lfs-pointer'
    }
  },
  {
    // R4: attestation presence
    id: 'attestation-presence', category: 'governance', title: 'Artifact signing / attestation detected',
    description: 'Signing or provenance evidence present in repository (sigstore bundle)',
    severity: 'medium', weight: 3,
    evidence: [{ file: 'model.sigstore.json', snippet: 'sigstore bundle present' }],
    attestationInfo: { detected: true, types: ['sigstore bundle'] }
  },
  {
    // CERT-In #12: guardrail tooling detected
    id: 'f-guardrail', category: 'guardrails', title: 'NVIDIA Guardrails Detected',
    description: 'Guardrails framework detected in requirements.txt',
    severity: 'medium', weight: 4,
    evidence: [{ file: 'requirements.txt', line: 9, snippet: 'nemoguardrails' }]
  }
];

const analysisResult = {
  repository: {
    owner: 'KhanFaheed', repo: 'chatAssistant', fullName: 'KhanFaheed/chatAssistant',
    description: '', htmlUrl: 'https://github.com/KhanFaheed/chatAssistant',
    topics: [], languages: ['Python'],
    systemVersion: '2.5.0', lastPushed: '2026-11-20T18:30:00Z'
  },
  analyzedAt: '2026-11-21T10:00:00.000Z'
};

(async () => {
  let failures = 0;
  const check = (cond, msg) => {
    if (cond) console.log(`  ok  ${msg}`);
    else { failures++; console.log(`FAIL  ${msg}`); }
  };

  ctx.__analysis = analysisResult;
  ctx.__findings = findings;
  const cdx = await vm.runInContext('generateCycloneDXJson(__analysis, __findings)', ctx);
  const spdx = await vm.runInContext('generateSPDX(__analysis, __findings)', ctx);
  const xml = await vm.runInContext('generateCycloneDXXml(__analysis, __findings)', ctx);
  const cdxDoc = JSON.parse(cdx);

  console.log('== library identity (P0 fix) ==');
  const libs = cdxDoc.components.filter(c => c.type === 'library');
  const langchain = libs.find(c => c.name === 'langchain');
  check(langchain && langchain.version === '0.1.13', `langchain clean name + version (${langchain && langchain.version})`);
  check(langchain && langchain.purl === 'pkg:pypi/langchain@0.1.13', `langchain purl (${langchain && langchain.purl})`);
  check(!libs.some(c => (c.name || '').startsWith('Dependency:')), 'no "Dependency:" prefixed names');
  check(!libs.some(c => c.version === 'detected'), 'no placeholder version "detected"');
  const lc = libs.find(c => c.name === 'langchain-community');
  check(lc && lc.version === undefined, 'import-only package: version omitted (unknown stays unknown)');
  check(lc && lc.purl === 'pkg:pypi/langchain-community', 'import-only package: unversioned purl');
  check(lc && lc.evidence && lc.evidence.identity[0].methods[0].technique === 'source-code-analysis',
    'import package evidence: source-code-analysis');
  const sbomLib = libs.find(c => c.name === 'langchain');
  check(sbomLib && sbomLib.evidence && sbomLib.evidence.identity[0].methods[0].technique === 'manifest-analysis',
    'SBOM library evidence: manifest-analysis');

  console.log('== model identity (P0 fix: no invented versions) ==');
  const models = cdxDoc.components.filter(c => c.type === 'machine-learning-model');
  check(models.length === 4, `four model components (${models.length})`);
  const bertModel = models.find(m => m.name === 'bert-base-uncased');
  check(bertModel && bertModel.version === 'f9c2dc59097785ff138a64bb2e313997894bca53',
    'HF hub model commit-pinned as version');
  const quantized = models.find(m => m.name === 'meta-llama-v3-q4');
  check(quantized && quantized.version === '3', 'name-declared version extracted (v3)');
  check(models.filter(m => m.name !== 'bert-base-uncased' && m.name !== 'meta-llama-v3-q4')
        .every(m => m.version === undefined),
    'genuinely unpinned models carry no invented version');
  const vsProps = models.map(m => m.properties.find(p => p.name === 'aibom:model:version-status')?.value);
  check(vsProps.includes('commit-pinned') && vsProps.includes('declared-in-identifier') &&
        vsProps.filter(v => v === 'unpinned-in-source').length === 2,
    `version-status recorded (${vsProps.join(', ')})`);
  check(models.every(m => m.properties.some(p => p.name === 'aibom:model:version-status')),
    'version-status property recorded');
  check(models.every(m => ['gemini-pro', 'models/embedding-001', 'bert-base-uncased', 'meta-llama-v3-q4'].includes(m.name)),
    'source identifiers preserved');

  console.log('== native CycloneDX evidence ==');
  const gemini = models.find(m => m.name === 'gemini-pro');
  check(gemini.evidence && gemini.evidence.identity[0].field === 'name', 'model evidence identity present');
  check(gemini.evidence.occurrences && gemini.evidence.occurrences[0].location === 'app/utils/chatbot.py'
        && gemini.evidence.occurrences[0].line === 23, 'model occurrence file+line recorded');
  check(!!gemini.evidence.occurrences[0].additionalContext, 'snippet preserved as additionalContext');

  console.log('== CycloneDX 1.7 modelCard schema validity ==');
  const mc = gemini.modelCard;
  check(mc.modelParameters.task === 'text-generation', `task singular string (${mc.modelParameters.task})`);
  check(mc.modelParameters.tasks === undefined && mc.modelParameters.modelType === undefined
        && mc.modelParameters.contextLength === undefined && mc.modelParameters.baseModel === undefined,
    'no schema-invalid modelParameters fields');
  check(mc.intendedUse === undefined && mc.limitations === undefined && mc.trainingData === undefined
        && mc.capabilities === undefined && mc.modelCardSource === undefined && mc.considerations.ethical === undefined,
    'no schema-invalid modelCard fields');
  check(Array.isArray(mc.considerations.useCases) && mc.considerations.useCases.includes('Multi-turn conversations'),
    `useCases from card primaryUses (${mc.considerations.useCases.length} entries)`);
  check(Array.isArray(mc.considerations.technicalLimitations)
        && mc.considerations.technicalLimitations.includes('Superseded by Gemini 1.5 Pro and Flash models'),
    'technicalLimitations from card');
  check(Array.isArray(mc.considerations.ethicalConsiderations)
        && mc.considerations.ethicalConsiderations[0].name === 'Bias & Fairness'
        && typeof mc.considerations.ethicalConsiderations[0].mitigationStrategy === 'string',
    'ethicalConsiderations risk objects');
  const propNames = mc.properties.map(p => p.name);
  check(propNames.includes('aibom:model-card-source'), 'modelCardSource → property');
  check(propNames.includes('aibom:capability'), 'capabilities → aibom:capability properties');
  check(propNames.includes('aibom:training-data'), 'trainingData → aibom:training-data property');
  check(propNames.includes('aibom:context-length'), 'contextLength → aibom:context-length property');
  check(propNames.includes('aibom:lifecycle-status'), 'lifecycle status → aibom:lifecycle-status property');
  check(propNames.includes('aibom:out-of-scope-use'), 'outOfScope → aibom:out-of-scope-use properties');
  check(mc.quantitativeAnalysis === undefined || Array.isArray(mc.quantitativeAnalysis.performanceMetrics),
    'quantitativeAnalysis shape valid');
  // required tasks must still exist for embeddings model
  const embed = models.find(m => m.name === 'models/embedding-001');
  check(embed.modelCard.modelParameters.task === 'feature-extraction', 'embeddings task singular');

  console.log('== external AI services ==');
  check(Array.isArray(cdxDoc.services) && cdxDoc.services.length === 1, `services emitted (${cdxDoc.services && cdxDoc.services.length})`);
  const svc = cdxDoc.services[0];
  check(svc && svc.name === 'Google Generative Language API', `service name (${svc && svc.name})`);
  check(svc && svc.endpoints[0] === 'https://generativelanguage.googleapis.com/v1beta', 'service endpoint');
  check(svc && svc.authenticated === true && svc.provider.name === 'Google', 'service provider + auth');
  const mainDep = cdxDoc.dependencies.find(d => d.ref.startsWith('repo-'));
  check(mainDep.dependsOn.includes(svc['bom-ref']), 'repo dependsOn service');
  check(models.filter(m => m.author === 'Google')
        .every(m => (cdxDoc.dependencies.find(d => d.ref === m['bom-ref']) || {dependsOn:[]}).dependsOn.includes(svc['bom-ref'])),
    'Google models dependOn service (data flow; HF hub model has no speculative service)');
  const depRefs = cdxDoc.dependencies.map(d => d.ref);
  check(new Set(depRefs).size === depRefs.length, 'dependency refs unique');

  console.log('== HuggingFace model card synthesis ==');
  const bert = models.find(m => m.name === 'bert-base-uncased');
  check(bert && bert.modelCard, 'HF model gets a modelCard (no bundled card needed)');
  const bertCardProps = {};
  (bert.modelCard.properties || []).forEach(p => { bertCardProps[p.name] = p.value; });
  check(bertCardProps['aibom:model-card-source'] === 'HuggingFace API — https://huggingface.co/bert-base-uncased',
    `model-card-source points at the HF API (${bertCardProps['aibom:model-card-source']})`);
  check(bertCardProps['aibom:origin'] === 'open-source-hub', 'origin classification (open-source-hub)');
  check(bertCardProps['aibom:context-length'] === '512', 'context length from HF config');
  check((bertCardProps['aibom:capability'] || '').length > 0 || (bert.modelCard.properties.filter(p => p.name === 'aibom:capability').length > 0),
    'capabilities as aibom:capability properties');
  check(bert.modelCard.modelParameters.task === 'fill-mask', 'task from HF pipeline_tag');
  check(bert.purl === 'pkg:huggingface/bert-base-uncased@f9c2dc59097785ff138a64bb2e313997894bca53',
    `commit-pinned HF purl (${bert.purl})`);
  check(Array.isArray(bert.licenses) && bert.licenses[0].license.id === 'apache-2.0', 'license from HF card data');
  check(bert.supplier?.name === 'google-research' && bert.manufacturer?.name === 'google-research' &&
        bert.author === 'google-research', 'supplier/manufacturer/author = HF org (not the platform)');
  const ds0 = (bert.modelCard.modelParameters.datasets || [])[0];
  check(ds0 && ds0.contents && ds0.contents.url === 'https://huggingface.co/datasets/bookcorpus',
    'training dataset with hub URL');
  const commitRef = (bert.externalReferences || []).find(r => r.comment === 'Specific commit');
  check(!!commitRef && commitRef.url.endsWith('/commit/f9c2dc59097785ff138a64bb2e313997894bca53'),
    'commit external reference');
  check((bert.externalReferences || []).some(r => r.url.endsWith('/tree/main')), 'model files distribution reference');
  check(!cdxDoc.services.some(s => s.provider.name === 'HuggingFace'), 'no speculative HF inference service');
  check(bertCardProps['aibom:tokenizer'] === 'BertTokenizer', 'aibom:tokenizer from tokenizer_config (G7 #29)');
  check(bertCardProps['aibom:last-modified'] === '2026-06-01T00:00:00.000Z', 'aibom:last-modified (G7 #23)');

  console.log('== name-embedded version/quantization extraction ==');
  const quantized2 = models.find(m => m.name === 'meta-llama-v3-q4');
  check(quantized2 && quantized2.version === '3',
    `version extracted from identifier (${quantized2 && quantized2.version})`);
  check(quantized2 && (quantized2.properties || []).some(p => p.name === 'aibom:model:quantization' && p.value === 'q4'),
    'quantization property (q4)');
  const quantStatus2 = quantized2 && quantized2.properties.find(p => p.name === 'aibom:model:version-status');
  check(quantStatus2 && quantStatus2.value === 'declared-in-identifier',
    `version-status = declared-in-identifier (${quantStatus2 && quantStatus2.value})`);
  check(!quantized2 || !quantized2.hashes, 'local model carries no hash claim');

  console.log('== R1: artifact hashes ==');
  const geminiModel = models.find(m => m.name === 'gemini-pro');
  check(models.length === 4, `duplicate bare-name model merged (${models.length} components for 4 distinct models)`);
  check(Array.isArray(geminiModel.hashes) && geminiModel.hashes[0].alg === 'SHA-256' &&
        geminiModel.hashes[0].content === '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea',
    'matched artifact sha256 on model component');
  check((geminiModel.modelCard.properties || []).some(p => p.name === 'aibom:release-date'),
    'aibom:release-date from bundled card (G7 #23)');
  check(Array.isArray(geminiModel.licenses) && geminiModel.licenses.some(l => l.license?.name),
    'license name from bundled card access.license (CERT-In #5/G7 #31)');
  const secControls = (cdxDoc.metadata.component.properties || []).find(p => p.name === 'aibom:security-controls');
  check(secControls && secControls.value === 'NVIDIA Guardrails Detected',
    'aibom:security-controls property (CERT-In #12)');
  const propNames0 = geminiModel.properties.map(p => p.name);
  check(propNames0.includes('aibom:artifact:path') && propNames0.includes('aibom:hash-source'),
    'artifact path + hash-source properties');
  check(!models.find(m => m.name === 'models/embedding-001').hashes,
    'unmatched model carries no hash claim');
  check(!models.some(m => m.name === 'embedding-001' && m.name !== 'models/embedding-001' && !m.name.includes('/')) &&
        models.filter(m => m.name.split('/').pop().toLowerCase() === 'embedding-001').length === 1,
    'bare-name duplicate merged into the attributed component');
  const mergedEmbed = models.find(m => m.name === 'models/embedding-001');
  const mergedOcc = (mergedEmbed.evidence?.occurrences || []).map(o => o.location);
  check(mergedOcc.includes('app/utils/embed.py'), 'merged component unions evidence occurrences');
  check(!cdxDoc.components.some(c => (c.name || '').includes('Model Artifact')),
    'artifact finding did not become a component');

  console.log('== model card references -> external references ==');
  const geminiRefs = (geminiModel.externalReferences || []).map(r => `${r.type}:${r.url}`);
  check(geminiRefs.some(r => r.startsWith('website:https://ai.google.dev/gemini-api/docs/models/gemini')),
    'modelPage reference emitted (website)');
  check(geminiRefs.some(r => r.startsWith('website:https://ai.google.dev/pricing')), 'pricing reference emitted');
  const bertRefs = (bert.externalReferences || []).map(r => `${r.type}:${r.url}`);
  check(bertRefs.some(r => r.startsWith('website:https://huggingface.co/bert-base-uncased')),
    'HF model page reference emitted (website)');
  check(models.every(m => !(m.externalReferences || []).some(r => !/^https?:\/\//i.test(r.url))),
    'all external reference urls are http(s)');

  console.log('== R3: header self-descriptions ==');
  check(Array.isArray(cdxDoc.metadata.lifecycles) && cdxDoc.metadata.lifecycles[0].phase === 'post-build',
    'metadata lifecycles post-build');
  const metaProps = {};
  (cdxDoc.metadata.properties || []).forEach(p => { metaProps[p.name] = p.value; });
  check(metaProps['aibom:scope'] === 'repository static source analysis (KhanFaheed/chatAssistant@main)',
    `aibom:scope (${metaProps['aibom:scope']})`);
  check((metaProps['aibom:completeness'] || '').startsWith('partial'), 'aibom:completeness declared');
  check(metaProps['aibom:generation-context'] === 'after-build', 'aibom:generation-context declared');
  check(metaProps['aibom:authorship'] === 'tool-generated', 'aibom:authorship declared');
  check(!!metaProps['aibom:graph-type'], 'aibom:graph-type declared');

  console.log('== R4: attestation state ==');
  check(metaProps['aibom:attestation'] === 'detected: sigstore bundle',
    `attestation state recorded (${metaProps['aibom:attestation']})`);

  console.log('== XML parity ==');
  check(xml.includes('<lifecycle><phase>post-build</phase></lifecycle>'), 'XML lifecycles (R3)');
  check(xml.includes('aibom:scope'), 'XML header properties (R3)');
  check(xml.includes('aibom:attestation'), 'XML attestation property (R4)');
  check(xml.includes('alg="SHA-256"'), 'XML model hashes (R1)');
  check(xml.includes('<service bom-ref="service-google">'), 'XML services');
  check(!xml.includes('<version>undefined</version>'), 'XML: no undefined version');
  check((xml.match(/type="machine-learning-model"/g) || []).length === models.length,
    'XML model components match JSON count (single assembly)');

  console.log('== gap-closing round: producer/version/timestamps/datasets ==');
  check(cdxDoc.metadata.manufacturer?.name === 'KhanFaheed', 'metadata.manufacturer = system producer (G7 #13)');
  check(metaProps['aibom:sbom-version'] === '1.0.0', 'aibom:sbom-version declared (G7 #2)');
  check(metaProps['aibom:system:timestamp'] === '2026-11-20T18:30:00Z', 'aibom:system:timestamp from repo push (G7 #15)');
  check(metaProps['aibom:system:version'] === '2.5.0', 'aibom:system:version from project manifest (G7 #14)');
  check(cdxDoc.metadata.component.version === '2.5.0', 'metadata component version = declared system version');
  check(cdxDoc.metadata.component.supplier?.name === 'KhanFaheed', 'component supplier = owner');
  const compProps = {};
  (cdxDoc.metadata.component.properties || []).forEach(p => { compProps[p.name] = p.value; });
  const areas = compProps['aibom:application-areas'] || '';
  check(areas.includes('text-generation') && areas.includes('fill-mask'), `aibom:application-areas aggregated (${areas})`);
  const dataSources = compProps['aibom:data-sources'] || '';
  check(dataSources.includes('rajpurkar/squad') && dataSources.includes('bookcorpus'),
    `aibom:data-sources recorded (${dataSources})`);
  const datasetComps = cdxDoc.components.filter(c => c.type === 'data');
  check(datasetComps.length === 2, `dataset components emitted (${datasetComps.length})`);
  check(datasetComps.every(c => (c.properties || []).some(p => p.name === 'aibom:dataset:source')),
    'dataset components carry source attribution');
  const squad = datasetComps.find(c => c.name === 'rajpurkar/squad');
  check(squad && (squad.externalReferences || []).some(r => r.url === 'https://huggingface.co/datasets/rajpurkar/squad'),
    'HF dataset external reference');
  check(squad && squad.licenses && squad.licenses[0].license.id === 'apache-2.0',
    'dataset license from HF datasets API (G7 #42)');
  check(squad && squad.description === 'Stanford Question Answering Dataset.', 'dataset description from API');
  const squadLastMod = (squad.properties || []).find(p => p.name === 'aibom:dataset:last-modified');
  check(squadLastMod && squadLastMod.value === '2026-05-01T00:00:00.000Z', 'dataset last-modified property');
  const bookcorpus = datasetComps.find(c => c.name === 'bookcorpus');
  check(bookcorpus && !bookcorpus.licenses, 'unresolvable dataset carries no license claim (honest)');
  check(cdxDoc.dependencies.find(d => d.ref.startsWith('repo-')).dependsOn.includes(squad['bom-ref']),
    'repo dependsOn dataset components (G7 #41)');
  check(datasetComps.every(c => !models.some(m => m['bom-ref'] === c['bom-ref'])), 'datasets distinct from models');

  console.log('== compliance validation of new output ==');
  const rc = compliance.validateCycloneDXBom(cdx);
  for (const c of rc.checks.filter(c => c.status === 'fail')) console.log(`  [fail] ${c.id}: ${c.detail}`);
  check(rc.checks.every(c => c.status !== 'fail'), 'CycloneDX validator: no failed checks');
  const rn = compliance.checkNtiaMinimumElements(cdx);
  const nv = rn.checks.find(c => c.id === 'ntia-version');
  check(nv.status === 'fail', `NTIA version honestly MISSING when unpinned (${nv.status}: ${nv.detail})`);
  const ns = rn.checks.find(c => c.id === 'ntia-supplier');
  check(ns.status === 'warn' && ns.detail.includes('4/11'),
    `NTIA supplier honest: 4 models attributed, libraries/datasets not (${ns.detail})`);
  const rs = compliance.validateSpdxBom(spdx);
  check(rs.checks.every(c => c.status !== 'fail'), 'SPDX validator: no failed checks');

  console.log('== SPDX output ==');
  const spdxDoc = JSON.parse(spdx);
  check((spdxDoc.comment || '').includes('Scope: repository static source analysis'),
    'SPDX document scope comment (R3)');
  const spdxRepo = spdxDoc.element.find(e => e.type === 'software_Package' && e.name === 'chatAssistant');
  check((spdxRepo.comment || '').includes('Attestation state: detected: sigstore bundle'),
    'SPDX repo attestation state (R4)');
  const spdxLibs = spdxDoc.element.filter(e => e.type === 'software_Package');
  check(spdxLibs.some(e => e.name === 'langchain' && e.packageVersion === '0.1.13'), 'SPDX langchain clean name+version');
  check(spdxLibs.some(e => e.name === 'langchain-community' && e.packageVersion === undefined), 'SPDX import pkg: no version');
  check(spdxLibs.every(e => !e.name.startsWith('Dependency:')), 'SPDX: no Dependency: prefixed names');
  check(spdxLibs.every(e => e.packageVersion !== 'detected'), 'SPDX: no placeholder versions');
  const spdxAi = spdxDoc.element.filter(e => e.type === 'ai_AIPackage');
  check(spdxAi.every(e => e.packageVersion === undefined || e.packageVersion === 'f9c2dc59097785ff138a64bb2e313997894bca53'),
    'SPDX: HF commit sha as packageVersion, no invented versions');
  const spdxGemini = spdxAi.find(e => e.name === 'gemini-pro');
  check(spdxGemini && spdxGemini.checksum && spdxGemini.checksum[0].checksumValue === '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea',
    'SPDX model checksum (R1)');
  check(spdxGemini.comment.includes('Artifact: weights/gemini-pro-7b/model.safetensors'),
    'SPDX model artifact comment');
  check(spdxDoc.element.every(e => !(e.name || '').startsWith('Model Artifact:')),
    'SPDX: artifact finding did not become a package');
  check(spdxAi.some(e => e.comment && e.comment.includes('chatbot.py:23')), 'SPDX model evidence comment');
  check(spdxLibs.some(e => e.comment && e.comment.includes('prepare_vectordb.py:1')), 'SPDX import evidence comment');
  check(spdxLibs.some(e => e.externalIdentifier && e.externalIdentifier[0].identifier === 'pkg:pypi/langchain@0.1.13'),
    'SPDX library purl externalIdentifier');

  console.log(failures === 0 ? '\nE2E PASSED' : `\n${failures} E2E FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((err) => { console.error('E2E CRASH:', err); process.exit(1); });
