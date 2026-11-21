// Standards Compliance panel logic.
//
// Two halves, both pure (no DOM) so tests.html can assert on them:
//
// 1. Dynamic per-document validation — checks the BOMs the app just
//    generated (generatedBOMs in ui.js) against the published requirements
//    of CycloneDX 1.7, SPDX 3.0.1 (JSON-LD), and the NTIA minimum elements.
//
// 2. Static AIBOM standards scorecard — element-by-element conformance of
//    this tool's output surface against CERT-In Table 10, the G7 SBOM-for-AI
//    minimum elements, and the OWASP AIBOM Foundations checklist. Transcribed
//    from guidance/guidance_details.md §6 (2026-11-20 assessment) and updated
//    when the implementation changes — scores move with the code, and the
//    changed rows (and why) are documented in DETAILED_CHANGELOG.md. Recent
//    deltas vs the §6 snapshot (2026-11-21): CERT-In #2 dropped to unmet —
//    invented model versions ("latest") removed so unknown stays unknown;
//    CERT-In #16 rose to met — out-of-scope uses extracted (R10, local
//    cards); G7 #22 dropped to unmet (same version cleanup); G7 #16 note
//    updated — external inference services now carry endpoints/trust-boundary
//    info (still no flow payload typing).
//    Net vs §6 (65.8/45.0/50.0 weighted): CERT-In 68.4% (13/19, strict
//    52.6%), G7 44.0% (22/50), OWASP 50.0% unchanged.
//
// Status vocabulary for dynamic checks: 'pass' | 'warn' | 'fail'
// Status vocabulary for scorecard rows:  'met' | 'partial' | 'unmet'

// ============================================================================
// 1. DYNAMIC DOCUMENT VALIDATION
// ============================================================================

/**
 * Parse a generated BOM JSON string defensively.
 * @param {string} text Raw BOM output
 * @returns {{ok: boolean, doc: Object|null, error: string|null}}
 */
function parseBomJson(text) {
  if (!text || typeof text !== 'string') {
    return { ok: false, doc: null, error: 'No document generated' };
  }
  const trimmed = text.trim();
  if (trimmed.startsWith('//') || trimmed.startsWith('<')) {
    return { ok: false, doc: null, error: 'No findings selected — BOM not generated' };
  }
  try {
    return { ok: true, doc: JSON.parse(trimmed), error: null };
  } catch (err) {
    return { ok: false, doc: null, error: `Invalid JSON: ${err.message}` };
  }
}

function isIsoTimestamp(value) {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isUuidUrn(value) {
  return typeof value === 'string' &&
    /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function makeCheck(id, label, status, detail) {
  return { id, label, status, detail };
}

/**
 * Validate the generated CycloneDX JSON document against CycloneDX 1.7
 * required/recommended fields.
 * @param {string} text generatedBOMs['cyclonedx-json']
 * @returns {{standard: string, format: string, checks: Array}}
 */
function validateCycloneDXBom(text) {
  const checks = [];
  const parsed = parseBomJson(text);
  if (!parsed.ok) {
    checks.push(makeCheck('parse', 'Document is valid JSON', 'fail', parsed.error));
    return { standard: 'CycloneDX 1.7', format: 'JSON', checks };
  }
  const bom = parsed.doc;

  checks.push(makeCheck('format', 'bomFormat is "CycloneDX"',
    bom.bomFormat === 'CycloneDX' ? 'pass' : 'fail',
    `bomFormat: ${JSON.stringify(bom.bomFormat)}`));

  checks.push(makeCheck('spec-version', 'specVersion declares the target spec',
    typeof bom.specVersion === 'string' ? 'pass' : 'fail',
    `specVersion: ${JSON.stringify(bom.specVersion)}`));

  checks.push(makeCheck('serial', 'serialNumber is a valid URN UUID (1.7 required format)',
    isUuidUrn(bom.serialNumber) ? 'pass' : 'fail',
    `serialNumber: ${JSON.stringify(bom.serialNumber)}`));

  checks.push(makeCheck('doc-version', 'Document revision `version` is an integer ≥ 1',
    Number.isInteger(bom.version) && bom.version >= 1 ? 'pass' : 'fail',
    `version: ${JSON.stringify(bom.version)}`));

  checks.push(makeCheck('timestamp', 'metadata.timestamp is a valid ISO 8601 date',
    isIsoTimestamp(bom.metadata && bom.metadata.timestamp) ? 'pass' : 'fail',
    `timestamp: ${JSON.stringify(bom.metadata && bom.metadata.timestamp)}`));

  const metaComp = bom.metadata && bom.metadata.component;
  checks.push(makeCheck('metadata-component', 'metadata.component present with type, name and bom-ref',
    metaComp && metaComp.type && metaComp.name && metaComp['bom-ref'] ? 'pass' : 'fail',
    metaComp ? `name: ${metaComp.name}` : 'missing metadata.component'));

  const components = Array.isArray(bom.components) ? bom.components : [];
  const missingType = components.filter((c) => !c.type).length;
  const missingName = components.filter((c) => !c.name).length;
  checks.push(makeCheck('component-required', 'Every component has type and name (spec required)',
    missingType === 0 && missingName === 0 ? 'pass' : 'fail',
    `${components.length} components; ${missingType} missing type, ${missingName} missing name`));

  const refs = components.map((c) => c['bom-ref']).filter(Boolean);
  const uniqueRefs = new Set(refs).size === refs.length;
  const allHaveRef = components.every((c) => c['bom-ref']);
  checks.push(makeCheck('bom-ref', 'Every component has a unique bom-ref',
    allHaveRef && uniqueRefs ? 'pass' : (uniqueRefs && !allHaveRef ? 'warn' : 'fail'),
    `${refs.length}/${components.length} components carry bom-ref; duplicates: ${refs.length - new Set(refs).size}`));

  const withPurl = components.filter((c) => typeof c.purl === 'string' && c.purl.startsWith('pkg:')).length;
  checks.push(makeCheck('purl', 'Package URLs present where identifiable (recommended)',
    withPurl > 0 ? 'pass' : 'warn',
    `${withPurl}/${components.length} components carry a pkg: purl`));

  const depRefs = new Set([...components.map((c) => c['bom-ref']),
    ...(metaComp ? [metaComp['bom-ref']] : []),
    ...((Array.isArray(bom.services) ? bom.services : []).map((s) => s['bom-ref']))].filter(Boolean));
  const deps = Array.isArray(bom.dependencies) ? bom.dependencies : [];
  const unresolved = [];
  for (const dep of deps) {
    if (dep.ref && !depRefs.has(dep.ref)) unresolved.push(dep.ref);
    for (const target of dep.dependsOn || []) {
      if (!depRefs.has(target)) unresolved.push(target);
    }
  }
  checks.push(makeCheck('dependency-refs', 'Dependency graph refs all resolve to components',
    deps.length > 0 && unresolved.length === 0 ? 'pass' : (unresolved.length > 0 ? 'fail' : 'warn'),
    `${deps.length} dependency entries; unresolved refs: ${unresolved.length}`));

  return { standard: 'CycloneDX 1.7', format: 'JSON', checks };
}

/**
 * Validate the generated CycloneDX JSON document against the NTIA "The
 * Minimum Elements For An SBOM" (2021) seven-element baseline.
 * @param {string} text generatedBOMs['cyclonedx-json']
 * @returns {{standard: string, format: string, checks: Array}}
 */
function checkNtiaMinimumElements(text) {
  const parsed = parseBomJson(text);
  const checks = [];
  if (!parsed.ok) {
    checks.push(makeCheck('parse', 'Document is valid JSON', 'fail', parsed.error));
    return { standard: 'NTIA Minimum Elements (2021)', format: 'JSON', checks };
  }
  const bom = parsed.doc;
  const components = Array.isArray(bom.components) ? bom.components : [];

  const noVersion = components.filter((c) => !c.version).length;
  const placeholderVersion = components.filter((c) => c.version === 'latest').length;
  checks.push(makeCheck('ntia-version', 'All components have a version',
    components.length === 0 ? 'warn' : (noVersion === 0 ? 'pass' : 'fail'),
    noVersion === 0
      ? (placeholderVersion > 0
        ? `${placeholderVersion} component(s) use placeholder version "latest"`
        : 'all components carry a version')
      : `${noVersion} component(s) missing version`));

  const noName = components.filter((c) => !c.name).length;
  checks.push(makeCheck('ntia-name', 'All components have a name',
    noName === 0 ? 'pass' : 'fail',
    `${noName} component(s) missing name`));

  const noSupplier = components.filter((c) => !c.supplier && !c.author && !c.publisher && !c.group).length;
  checks.push(makeCheck('ntia-supplier', 'All components have a supplier name',
    components.length === 0 ? 'warn' : (noSupplier === 0 ? 'pass' : 'warn'),
    `${components.length - noSupplier}/${components.length} components carry supplier/author/publisher/group attribution`));

  const noId = components.filter((c) => !c['bom-ref'] && !c.purl).length;
  const uniqueRefs = new Set(components.map((c) => c['bom-ref']).filter(Boolean));
  const dupRefs = components.length - uniqueRefs.size;
  checks.push(makeCheck('ntia-identifier', 'All components have a unique identifier (bom-ref/purl)',
    components.length === 0 ? 'warn' : (noId === 0 && dupRefs === 0 ? 'pass' : 'warn'),
    `${components.length} components; ${noId} without identifier; ${dupRefs} duplicate/missing bom-refs`));

  const deps = Array.isArray(bom.dependencies) ? bom.dependencies : [];
  checks.push(makeCheck('ntia-relationships', 'Dependency relationships describe the component tree',
    deps.length > 0 ? 'pass' : 'warn',
    `${deps.length} dependency entries`));

  const metaComp = bom.metadata && bom.metadata.component;
  const authorKnown = !!(bom.metadata && (bom.metadata.author || bom.metadata.supplier));
  checks.push(makeCheck('ntia-author', 'Author of the SBOM data identified',
    authorKnown ? 'pass' : 'warn',
    authorKnown ? 'metadata author/supplier present' :
      'tool name recorded in metadata.tools but no authoring entity (browser app has no account identity)'));

  checks.push(makeCheck('ntia-timestamp', 'Timestamp of the SBOM generation',
    isIsoTimestamp(bom.metadata && bom.metadata.timestamp) ? 'pass' : 'fail',
    `timestamp: ${JSON.stringify(bom.metadata && bom.metadata.timestamp)}`));

  checks.push(makeCheck('ntia-profile', 'Recommended: profile depth (AI components vs plain libraries)',
    'warn',
    metaComp && components.length > 0
      ? `${components.length} components in baseline profile; AIBOM-specific depth tracked in the scorecard below`
      : 'no components detected'));

  return { standard: 'NTIA Minimum Elements (2021)', format: 'JSON', checks };
}

/**
 * Validate the generated SPDX document against SPDX 3.0.1 JSON-LD shape.
 * @param {string} text generatedBOMs['spdx']
 * @returns {{standard: string, format: string, checks: Array}}
 */
function validateSpdxBom(text) {
  const checks = [];
  const parsed = parseBomJson(text);
  if (!parsed.ok) {
    checks.push(makeCheck('parse', 'Document is valid JSON', 'fail', parsed.error));
    return { standard: 'SPDX 3.0.1', format: 'JSON-LD', checks };
  }
  const doc = parsed.doc;

  checks.push(makeCheck('context', '@context references the SPDX 3.0.1 JSON-LD context',
    typeof doc['@context'] === 'string' && doc['@context'].includes('spdx.org/rdf/3.0.1') ? 'pass' : 'fail',
    `@context: ${JSON.stringify(doc['@context'])}`));

  checks.push(makeCheck('doc-type', 'Document type is SpdxDocument',
    doc.type === 'SpdxDocument' ? 'pass' : 'fail',
    `type: ${JSON.stringify(doc.type)}`));

  checks.push(makeCheck('spdx-id', 'spdxId present (document IRI)',
    typeof doc.spdxId === 'string' && doc.spdxId.length > 0 ? 'pass' : 'fail',
    `spdxId: ${JSON.stringify(doc.spdxId)}`));

  const ci = doc.creationInfo;
  checks.push(makeCheck('creation-created', 'creationInfo.created is a valid ISO 8601 date',
    isIsoTimestamp(ci && ci.created) ? 'pass' : 'fail',
    `created: ${JSON.stringify(ci && ci.created)}`));

  checks.push(makeCheck('creation-by', 'creationInfo.createdBy names the creating agent',
    ci && Array.isArray(ci.createdBy) && ci.createdBy.length > 0 ? 'pass' : 'fail',
    `createdBy: ${JSON.stringify(ci && ci.createdBy)}`));

  checks.push(makeCheck('creation-spec', 'creationInfo.specVersion is 3.0.1',
    ci && ci.specVersion === '3.0.1' ? 'pass' : 'fail',
    `specVersion: ${JSON.stringify(ci && ci.specVersion)}`));

  const elements = Array.isArray(doc.element) ? doc.element : [];
  const badElements = elements.filter((el) => !el['@id'] || !el.type).length;
  checks.push(makeCheck('elements', 'Every element has @id and type',
    elements.length > 0 && badElements === 0 ? 'pass' : 'fail',
    `${elements.length} elements; ${badElements} malformed`));

  const ids = elements.map((el) => el.spdxId || el['@id']);
  checks.push(makeCheck('element-ids', 'Element spdxIds are unique',
    new Set(ids).size === ids.length ? 'pass' : 'fail',
    `${ids.length} ids; duplicates: ${ids.length - new Set(ids).size}`));

  const idSet = new Set(ids);
  const rootDangling = (doc.rootElement || []).filter((id) => !idSet.has(id));
  checks.push(makeCheck('root-elements', 'rootElement refs resolve to elements',
    (doc.rootElement || []).length > 0 && rootDangling.length === 0 ? 'pass' : 'fail',
    `${(doc.rootElement || []).length} roots; dangling: ${rootDangling.length}`));

  const relationships = elements.filter((el) => el.type === 'Relationship');
  const danglingRel = [];
  for (const rel of relationships) {
    if (rel.from && !idSet.has(rel.from)) danglingRel.push(rel.spdxId || rel['@id']);
    for (const to of rel.to || []) {
      if (!idSet.has(to)) danglingRel.push(rel.spdxId || rel['@id']);
    }
  }
  checks.push(makeCheck('relationships', 'Relationship from/to refs resolve to elements',
    danglingRel.length === 0 ? 'pass' : 'fail',
    `${relationships.length} relationships; dangling: ${danglingRel.length}`));

  return { standard: 'SPDX 3.0.1', format: 'JSON-LD', checks };
}

// ============================================================================
// 2. STATIC AIBOM STANDARDS SCORECARD
// ============================================================================
//
// Transcribed from guidance/guidance_details.md §6.1–§6.3 (assessment dated
// 2026-11-20). Row statuses: met (✅, 1.0) / partial (🟡, 0.5) / unmet (❌, 0).
// `structural: true` marks ⛔ rows — not derivable by a post-hoc, browser-only
// scanner, so they are structural limits rather than unimplemented features.
// Several rows note the recommendation (R1/R3/R4/R5/R10) that would close them.

const AIBOM_SCORECARD = [
  {
    id: 'certin',
    name: 'CERT-In Technical Guidelines v2.0 — Table 10 (AIBOM elements)',
    ref: 'guidance/guidance_details.md §6.1',
    rows: [
      { n: 1, element: 'Model Name', status: 'met', note: 'modelsIdentifierDetector → component name' },
      { n: 2, element: 'Model Version', status: 'unmet', note: 'version omitted unless derived from a model card (invented "latest" removed 2026-11-21); no commit/tag pinning' },
      { n: 3, element: 'Model Type', status: 'met', note: 'text-generation / embeddings / text-to-image + typeOfModel' },
      { n: 4, element: 'Model Developer', status: 'met', note: 'provider attribution (author on component; HF org)' },
      { n: 5, element: 'Model Licensing Information', status: 'partial', note: 'licenseConcluded only from verified HF model card; repo LICENSE not correlated per model' },
      { n: 6, element: 'Software Dependencies', status: 'met', note: 'dependencies detector (SBOM API + go/rust/java fallback parsers)' },
      { n: 7, element: 'ML Models and Algorithms', status: 'partial', note: 'architectureFamily/modelArchitecture from cards; decision-process docs not derivable' },
      { n: 8, element: 'Model Performance Metrics', status: 'met', note: 'quantitativeAnalysis.performanceMetrics + metricDecisionThreshold' },
      { n: 9, element: 'Data Source', status: 'partial', note: 'dataset names extracted (load_dataset, kagglehub); not attributed per model' },
      { n: 10, element: 'Data Sets', status: 'partial', note: 'names + identifiers only; no version/format/limitations fields' },
      { n: 11, element: 'Hardware', status: 'met', note: 'hardwareDetector → GPU/TPU/specialized + aibom:hardware properties' },
      { n: 12, element: 'Security Requirements', status: 'partial', note: 'guardrail detection as positive indicator; no explicit controls field' },
      { n: 13, element: 'Input', status: 'met', note: 'modelCard.modelParameters.inputs' },
      { n: 14, element: 'Output', status: 'met', note: 'modelCard.modelParameters.outputs' },
      { n: 15, element: 'Intended Usage', status: 'met', note: 'modelCard.considerations.useCases + aibom:intended-use' },
      { n: 16, element: 'Out of Scope Usage', status: 'met', note: 'aibom:out-of-scope-use properties from card outOfScope (added 2026-11-21, R10 closed for local cards)' },
      { n: 17, element: 'Environmental Impact', status: 'partial', note: 'carbon-footprint estimate in extended AIBOM (heuristic, labeled as such)' },
      { n: 18, element: 'Vulnerabilities', status: 'unmet', structural: true, note: 'no CVE feed client-side; obtain via supplier VEX/advisory channels' },
      { n: 19, element: 'Attestations', status: 'unmet', note: 'no signature/attestation state recorded (R4 deferred)' }
    ]
  },
  {
    id: 'g7',
    name: 'G7 Cyber Group — SBOM for AI: Minimum Elements (50 elements)',
    ref: 'guidance/guidance_details.md §6.2',
    clusters: true,
    rows: [
      { n: 1, cluster: 'Metadata (§2.1)', element: 'SBOM author', status: 'unmet', note: 'tool name emitted; no authoring entity field' },
      { n: 2, cluster: 'Metadata (§2.1)', element: 'SBOM version', status: 'unmet', note: 'serialNumber + timestamp only; no SemVer document version' },
      { n: 3, cluster: 'Metadata (§2.1)', element: 'SBOM data format name', status: 'met', note: 'bomFormat: CycloneDX / SPDX spdxVersion' },
      { n: 4, cluster: 'Metadata (§2.1)', element: 'SBOM data format version', status: 'met', note: '1.7 / 3.0.1' },
      { n: 5, cluster: 'Metadata (§2.1)', element: 'SBOM author signature', status: 'unmet', structural: true, note: 'browser has no signing keys' },
      { n: 6, cluster: 'Metadata (§2.1)', element: 'SBOM tool name', status: 'met', note: '"AI BOM Generator" metadata component' },
      { n: 7, cluster: 'Metadata (§2.1)', element: 'SBOM tool version', status: 'met', note: 'tool component version' },
      { n: 8, cluster: 'Metadata (§2.1)', element: 'SBOM generation context', status: 'unmet', note: 'no declared lifecycle phase (R3 deferred)' },
      { n: 9, cluster: 'Metadata (§2.1)', element: 'SBOM timestamp', status: 'met', note: 'metadata.timestamp / <timestamp> / created' },
      { n: 10, cluster: 'Metadata (§2.1)', element: 'SBOM dependency relationship', status: 'met', note: 'dependencies graph' },
      { n: 11, cluster: 'System Level (§2.2)', element: 'System name', status: 'met', note: 'repository component' },
      { n: 12, cluster: 'System Level (§2.2)', element: 'System components', status: 'met', note: 'full component list' },
      { n: 13, cluster: 'System Level (§2.2)', element: 'System producer', status: 'partial', note: 'repo owner in name/purl; no explicit producer field' },
      { n: 14, cluster: 'System Level (§2.2)', element: 'System version', status: 'unmet', note: 'repo version not detected (package.json version not read)' },
      { n: 15, cluster: 'System Level (§2.2)', element: 'System timestamp', status: 'unmet', note: 'model/update timestamps not emitted' },
      { n: 16, cluster: 'System Level (§2.2)', element: 'System data flow', status: 'partial', note: 'dependency graph + external inference services (endpoints, trust boundary); no flow payload/modality typing' },
      { n: 17, cluster: 'System Level (§2.2)', element: 'System data usage', status: 'unmet', structural: true, note: 'training-improvement/API-logging disclosure lives in policies, not source' },
      { n: 18, cluster: 'System Level (§2.2)', element: 'System input/output properties', status: 'partial', note: 'per-model I/O from cards; no system-level aggregation' },
      { n: 19, cluster: 'System Level (§2.2)', element: 'Intended application area', status: 'partial', note: 'per-model intended use; not system-level' },
      { n: 20, cluster: 'Models (§2.3)', element: 'Model name', status: 'met', note: '' },
      { n: 21, cluster: 'Models (§2.3)', element: 'Model identifier (CPE/PURL)', status: 'met', note: 'pkg:pypi/…, pkg:huggingface/…, pkg:ml/… purls' },
      { n: 22, cluster: 'Models (§2.3)', element: 'Model version', status: 'unmet', note: 'version omitted (invented "latest" removed 2026-11-21); identifier preserved as-is' },
      { n: 23, cluster: 'Models (§2.3)', element: 'Model timestamp', status: 'unmet', note: 'release dates not emitted' },
      { n: 24, cluster: 'Models (§2.3)', element: 'Model producer', status: 'met', note: 'provider attribution via lineage' },
      { n: 25, cluster: 'Models (§2.3)', element: 'Model description (lineage, dependencies)', status: 'met', note: 'fine-tuned-from relationships, relatedModels' },
      { n: 26, cluster: 'Models (§2.3)', element: 'Model hash value', status: 'unmet', note: 'R1 deferred (Git-LFS pointer parsing is the path)' },
      { n: 27, cluster: 'Models (§2.3)', element: 'Model hash algorithm', status: 'unmet', note: 'R1 deferred' },
      { n: 28, cluster: 'Models (§2.3)', element: 'Model properties (params, architecture)', status: 'met', note: 'num_parameters, architectureFamily, hyperparameter/contextWindow' },
      { n: 29, cluster: 'Models (§2.3)', element: 'Model input-output properties', status: 'partial', note: 'context window yes; tokenizer type not extracted' },
      { n: 30, cluster: 'Models (§2.3)', element: 'Model training properties', status: 'partial', note: 'informationAboutTraining from card when present; not parsed from configs' },
      { n: 31, cluster: 'Models (§2.3)', element: 'Model license', status: 'partial', note: 'verified HF cards only' },
      { n: 32, cluster: 'Models (§2.3)', element: 'Model external references', status: 'met', note: 'model card object, HF URL, provider docs' },
      { n: 33, cluster: 'Datasets (§2.4)', element: 'Dataset name', status: 'partial', note: 'names in data-pipeline findings (R5 would componentize)' },
      { n: 34, cluster: 'Datasets (§2.4)', element: 'Dataset description', status: 'unmet', note: '' },
      { n: 35, cluster: 'Datasets (§2.4)', element: 'Dataset content (format/encoding)', status: 'unmet', note: '' },
      { n: 36, cluster: 'Datasets (§2.4)', element: 'Dataset identifier', status: 'partial', note: 'HF org/name / Kaggle ids from dataPipelineDetector' },
      { n: 37, cluster: 'Datasets (§2.4)', element: 'Dataset hash', status: 'unmet', note: 'R1 deferred' },
      { n: 38, cluster: 'Datasets (§2.4)', element: 'Dataset provenance', status: 'unmet', structural: true, note: 'collection methods not in source code' },
      { n: 39, cluster: 'Datasets (§2.4)', element: 'Dataset statistical properties', status: 'unmet', structural: true, note: 'requires dataset access' },
      { n: 40, cluster: 'Datasets (§2.4)', element: 'Dataset sensitivity', status: 'unmet', note: 'no classification field' },
      { n: 41, cluster: 'Datasets (§2.4)', element: 'Dataset dependency relationship', status: 'unmet', note: 'build tooling not linked' },
      { n: 42, cluster: 'Datasets (§2.4)', element: 'Dataset license', status: 'unmet', note: '' },
      { n: 43, cluster: 'Infrastructure (§2.5)', element: 'Infrastructure software', status: 'met', note: 'frameworks/runtimes/serving/MLOps detection' },
      { n: 44, cluster: 'Infrastructure (§2.5)', element: 'Infrastructure hardware', status: 'met', note: 'GPU/TPU/specialized detection (HBOM-style properties)' },
      { n: 45, cluster: 'Security (§2.6)', element: 'Security controls (incl. prompt-injection)', status: 'partial', note: 'guardrail packages + OWASP-pack mitigation indicator; no controls field' },
      { n: 46, cluster: 'Security (§2.6)', element: 'Security compliance', status: 'unmet', note: 'certification schemes not detectable in source' },
      { n: 47, cluster: 'Security (§2.6)', element: 'Cybersecurity policy info (security.txt)', status: 'met', note: 'RFC 9116 parser in documentationParser' },
      { n: 48, cluster: 'Security (§2.6)', element: 'Vulnerability referencing', status: 'unmet', structural: true, note: 'no CVE feed (R6)' },
      { n: 49, cluster: 'KPIs (§2.7)', element: 'Security metrics', status: 'unmet', structural: true, note: 'robustness benchmarks are evaluation-time artifacts' },
      { n: 50, cluster: 'KPIs (§2.7)', element: 'Operational performance KPIs', status: 'unmet', structural: true, note: 'runtime telemetry (uptime/latency/throughput)' }
    ]
  },
  {
    id: 'owasp',
    name: 'OWASP AIBOM Foundations v1.0 — 4-part structure (24-point checklist)',
    ref: 'guidance/guidance_details.md §6.3',
    clusters: true,
    rows: [
      { n: 1, cluster: 'Part 1 — Header', element: 'Graph type declaration', status: 'unmet', note: 'not emitted (R3 deferred)' },
      { n: 2, cluster: 'Part 1 — Header', element: 'Scope declaration', status: 'unmet', note: 'not emitted (R3 deferred)' },
      { n: 3, cluster: 'Part 1 — Header', element: 'Completeness claim', status: 'unmet', note: 'not emitted (R3 deferred) — "silence becomes a producer assertion"' },
      { n: 4, cluster: 'Part 1 — Header', element: 'Authorship / review metadata', status: 'partial', note: 'tool-generated metadata present; no accountable-author/reviewer fields' },
      { n: 5, cluster: 'Part 1 — Header', element: 'Validity period', status: 'unmet', note: '' },
      { n: 6, cluster: 'Part 2 — Component list', element: 'Component identity + type', status: 'met', note: 'typed components (machine-learning-model, library, platform)' },
      { n: 7, cluster: 'Part 2 — Component list', element: 'Models category', status: 'met', note: 'incl. adapters/LoRA via lineage; base-model digests unmet (R1)' },
      { n: 8, cluster: 'Part 2 — Component list', element: 'Datasets category', status: 'partial', note: 'names extracted, not componentized (R5)' },
      { n: 9, cluster: 'Part 2 — Component list', element: 'Agents & Tools category', status: 'partial', note: 'agent frameworks as findings; MCP servers as components; no agent entities' },
      { n: 10, cluster: 'Part 2 — Component list', element: 'Prompts & Guardrails category', status: 'partial', note: 'guardrails detected; prompt templates intentionally not components' },
      { n: 11, cluster: 'Part 2 — Component list', element: 'Runtime / dependencies', status: 'met', note: 'full dependency detection' },
      { n: 12, cluster: 'Part 2 — Component list', element: 'Build provenance', status: 'partial', note: 'digest-pinned base images detected; no build args/inputs' },
      { n: 13, cluster: 'Part 2 — Component list', element: 'System membership (integral/external)', status: 'partial', note: 'implicit (in-repo vs dependency); no explicit field' },
      { n: 14, cluster: 'Part 2 — Component list', element: 'Node behavior (active/passive)', status: 'partial', note: 'implicit per type; no explicit annotation' },
      { n: 15, cluster: 'Part 3 — Data flows', element: 'Directed data flows', status: 'partial', note: 'CycloneDX dependencies graph approximates' },
      { n: 16, cluster: 'Part 3 — Data flows', element: 'Flow kind / payload / movement properties', status: 'unmet', note: 'no data/control/event typing, no encryption/protocol metadata' },
      { n: 17, cluster: 'Part 4 — Evidence & provenance', element: 'Provenance references', status: 'met', note: 'base-model lineage (fine-tuned-from, relatedModels)' },
      { n: 18, cluster: 'Part 4 — Evidence & provenance', element: 'Cryptographic hashes', status: 'unmet', note: 'R1 deferred' },
      { n: 19, cluster: 'Part 4 — Evidence & provenance', element: 'Signatures / attestations', status: 'unmet', note: 'R4 deferred; self-signing structural' },
      { n: 20, cluster: 'Part 4 — Evidence & provenance', element: 'Evaluation results', status: 'met', note: 'performanceMetrics + threshold' },
      { n: 21, cluster: 'Part 4 — Evidence & provenance', element: 'External documents (model card, license)', status: 'met', note: 'modelCard object + HF references + license when verified' },
      { n: 22, cluster: 'Category-specific', element: 'MCP server identity/transport/pinning/scopes', status: 'partial', note: 'identity, command/args/env parsed; version pinning & granted scopes not captured' },
      { n: 23, cluster: 'Category-specific', element: 'A2A Agent Cards as AIBOM input', status: 'met', note: '.well-known/agent.json parsed (name/url/skills/capabilities)' },
      { n: 24, cluster: 'Category-specific', element: 'Skill / policy-pack tracking', status: 'partial', note: 'SKILL.md file detection only' }
    ]
  }
];

/**
 * Score a scorecard document. met = 1.0, partial = 0.5, unmet = 0.
 * strict = full credit only (met rows). Percentages are rounded to 1 decimal.
 * @param {Object} docEntry entry from AIBOM_SCORECARD
 * @returns {{weightedPct: number, strictPct: number, met: number, partial: number,
 *            unmet: number, structural: number, score: number, total: number}}
 */
function computeScorecardStats(docEntry) {
  const total = docEntry.rows.length;
  let score = 0;
  let met = 0;
  let partial = 0;
  let unmet = 0;
  let structural = 0;
  for (const row of docEntry.rows) {
    if (row.status === 'met') { score += 1; met += 1; }
    else if (row.status === 'partial') { score += 0.5; partial += 1; }
    else { unmet += 1; }
    if (row.structural) structural += 1;
  }
  return {
    weightedPct: Math.round((score / total) * 1000) / 10,
    strictPct: Math.round((met / total) * 1000) / 10,
    met,
    partial,
    unmet,
    structural,
    score,
    total
  };
}

/**
 * Run all dynamic document validations against a generatedBOMs map.
 * @param {Object} generatedBOMs { 'cyclonedx-json', 'cyclonedx-xml', 'spdx', 'extended-aibom' }
 * @returns {Array} reports [{standard, format, checks}]
 */
function buildComplianceReports(generatedBOMs) {
  const bomText = generatedBOMs && generatedBOMs['cyclonedx-json'];
  const spdxText = generatedBOMs && generatedBOMs['spdx'];
  return [
    validateCycloneDXBom(bomText),
    checkNtiaMinimumElements(bomText),
    validateSpdxBom(spdxText)
  ];
}

// Export for Node-based tooling/tests without breaking browser usage.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    parseBomJson,
    validateCycloneDXBom,
    checkNtiaMinimumElements,
    validateSpdxBom,
    AIBOM_SCORECARD,
    computeScorecardStats,
    buildComplianceReports
  };
}
