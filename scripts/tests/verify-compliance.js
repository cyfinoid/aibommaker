// Node verification harness — exercises the pure functions added for the
// standards-compliance work (formatModelCardField, validators, scorecard
// math) exactly as the browser would. Committed so the verification is
// reproducible: `node scripts/tests/verify-compliance.js`
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');

// Load utils.js globals (formatModelCardField etc.) into a sandbox context.
const utilsSrc = fs.readFileSync(path.join(ROOT, 'js/utils.js'), 'utf8');
const ctx = { console };
vm.createContext(ctx);
vm.runInContext(utilsSrc, ctx, { filename: 'utils.js' });

// Load compliance.js as a CommonJS module (it exports its API).
const compliance = require(path.join(ROOT, 'js/compliance.js'));

let failures = 0;
function check(cond, msg) {
  if (cond) { console.log(`  ok  ${msg}`); }
  else { failures++; console.log(`FAIL  ${msg}`); }
}

// ------------------------------------------------------------------
console.log('== formatModelCardField ==');
// Real card from the user's report: models/embedding-001
const card = JSON.parse(fs.readFileSync(path.join(ROOT, 'modelcards/google/models-embedding-001.json'), 'utf8'));
const intended = ctx.formatModelCardField(card.intendedUse, { primaryUses: '', primaryUseCases: '', outOfScope: 'Out of scope' });
console.log('  intendedUse ->', JSON.stringify(intended));
check(!intended.includes('[object Object]'), 'embedding-001 intendedUse has no [object Object]');
check(intended.startsWith('Semantic search and retrieval'), 'primaryUses rendered first');
check(intended.includes('Out of scope: Text generation'), 'outOfScope labeled');

const limits = ctx.formatModelCardField(card.limitations, { knownLimitations: '' });
console.log('  limitations ->', JSON.stringify(limits));
check(!limits.includes('[object Object]'), 'embedding-001 limitations has no [object Object]');
check(limits.startsWith('Superseded by text-embedding-004'), 'knownLimitations joined');

// Legacy shape: plain string field (old code path `note || value`)
check(ctx.formatModelCardField('Just text') === 'Just text', 'plain string passthrough');
check(ctx.formatModelCardField({ note: 'legacy note' }) === 'legacy note', 'legacy .note preferred');
check(ctx.formatModelCardField(null) === '', 'null -> empty');
check(ctx.formatModelCardField(undefined, {}) === '', 'undefined -> empty');
check(ctx.formatModelCardField({ unknownShape: { deep: 1 } }) === '', 'object with no readable strings -> empty');
check(ctx.formatModelCardField(['a', 'b']) === 'a; b', 'bare array joined');
check(ctx.formatModelCardField({ description: 'desc text' }, { description: '' }) === 'desc text', 'trainingData shape');

// ------------------------------------------------------------------
console.log('== scorecard math reproduces guidance headline ==');
const expected = { certin: [68.4, 52.6], g7: [44.0, 34.0], owasp: [50.0, 29.2] };
// Post-uplift (2026-11-21): invented model versions removed → CERT-In #2 and
// G7 #22 honestly unmet; out-of-scope extraction added → CERT-In #16 met.
// guidance §6 snapshot was 65.8/45.0/50.0 weighted.
for (const doc of compliance.AIBOM_SCORECARD) {
  const s = compliance.computeScorecardStats(doc);
  const [w, st] = expected[doc.id];
  console.log(`  ${doc.id}: weighted ${s.weightedPct}% strict ${s.strictPct}% (${s.met}✓/${s.partial}∆/${s.unmet}✗, ⛔${s.structural})`);
  check(s.weightedPct === w, `${doc.id} weighted ${s.weightedPct}% === ${w}%`);
  check(s.strictPct === st, `${doc.id} strict ${s.strictPct}% === ${st}%`);
  check(s.total === doc.rows.length, `${doc.id} row count ${s.total}`);
}

// ------------------------------------------------------------------
console.log('== CycloneDX validation ==');
// Mirrors the exact shape bom-generators.js emits.
const goodCdx = {
  bomFormat: 'CycloneDX', specVersion: '1.7', version: 1,
  serialNumber: 'urn:uuid:123e4567-e89b-12d3-a456-426614174000',
  metadata: {
    timestamp: '2026-11-21T00:00:00.000Z',
    tools: { components: [{ type: 'application', 'bom-ref': 'tool-aibom-generator', name: 'AI BOM Generator', version: '1.0.0' }] },
    component: { type: 'application', 'bom-ref': 'repo-owner-repo', group: 'owner', name: 'repo', version: 'main', purl: 'pkg:github/owner/repo' }
  },
  components: [
    { type: 'machine-learning-model', 'bom-ref': 'model-1', name: 'gpt-4o', version: 'latest', purl: 'pkg:openai/gpt-4o', supplier: { name: 'OpenAI' } },
    { type: 'library', 'bom-ref': 'lib-1', name: 'requests', version: '2.31.0', purl: 'pkg:pypi/requests@2.31.0' }
  ],
  dependencies: [
    { ref: 'repo-owner-repo', dependsOn: ['model-1', 'lib-1'] },
    { ref: 'model-1', dependsOn: [] }
  ]
};
const goodText = JSON.stringify(goodCdx, null, 2);
const r1 = compliance.validateCycloneDXBom(goodText);
for (const c of r1.checks) console.log(`  [${c.status}] ${c.id}: ${c.detail}`);
check(r1.checks.every(c => c.status !== 'fail'), 'good CycloneDX doc: no failed checks');

const n1 = compliance.checkNtiaMinimumElements(goodText);
for (const c of n1.checks) console.log(`  [${c.status}] ${c.id}: ${c.detail}`);
check(n1.checks.find(c => c.id === 'ntia-name').status === 'pass', 'NTIA name pass');
check(n1.checks.find(c => c.id === 'ntia-version').status === 'pass', 'NTIA version pass (latest noted)');
check(n1.checks.find(c => c.id === 'ntia-supplier').status === 'warn', 'NTIA supplier partial -> warn (lib-1 has none)');
check(n1.checks.find(c => c.id === 'ntia-author').status === 'warn', 'NTIA author warn (tool only)');

// Broken docs
const bad1 = compliance.validateCycloneDXBom('{ not json');
check(bad1.checks[0].status === 'fail', 'invalid JSON -> fail');
const bad2 = compliance.validateCycloneDXBom('// No findings selected');
check(bad2.checks[0].status === 'fail' && bad2.checks[0].detail.includes('No findings'), 'placeholder handled');

const dupCdx = JSON.parse(goodText);
dupCdx.serialNumber = 'not-a-uuid';
dupCdx.components[1]['bom-ref'] = 'model-1'; // duplicate ref
dupCdx.dependencies[0].dependsOn.push('ghost-ref'); // unresolved
dupCdx.metadata.timestamp = 'not-a-date';
const r2 = compliance.validateCycloneDXBom(JSON.stringify(dupCdx));
for (const c of r2.checks) console.log(`  [${c.status}] ${c.id}: ${c.detail}`);
check(r2.checks.find(c => c.id === 'serial').status === 'fail', 'bad serialNumber detected');
check(r2.checks.find(c => c.id === 'bom-ref').status === 'fail', 'duplicate bom-ref detected');
check(r2.checks.find(c => c.id === 'dependency-refs').status === 'fail', 'unresolved dependency ref detected');
check(r2.checks.find(c => c.id === 'timestamp').status === 'fail', 'bad timestamp detected');

// ------------------------------------------------------------------
console.log('== SPDX validation ==');
const goodSpdx = {
  '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
  '@id': 'https://example/spdx/SpdxDocument',
  type: 'SpdxDocument',
  spdxId: 'https://example/spdx/SpdxDocument',
  creationInfo: { type: 'CreationInfo', specVersion: '3.0.1', created: '2026-11-21T00:00:00.000Z', createdBy: ['Tool: AI BOM Generator-1.0.0'] },
  name: 'AI BOM for owner/repo',
  element: [
    { '@id': 'https://example/spdx/Repository', type: 'software_Package', spdxId: 'https://example/spdx/Repository', name: 'repo' },
    { '@id': 'https://example/spdx/Rel-0', type: 'Relationship', spdxId: 'https://example/spdx/Rel-0', relationshipType: 'dependsOn', from: 'https://example/spdx/Repository', to: ['https://example/spdx/Ai-1'] },
    { '@id': 'https://example/spdx/Ai-1', type: 'software_Package', spdxId: 'https://example/spdx/Ai-1', name: 'gpt-4o' }
  ],
  rootElement: ['https://example/spdx/Repository']
};
const s1 = compliance.validateSpdxBom(JSON.stringify(goodSpdx, null, 2));
for (const c of s1.checks) console.log(`  [${c.status}] ${c.id}: ${c.detail}`);
check(s1.checks.every(c => c.status !== 'fail'), 'good SPDX doc: no failed checks');

const badSpdx = JSON.parse(JSON.stringify(goodSpdx));
badSpdx.creationInfo.specVersion = '3.0.0';
badSpdx.rootElement = ['https://example/spdx/Missing'];
badSpdx.element[1].to = ['https://example/spdx/Ghost'];
badSpdx.element[2].spdxId = 'https://example/spdx/Repository'; // duplicate id
const s2 = compliance.validateSpdxBom(JSON.stringify(badSpdx));
for (const c of s2.checks) console.log(`  [${c.status}] ${c.id}: ${c.detail}`);
check(s2.checks.find(c => c.id === 'creation-spec').status === 'fail', 'wrong specVersion detected');
check(s2.checks.find(c => c.id === 'root-elements').status === 'fail', 'dangling rootElement detected');
check(s2.checks.find(c => c.id === 'relationships').status === 'fail', 'dangling relationship target detected');
check(s2.checks.find(c => c.id === 'element-ids').status === 'fail', 'duplicate element id detected');

// ------------------------------------------------------------------
console.log('== buildComplianceReports ==');
const reports = compliance.buildComplianceReports({ 'cyclonedx-json': goodText, 'spdx': JSON.stringify(goodSpdx) });
check(reports.length === 3, 'three reports built');
check(reports.map(r => r.standard).join('|') === 'CycloneDX 1.7|NTIA Minimum Elements (2021)|SPDX 3.0.1', 'report order/standards');
const empty = compliance.buildComplianceReports({});
check(empty.every(r => r.checks[0].status === 'fail'), 'empty BOM map -> fail checks');

console.log(failures === 0 ? '\nALL VERIFICATIONS PASSED' : `\n${failures} VERIFICATION(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
