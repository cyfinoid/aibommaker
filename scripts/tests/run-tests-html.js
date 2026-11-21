// Run tests.html's inline script in Node (vm) with a stubbed DOM + fetch shim.
// Reproducible: `node scripts/tests/run-tests-html.js`
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const html = fs.readFileSync(path.join(ROOT, 'tests.html'), 'utf8');

// Extract the inline test script (between the last <script> ... </script>).
const m = html.match(/<script>\n([\s\S]*?)\n<\/script>/);
if (!m) { console.error('no inline script found'); process.exit(1); }
const testSrc = m[1];

// Literal whitelist — loadScript() is only called with these names, so the
// path join cannot be steered by any external input.
const SCRIPT_WHITELIST = [
  'constants.js', 'utils.js', 'github-api.js', 'detectors.js',
  'bom-generators.js', 'extended-aibom-generator.js', 'compliance.js'
];
const loadScript = (f) => {
  if (!SCRIPT_WHITELIST.includes(f)) {
    throw new Error(`Unexpected script name: ${f}`);
  }
  return fs.readFileSync(`${ROOT}/js/${f}`, 'utf8');
};

const realFetch = (p) => {
  const clean = String(p).split('?')[0].replace(/^\.\//, '');
  const abs = path.join(ROOT, clean);
  if (!fs.existsSync(abs)) return Promise.resolve({ ok: false, status: 404, json: () => Promise.reject(new Error('404')) });
  const text = fs.readFileSync(abs, 'utf8');
  return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(JSON.parse(text)) });
};

const resultsDiv = { set innerHTML(v) { fs.writeFileSync(path.join(require('os').tmpdir(), 'aibom-tests-results.html'), v); } };
const summaryDiv = { set innerHTML(v) { console.log('SUMMARY:', v.replace(/<[^>]+>/g, '')); } };

const ctx = {
  console: { log: () => {}, warn: () => {}, error: console.error },
  fetch: realFetch,
  performance: { now: () => Date.now() },
  crypto: require('crypto').webcrypto,
  document: {
    getElementById: (id) => (id === 'results' ? resultsDiv : id === 'summary' ? summaryDiv : { innerHTML: '', classList: { add() {}, remove() {} } }),
    querySelectorAll: () => [],
    createElement: () => ({ classList: { add() {}, remove() {} }, dataset: {}, style: {} }),
    addEventListener: () => {}
  },
  window: {},
  localStorage: { getItem: () => null, setItem: () => {} },
  location: { href: 'file:///tests.html' },
};
vm.createContext(ctx);

// Load app scripts in the same order as tests.html, then the test script.
const scripts = ['constants.js', 'utils.js', 'github-api.js', 'detectors.js', 'bom-generators.js', 'extended-aibom-generator.js', 'compliance.js'];
for (const f of scripts) {
  try {
    vm.runInContext(loadScript(f), ctx, { filename: f });
  } catch (err) {
    console.error(`LOAD FAIL ${f}: ${err.message}`);
    process.exit(1);
  }
}

try {
  vm.runInContext(testSrc, ctx, { filename: 'tests-inline.js' });
} catch (err) {
  console.error('TEST RUNTIME FAIL:', err.message);
  const res = fs.readFileSync(path.join(require('os').tmpdir(), 'aibom-tests-results.html'), 'utf8');
  console.log(res.split('\n').filter(l => l.includes('FAIL')).slice(0, 10).join('\n'));
  process.exit(1);
}
