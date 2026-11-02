// Offline harness for ma-resolve-profile.js (mocked Apigee context).
// Run: node guardrail-proxy/tests/ma_profile_harness.js
const fs = require('fs');
const path = require('path');
const src = fs.readFileSync(path.join(__dirname, '../apiproxy/resources/jsc/ma-resolve-profile.js'), 'utf8');

function run(headers) {
  const store = {};
  for (const [k, v] of Object.entries(headers)) store['request.header.' + k] = v;
  const context = { getVariable: (k) => store[k], setVariable: (k, v) => { store[k] = v; } };
  new Function('context', src)(context);
  return store;
}

let fails = 0;
function expect(name, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) fails++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  got ${JSON.stringify(got)} want ${JSON.stringify(want)}`}`);
}
const t = (s) => [s['ma.profile'], s['ma.template_in'], s['ma.template_out']];

expect('no header -> balanced', t(run({})), ['balanced', 'guardrail-proxy-in-balanced', 'guardrail-proxy-out-balanced']);
expect('strict', t(run({ 'x-ma-profile': 'strict' })), ['strict', 'guardrail-proxy-in-strict', 'guardrail-proxy-out-strict']);
expect('permissive', t(run({ 'x-ma-profile': 'permissive' })), ['permissive', 'guardrail-proxy-in-permissive', 'guardrail-proxy-out-permissive']);
expect('case / whitespace tolerant', t(run({ 'x-ma-profile': '  STRICT ' }))[0], 'strict');
expect('per-direction override', t(run({ 'x-ma-profile': 'strict', 'x-ma-profile-out': 'permissive' })),
  ['strict/permissive', 'guardrail-proxy-in-strict', 'guardrail-proxy-out-permissive']);
expect('override only in', t(run({ 'x-ma-profile-in': 'permissive' })),
  ['permissive/balanced', 'guardrail-proxy-in-permissive', 'guardrail-proxy-out-balanced']);
// Security: callers can never inject a template ID or path.
for (const evil of ['ma-ai-gw-inbound', '../../templates/x', 'strict/../x', 'projects/p/locations/us/templates/x',
  'balanced}', '{ma.template_out}', 'strict,permissive', '']) {
  expect(`rejects ${JSON.stringify(evil)} -> balanced`, t(run({ 'x-ma-profile': evil, 'x-ma-profile-in': evil, 'x-ma-profile-out': evil })),
    ['balanced', 'guardrail-proxy-in-balanced', 'guardrail-proxy-out-balanced']);
}
console.log(fails ? `\n${fails} FAILED` : '\nAll checks passed');
process.exit(fails ? 1 : 0);
