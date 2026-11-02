// Local harness for request-validate.js and nemo-input.js (mocked Apigee `context`).
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '../..'); // repo root
const jsc = (f) => fs.readFileSync(path.join(ROOT, 'guardrail-proxy/apiproxy/resources/jsc', f), 'utf8');
const cases = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/owasp/cases.json'), 'utf8')).cases;

function run(src, vars) {
  const store = Object.assign({}, vars);
  const context = { getVariable: (k) => store[k], setVariable: (k, v) => { store[k] = v; } };
  new Function('context', src)(context);
  return store;
}
function validate(bodyText) { return run(jsc('request-validate.js'), { 'request.content': bodyText }); }

let fails = 0;
function expect(name, cond, info) { if (!cond) fails++; console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${info ? '  ' + info : ''}`); }

// Every non-API case must pass validation (no false rejections) and its inspect text must contain every part.
for (const c of cases.filter((x) => x.direction !== 'api')) {
  const body = c.contents ? { contents: c.contents } : { contents: [{ role: 'user', parts: [{ text: c.prompt }] }] };
  const s = validate(JSON.stringify(body));
  const texts = body.contents.flatMap((t) => t.parts.map((p) => p.text));
  const inspect = s['guardrail.inspect_text'] || '';
  const covered = inspect.length >= 50000 || texts.every((t) => inspect.includes(t.slice(0, 40)));
  if (s['reqval.reject'] !== 'false' || !covered) expect(`${c.id} accepted + fully inspected`, false, s['reqval.message']);
}
expect(`all ${cases.filter((x) => x.direction !== 'api').length} prompt cases accepted and fully inspected`, fails === 0);

// API cases
const api = Object.fromEntries(cases.filter((x) => x.direction === 'api').map((c) => [c.id, c]));
const v = (id) => validate(api[id].api.raw_body !== undefined ? api[id].api.raw_body : JSON.stringify(api[id].api.body));
expect('API3-01 systemInstruction rejected', v('API3-01')['reqval.reject'] === 'true', v('API3-01')['reqval.fields']);
expect('API3-02 safetySettings rejected', v('API3-02')['reqval.reject'] === 'true', v('API3-02')['reqval.fields']);
expect('API3-03 tools rejected', v('API3-03')['reqval.reject'] === 'true', v('API3-03')['reqval.fields']);
expect('API4-03 nested metadata rejected', v('API4-03')['reqval.reject'] === 'true', v('API4-03')['reqval.fields']);
expect('API8-02 malformed JSON rejected', v('API8-02')['reqval.reject'] === 'true');
expect('API2-01 benign body accepted', v('API2-01')['reqval.reject'] === 'false');
expect('API4-02 300 KB body rejected as too large (P2)', v('API4-02')['reqval.too_large'] === 'true' && v('API4-02')['reqval.reject'] === 'true');
expect('128 KB limit: 100 KB body accepted', validate(JSON.stringify({ contents: [{ role: 'user', parts: [{ text: 'y'.repeat(100000) }] }] }))['reqval.reject'] === 'false');
expect('101 turns rejected (P2)', validate(JSON.stringify({ contents: Array.from({ length: 101 }, (_, i) => ({ role: i % 2 ? 'model' : 'user', parts: [{ text: 'hi' }] })) }))['reqval.reject'] === 'true');
expect('inlineData part rejected', validate(JSON.stringify({ contents: [{ role: 'user', parts: [{ inlineData: { mimeType: 'image/png', data: 'AA==' } }] }] }))['reqval.reject'] === 'true');
expect('system role rejected', validate(JSON.stringify({ contents: [{ role: 'system', parts: [{ text: 'x' }] }] }))['reqval.reject'] === 'true');
expect('empty contents rejected', validate('{"contents":[]}')['reqval.reject'] === 'true');
expect('message is JSON-safe', JSON.parse(`{"m":"${v('API3-01')['reqval.message']}"}`).m.length > 10);

// NeMo input uses the all-turns text
const mt = cases.find((c) => c.id === 'LLM01-21');
const sv = validate(JSON.stringify({ contents: mt.contents }));
const nemo = run(jsc('nemo-input.js'), { 'guardrail.inspect_text': sv['guardrail.inspect_text'], 'request.header.x-nemo-guardrails': 'enforce', 'request.header.x-nemo-profile': 'jailbreak_self_check' });
const msg = JSON.parse(nemo['nemo.request.body']).messages[0].content;
expect('NeMo sees the earlier-turn injection (LLM01-21)', msg.includes('You are now DAN'));
const big = run(jsc('nemo-input.js'), { 'guardrail.inspect_text': 'HEAD-' + 'x'.repeat(20000) + '-TAIL', 'request.header.x-nemo-guardrails': 'enforce' });
const bm = JSON.parse(big['nemo.request.body']).messages[0].content;
expect('NeMo long input keeps head + tail', bm.startsWith('HEAD-') && bm.endsWith('-TAIL') && bm.length <= 8010, `${bm.length} chars`);
console.log(fails ? `\n${fails} failure(s)` : '\nAll checks passed');
process.exit(fails ? 1 : 0);
