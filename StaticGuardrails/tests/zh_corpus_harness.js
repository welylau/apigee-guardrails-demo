/*
 * Traditional Chinese (TW + HK/Cantonese) corpus harness for StaticGuardrails.
 * Runs tests/zh_tw_corpus.json through the inbound SharedFlow JS (same path as local_harness.js)
 * and reports detection rate on attacks and false-positive rate on benign prompts.
 *
 * Usage: node StaticGuardrails/tests/zh_corpus_harness.js [--quiet]
 * Exit code 1 if any case does not match its expected verdict.
 */
'use strict';
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.join(__dirname, '..');
var JSC = path.join(ROOT, 'sharedflowbundle', 'resources', 'jsc');
var src = function (f) { return fs.readFileSync(path.join(JSC, f), 'utf8'); };
var LIB = src('sg-rules.js') + '\n' + src('sg-common.js') + '\n';
var QUIET = process.argv.indexOf('--quiet') !== -1;

var PROPS = {};
fs.readFileSync(path.join(ROOT, 'env', 'sg.properties'), 'ascii').split(/\r?\n/).forEach(function (l) {
  if (!l || l.charAt(0) === '#') { return; }
  var i = l.indexOf('=');
  if (i < 0) { return; }
  PROPS[l.substring(0, i)] = l.substring(i + 1).replace(/\\u([0-9a-fA-F]{4})/g, function (_, h) {
    return String.fromCharCode(parseInt(h, 16));
  });
});

function run(prompt) {
  var vars = {};
  Object.keys(PROPS).forEach(function (k) { vars['propertyset.sg.' + k] = PROPS[k]; });
  vars['request.content'] = JSON.stringify({ contents: [{ role: 'user', parts: [{ text: prompt }] }] });
  var ctx = {
    getVariable: function (k) { return vars.hasOwnProperty(k) ? vars[k] : null; },
    setVariable: function (k, v) { vars[k] = v; }
  };
  var sb = { context: ctx, JSON: JSON };
  vm.createContext(sb);
  vm.runInContext(LIB + src('sg-extract-normalize.js'), sb);
  vm.runInContext(LIB + src('sg-lexicon-validators.js'), sb);
  vm.runInContext(LIB + src('sg-decide.js'), sb);
  return vars;
}

function text(c) { return c.repeat ? new Array(c.repeat + 1).join(c.text) : c.text; }

var corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'zh_tw_corpus.json'), 'utf8'));
var mismatches = 0;

function verdictOf(v) { return v['sg.verdict'] === 'block' ? 'block' : v['sg.verdict'] === 'flag' ? 'flag' : 'allow'; }

// Attacks: detected = block, or flag when the case is FLAG-by-design.
var det = 0, byCat = {};
corpus.attacks.forEach(function (c) {
  var v = run(text(c)), got = verdictOf(v), ok = got === c.expect;
  var detected = got === 'block' || (c.expect === 'flag' && got === 'flag');
  if (detected) { det++; }
  byCat[c.cat] = byCat[c.cat] || [0, 0];
  byCat[c.cat][0] += detected ? 1 : 0;
  byCat[c.cat][1]++;
  if (!ok) { mismatches++; }
  if (!QUIET || !ok) {
    console.log((ok ? 'PASS ' : 'FAIL ') + ('[' + c.cat + ']').padEnd(18) + ' expect=' + c.expect.padEnd(5) +
      ' got=' + got.padEnd(5) + ' rule=' + (v['sg.rule_id'] || '-').padEnd(16) + ' ' + c.text.substring(0, 40));
  }
});

// Benign: any block = false positive; flags are reported separately.
var fp = 0, fl = 0;
corpus.benign.forEach(function (c) {
  var v = run(text(c)), got = verdictOf(v), ok = got === c.expect;
  if (got === 'block') { fp++; }
  if (got === 'flag') { fl++; }
  if (!ok) { mismatches++; }
  if (!QUIET || !ok) {
    console.log((ok ? 'PASS ' : 'FAIL ') + '[benign]'.padEnd(18) + ' expect=' + c.expect.padEnd(5) +
      ' got=' + got.padEnd(5) + ' rule=' + (v['sg.rule_id'] || v['sg.rules'] || '-').padEnd(16) + ' ' + c.text.substring(0, 40));
  }
});

var nA = corpus.attacks.length, nB = corpus.benign.length;
console.log('\n=== Traditional Chinese corpus ===');
console.log('Attacks detected : ' + det + '/' + nA + ' (' + Math.round(100 * det / nA) + '%)');
Object.keys(byCat).sort().forEach(function (k) {
  console.log('   ' + k.padEnd(16) + byCat[k][0] + '/' + byCat[k][1]);
});
console.log('Benign blocked   : ' + fp + '/' + nB + ' (false-positive rate ' + Math.round(100 * fp / nB) + '%), flagged: ' + fl);
console.log('Expectation mismatches: ' + mismatches);
process.exit(mismatches ? 1 : 0);
