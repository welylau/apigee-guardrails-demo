/*
 * StaticGuardrails precision report + CI gate.
 * Runs tests/benign_corpus.json (normal traffic) and the attack sets (attacks_en + the Traditional
 * Chinese corpus attacks) through the inbound SharedFlow JS under both profiles and prints:
 *   - benign BLOCK rate (false positives) and FLAG rate (deferred to Model Armor) per profile
 *   - attack detection (block / flag) per profile
 *   - per-rule false-positive blocks and flags on benign traffic
 * Gate (balanced profile): benign block rate <= 0.5%, no rule with > 2 benign blocks,
 * and every clear-cut attack in attacks_en still BLOCKED.
 *
 * Usage: node StaticGuardrails/tests/precision_report.js [--verbose]
 */
'use strict';
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.join(__dirname, '..');
var JSC = path.join(ROOT, 'sharedflowbundle', 'resources', 'jsc');
var src = function (f) { return fs.readFileSync(path.join(JSC, f), 'utf8'); };
var LIB = src('sg-rules.js') + '\n' + src('sg-common.js') + '\n';
var VERBOSE = process.argv.indexOf('--verbose') !== -1;

var PROPS = {};
fs.readFileSync(path.join(ROOT, 'env', 'sg.properties'), 'ascii').split(/\r?\n/).forEach(function (l) {
  if (!l || l.charAt(0) === '#') { return; }
  var i = l.indexOf('=');
  if (i < 0) { return; }
  PROPS[l.substring(0, i)] = l.substring(i + 1).replace(/\\u([0-9a-fA-F]{4})/g, function (_, h) {
    return String.fromCharCode(parseInt(h, 16));
  });
});

// Same pipeline as local_harness.js, including the simulated Java RegularExpressionProtection.
function run(prompt, profile) {
  var vars = {};
  Object.keys(PROPS).forEach(function (k) { vars['propertyset.sg.' + k] = PROPS[k]; });
  vars['request.content'] = JSON.stringify({ contents: [{ role: 'user', parts: [{ text: prompt }] }] });
  vars['request.header.x-static-profile'] = profile;
  var ctx = {
    getVariable: function (k) { return vars.hasOwnProperty(k) ? vars[k] : null; },
    setVariable: function (k, v) { vars[k] = v; }
  };
  var sb = { context: ctx, JSON: JSON };
  vm.createContext(sb);
  vm.runInContext(LIB + src('sg-extract-normalize.js'), sb);
  vm.runInContext(LIB + [
    'for (var pol in SG_RE_POLICIES) {',
    '  for (var i = 0; i < SG_RULES.length; i++) {',
    '    var r = SG_RULES[i];',
    '    if (r.cat !== SG_RE_POLICIES[pol] || !r.rePol) continue;',
    '    var t = context.getVariable(r.src === "raw" ? "sg.prompt_raw" : "sg.prompt_norm") || "";',
    '    if (r.re.test(t)) { context.setVariable("regularexpressionprotection." + pol + ".failed", true); break; }',
    '  }',
    '}'].join('\n'), sb);
  vm.runInContext(LIB + src('sg-lexicon-validators.js'), sb);
  vm.runInContext(LIB + src('sg-decide.js'), sb);
  return vars;
}

var bench = JSON.parse(fs.readFileSync(path.join(__dirname, 'benign_corpus.json'), 'utf8'));
var zh = JSON.parse(fs.readFileSync(path.join(__dirname, 'zh_tw_corpus.json'), 'utf8'));
var benign = [];
Object.keys(bench.benign).forEach(function (g) { bench.benign[g].forEach(function (t) { benign.push({ g: g, t: t }); }); });
zh.benign.forEach(function (c) { benign.push({ g: 'zh_tw', t: c.text }); });
var attacksEn = bench.attacks_en;
var attacksZh = zh.attacks.map(function (c) { return c.repeat ? new Array(c.repeat + 1).join(c.text) : c.text; });

function pct(a, b) { return (100 * a / b).toFixed(1) + '%'; }

var summary = {};
['balanced', 'strict'].forEach(function (profile) {
  var bBlock = 0, bFlag = 0, perRuleBlock = {}, perRuleFlag = {}, fpList = [];
  benign.forEach(function (c) {
    var v = run(c.t, profile);
    if (v['sg.verdict'] === 'block') {
      bBlock++;
      perRuleBlock[v['sg.rule_id']] = (perRuleBlock[v['sg.rule_id']] || 0) + 1;
      fpList.push('[' + c.g + '] ' + v['sg.rule_id'] + '  ' + c.t.replace(/\n/g, ' ').substring(0, 70));
    } else if (v['sg.verdict'] === 'flag') {
      bFlag++;
      String(v['sg.flags']).split(',').forEach(function (id) { if (id) { perRuleFlag[id] = (perRuleFlag[id] || 0) + 1; } });
    }
  });
  var enBlock = 0, enMiss = [];
  attacksEn.forEach(function (t) {
    var v = run(t, profile);
    if (v['sg.verdict'] === 'block') { enBlock++; } else { enMiss.push(v['sg.verdict'] + '  ' + t.substring(0, 60)); }
  });
  var zhBlock = 0, zhFlag = 0;
  attacksZh.forEach(function (t) {
    var v = run(t, profile);
    if (v['sg.verdict'] === 'block') { zhBlock++; } else if (v['sg.verdict'] === 'flag') { zhFlag++; }
  });
  summary[profile] = { bBlock: bBlock, perRuleBlock: perRuleBlock };

  console.log('\n=== profile: ' + profile + ' ===');
  console.log('Benign prompts           : ' + benign.length);
  console.log('  blocked (false pos.)   : ' + bBlock + ' (' + pct(bBlock, benign.length) + ')');
  console.log('  flagged -> Model Armor : ' + bFlag + ' (' + pct(bFlag, benign.length) + ')');
  console.log('Clear-cut attacks (EN+ID): blocked ' + enBlock + '/' + attacksEn.length);
  console.log('TC/HK attacks            : blocked ' + zhBlock + ', flagged ' + zhFlag + ' of ' + attacksZh.length);
  if (fpList.length) { console.log('  False positives:\n    ' + fpList.join('\n    ')); }
  if (enMiss.length) { console.log('  Clear-cut attacks not blocked:\n    ' + enMiss.join('\n    ')); }
  if (VERBOSE) {
    console.log('  Benign flags by rule: ' + JSON.stringify(perRuleFlag));
  }
  summary[profile].enMiss = enMiss.length;
});

// ---- CI gate (balanced) ----
var b = summary.balanced, failures = [];
if (b.bBlock / benign.length > 0.005) { failures.push('benign block rate ' + pct(b.bBlock, benign.length) + ' > 0.5%'); }
Object.keys(b.perRuleBlock).forEach(function (id) {
  if (b.perRuleBlock[id] > 2) { failures.push(id + ' blocked ' + b.perRuleBlock[id] + ' benign prompts (> 2)'); }
});
if (b.enMiss) { failures.push(b.enMiss + ' clear-cut attack(s) not blocked'); }
console.log('\n=== GATE (balanced) ' + (failures.length ? 'FAILED' : 'PASSED') + ' ===');
failures.forEach(function (f) { console.log('  - ' + f); });
process.exit(failures.length ? 1 : 0);
