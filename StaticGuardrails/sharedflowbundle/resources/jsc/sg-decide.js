/*
 * JS-SG-Decide
 * Combines RegularExpressionProtection results (authoritative, declarative BLOCK signatures)
 * with JS hits, attributes rule IDs, applies escalation and mode, and publishes:
 *   sg.verdict   block | flag | pass         (what the rules concluded)
 *   sg.action    block | allow               (what happens; monitor mode never blocks)
 *   sg.rule_id / sg.category / sg.severity / sg.message   (primary finding)
 *   sg.rules     all rule IDs hit (csv)      sg.flags  FLAG rule IDs (csv)
 *   sg.parity    ok | mismatch               (Java RE policy vs JS catalog agreement)
 *   sg.elapsed_ms
 */
var hits = JSON.parse(context.getVariable('sg.js_hits') || '[]');
var mode = context.getVariable('sg.mode') || 'enforce';
var profile = context.getVariable('sg.profile') || 'balanced';
var minFlagCats = parseInt(context.getVariable('sg.min_flag_categories'), 10);
if (isNaN(minFlagCats)) { minFlagCats = 2; }

var ABBR = { prompt_injection: 'PI', code_injection: 'INJ', secret_leak: 'SEC' };
var parity = 'ok';
var IN_RE_POLICY = {};
for (var ri = 0; ri < SG_RULES.length; ri++) { if (SG_RULES[ri].rePol) { IN_RE_POLICY[SG_RULES[ri].id] = true; } }

for (var policy in SG_RE_POLICIES) {
  if (!SG_RE_POLICIES.hasOwnProperty(policy)) { continue; }
  var cat = SG_RE_POLICIES[policy];
  var reFailed = String(context.getVariable('regularexpressionprotection.' + policy + '.failed')) === 'true';
  var jsBlock = false, jsSeen = false;
  for (var i = 0; i < hits.length; i++) {
    if (hits[i].cat !== cat) { continue; }
    if (hits[i].sev === 'BLOCK') { jsBlock = true; jsSeen = true; break; }
    if (IN_RE_POLICY[hits[i].id]) { jsSeen = true; }   // a Java-policy rule JS matched but downgraded
  }
  if (reFailed && !jsSeen) {
    // RE policy matched but JS saw nothing in this category (dialect difference) - still block.
    hits.push({ id: 'SG-' + ABBR[cat] + '-RE', cat: cat, sev: 'BLOCK' });
    parity = 'mismatch';
  } else if (!reFailed && jsBlock) {
    // JS matched a BLOCK rule that Java did not - defence in depth: keep the JS block.
    parity = 'mismatch';
  }
  // reFailed && jsSeen && !jsBlock: JS attributed the match and deliberately downgraded it
  // (balanced profile, context dampener or override) - the JS decision stands.
}

var d = SG.decide(hits, minFlagCats, profile);
if (mode === 'disable') {
  // SharedFlow ran only to prepare the outbound scanner; inbound findings are not reported.
  hits = [];
  d = { verdict: 'disabled', primary: null, block: [], flag: [], log: [] };
}
var action = (d.verdict === 'block' && mode === 'enforce') ? 'block' : 'allow';
var allIds = [], damped = [];
for (var k = 0; k < hits.length; k++) {
  if (hits[k].sev === 'OFF') { continue; }
  allIds.push(hits[k].id);
  if (hits[k].damp) { damped.push(hits[k].id + ':' + hits[k].damp); }
}

context.setVariable('sg.verdict', d.verdict);
context.setVariable('sg.action', action);
context.setVariable('sg.would_block', d.verdict === 'block' ? 'true' : 'false');
context.setVariable('sg.rules', allIds.join(','));
context.setVariable('sg.flags', d.flag.join(','));
context.setVariable('sg.dampened', damped.join(','));
context.setVariable('sg.parity', parity);
if (d.primary) {
  context.setVariable('sg.rule_id', d.primary.id);
  context.setVariable('sg.category', d.primary.cat);
  context.setVariable('sg.severity', d.primary.sev);
  context.setVariable('sg.message', SG.MESSAGES[d.primary.cat] || 'Request blocked by static guardrail policy.');
} else {
  context.setVariable('sg.rule_id', '');
  context.setVariable('sg.category', '');
  context.setVariable('sg.severity', '');
  context.setVariable('sg.message', '');
}
var t0 = parseInt(context.getVariable('sg.t_start'), 10);
context.setVariable('sg.elapsed_ms', String(isNaN(t0) ? -1 : (new Date().getTime() - t0)));
