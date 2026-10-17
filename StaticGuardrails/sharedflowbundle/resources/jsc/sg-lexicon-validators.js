/*
 * JS-SG-Lexicon-Validators
 * Runs the non-regex-policy checks on the normalized prompt:
 *   - tiered multilingual harsh-language lexicon + business deny-list (property set)
 *   - checksum-validated PII (Luhn, SG NRIC/FIN, Thai national ID) + email
 *   - structural limits (size, turns, zero-width/control chars, JSONThreatProtection result)
 *   - JS-only regex rules (FLAG rules, harsh-language T1 regex, structural regex)
 * Publishes sg.js_hits (JSON array of {id, cat, sev}).
 */
var lex = JSON.parse(context.getVariable('sg.lexicon') || '{"allow":[],"deny":[]}');
var m = JSON.parse(context.getVariable('sg.metrics') || '{}');
var jtpFailed = String(context.getVariable('jsonattack.JTP-SG-Structure.failed')) === 'true';
m.jsonThreat = jtpFailed;

var raw = context.getVariable('sg.prompt_raw') || '';
var norm = context.getVariable('sg.prompt_norm') || '';
var folded = context.getVariable('sg.prompt_folded') || '';
var profile = context.getVariable('sg.profile') || 'balanced';
var overrides = JSON.parse(context.getVariable('sg.overrides') || '{}');

var hits = [];
hits = hits.concat(SG.scanStructural(m));
hits = hits.concat(SG.scanLexicon(norm, folded, lex, 'in', profile));
hits = hits.concat(SG.scanPII(raw));
// JS evaluates the full catalog: FLAG rules, T1/structural regex rules, plus BLOCK rules for
// rule-ID attribution of RegularExpressionProtection matches (see JS-SG-Decide).
var ruleHits = SG.scanRules({ raw: raw, norm: norm }, 'in', null, profile);
// Balanced: context dampeners lower BLOCK -> FLAG (quoted mention, attack discussion, code review,
// ZH negation). Never to ALLOW: the request still goes to Model Armor.
if (profile !== 'strict') { SG.dampen(ruleHits, { raw: raw, norm: norm }); }
hits = hits.concat(ruleHits);
// Explicit operator overrides win over profile and dampeners.
SG.applyOverrides(hits, overrides['in']);

context.setVariable('sg.js_hits', JSON.stringify(SG.dedupe(hits)));
