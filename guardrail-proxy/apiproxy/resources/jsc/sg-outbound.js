/*
 * JS-SG-Outbound-Scan (runs in the TargetEndpoint EventFlow, once per SSE event)
 *
 * Outbound mode (sg.out_mode, from header x-static-outbound, set by the StaticGuardrails SharedFlow):
 *   enforce - scan the cumulative model output (response_partial); BLOCK findings end the stream
 *   monitor - same scan, findings are reported/logged only
 *   redact  - secrets + PII are masked in-flight in the CURRENT event ("[REDACTED:SG-SEC-002]");
 *             other BLOCK findings (XSS, template/command injection, harsh language, deny-list)
 *             still end the stream. Fallback: if a secret appears in the cumulative text that was
 *             never masked (split across two events), the stream is blocked instead of leaking it.
 *   disable - step is skipped by its flow condition
 *
 * EventFlow cannot run RegularExpressionProtection / FlowCallout, so the outbound path is JS-only.
 * PII is FLAG-only and escalation is disabled (minFlagCats = 0).
 *
 * Publishes: sg.out_verdict (pass|flag|redact|block), sg.out_action (allow|block), sg.out_rule_id,
 *            sg.out_category, sg.out_message, sg.out_rules, sg.out_flags,
 *            sg.out_redactions (total count), sg.out_redacted_rules (csv), sg.out_redact_counts (JSON)
 */
var REDACT_CATS = { secret_leak: 1, pii: 1 };

function globalRe(re) {
  return new RegExp(re.source, 'g' + (re.ignoreCase ? 'i' : '') + (re.multiline ? 'm' : ''));
}

function countMatches(re, text) {
  var g = globalRe(re), n = 0, m;
  while ((m = g.exec(text)) !== null) {
    n++;
    if (m[0].length === 0) { g.lastIndex++; }
  }
  return n;
}

// Redacts secrets + PII catalog rules (those with an outbound severity) and validated PII in one string.
function redactText(text, counts) {
  var i, r;
  for (i = 0; i < SG_RULES.length; i++) {
    r = SG_RULES[i];
    if (!REDACT_CATS[r.cat] || !r.sevOut) { continue; }
    text = text.replace(globalRe(r.re), function () {
      counts[r.id] = (counts[r.id] || 0) + 1;
      return '[REDACTED:' + r.id + ']';
    });
  }
  text = text.replace(/\b(?:\d[ -]?){12,18}\d\b/g, function (m) {
    var digits = m.replace(/[ -]/g, '');
    if (digits.length >= 13 && digits.length <= 19 && SG.luhnOk(digits)) {
      counts['SG-PII-001'] = (counts['SG-PII-001'] || 0) + 1;
      return '[REDACTED:SG-PII-001]';
    }
    return m;
  });
  text = text.replace(/\b([STFGMstfgm])(\d{7})([A-Za-z])\b/g, function (m, p, d, c) {
    if (SG.nricOk(p, d, c)) {
      counts['SG-PII-002'] = (counts['SG-PII-002'] || 0) + 1;
      return '[REDACTED:SG-PII-002]';
    }
    return m;
  });
  text = text.replace(/[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}/g, function () {
    counts['SG-PII-004'] = (counts['SG-PII-004'] || 0) + 1;
    return '[REDACTED:SG-PII-004]';
  });
  return text;
}

// Redact mode rewrites each SSE event's text through a hold-back buffer: the last HOLD_BACK chars
// are withheld and prepended to the next event, so a secret split across events (Gemini streams
// very small chunks, e.g. "AKIA" + "IOSFODNN7EXAMPLE") is always complete before it is masked.
// The event carrying finishReason flushes the buffer. HOLD_BACK >= longest secret signature.
var HOLD_BACK = 64;

function redactCurrentEvent(counts) {
  var content = context.getVariable('response.event.current.content') || '';
  var idx = content.indexOf('data: ');
  if (idx === -1) { return false; }
  var jsonPart = content.substring(idx + 6);
  var trimmed = jsonPart.replace(/\s+$/, '');
  var trail = jsonPart.substring(trimmed.length);
  var parsed;
  try { parsed = JSON.parse(trimmed); } catch (e) { return false; }
  var cand = parsed.candidates && parsed.candidates[0];
  if (!cand) { return false; }
  var parts = (cand.content && cand.content.parts) || [];
  var current = '', p, firstText = -1;
  for (p = 0; p < parts.length; p++) {
    if (typeof parts[p].text === 'string') {
      current += parts[p].text;
      if (firstText === -1) { firstText = p; }
    }
  }
  var pending = redactText((context.getVariable('sg.out_carry') || '') + current, counts);
  var isLast = !!cand.finishReason;
  var cut = isLast ? pending.length : Math.max(0, pending.length - HOLD_BACK);
  context.setVariable('sg.out_carry', pending.substring(cut));
  var release = pending.substring(0, cut);

  if (firstText === -1) {
    if (!cand.content) { cand.content = { role: 'model', parts: [] }; }
    if (!cand.content.parts) { cand.content.parts = []; }
    cand.content.parts.push({ text: release });
  } else {
    for (p = 0; p < parts.length; p++) {
      if (typeof parts[p].text === 'string') { parts[p].text = (p === firstText) ? release : ''; }
    }
  }
  context.setVariable('response.event.current.content', content.substring(0, idx + 6) + JSON.stringify(parsed) + trail);
  return true;
}

if (context.getVariable('sg.out_action') !== 'block') {
  var outMode = context.getVariable('sg.out_mode') || 'enforce';
  var text = context.getVariable('response_partial') || '';
  if (text.length > 0 && outMode !== 'disable') {
    var lex = JSON.parse(context.getVariable('sg.lexicon') || '{"allow":[],"deny":[]}');
    var norm = SG.normalize(text).text;
    var folded = SG.fold(norm);

    var hits = [];
    hits = hits.concat(SG.scanRules({ raw: text, norm: norm }, 'out'));
    hits = hits.concat(SG.scanLexicon(norm, folded, lex, 'out'));
    hits = hits.concat(SG.scanPII(text));
    hits = SG.dedupe(hits);

    var counts = JSON.parse(context.getVariable('sg.out_redact_counts') || '{}');
    var leaked = null;
    if (outMode === 'redact') {
      redactCurrentEvent(counts);
      // Secrets/PII are handled by masking, not blocking...
      var kept = [];
      for (var h = 0; h < hits.length; h++) {
        if (!REDACT_CATS[hits[h].cat]) { kept.push(hits[h]); }
      }
      hits = kept;
      // ...unless a secret in the cumulative text was never masked (split across events).
      for (var s = 0; s < SG_RULES.length && !leaked; s++) {
        var sr = SG_RULES[s];
        if (sr.cat === 'secret_leak' && sr.sevOut === 'BLOCK' && countMatches(sr.re, text) > (counts[sr.id] || 0)) {
          leaked = { id: sr.id, cat: 'secret_leak', sev: 'BLOCK' };
        }
      }
      if (leaked) { hits.unshift(leaked); }
    }

    var d = SG.decide(hits, 0);
    var ids = [], redactedIds = [], total = 0;
    for (var i = 0; i < hits.length; i++) { ids.push(hits[i].id); }
    for (var k in counts) {
      if (counts.hasOwnProperty(k)) { redactedIds.push(k); total += counts[k]; }
    }

    var verdict = d.verdict;
    if (verdict !== 'block' && total > 0) { verdict = 'redact'; }
    var blocking = d.verdict === 'block' && (outMode === 'enforce' || outMode === 'redact');

    context.setVariable('sg.out_redact_counts', JSON.stringify(counts));
    context.setVariable('sg.out_redactions', String(total));
    context.setVariable('sg.out_redacted_rules', redactedIds.join(','));
    context.setVariable('sg.out_verdict', verdict);
    context.setVariable('sg.out_action', blocking ? 'block' : 'allow');
    context.setVariable('sg.out_rules', ids.join(','));
    context.setVariable('sg.out_flags', d.flag.join(','));
    if (d.primary) {
      context.setVariable('sg.out_rule_id', d.primary.id);
      context.setVariable('sg.out_category', d.primary.cat);
      context.setVariable('sg.out_message', 'Model response withheld by static guardrail policy (' + d.primary.cat + ').');
    }
  }
}
