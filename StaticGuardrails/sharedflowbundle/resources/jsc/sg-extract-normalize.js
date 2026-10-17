/*
 * JS-SG-Extract-Normalize
 * Extracts all prompt text from a Vertex AI Gemini request body
 * (contents[].parts[].text + systemInstruction.parts[].text), normalizes it and
 * publishes flow variables consumed by the RegularExpressionProtection policies:
 *   sg.prompt_raw   - original text (case-sensitive; secrets rules)
 *   sg.prompt_norm  - lower-case, zero-width stripped, full-width/homoglyph folded
 *   sg.prompt_folded- sg.prompt_norm + leetspeak fold + repeated-letter collapse (lexicon)
 * Also stashes the parsed lexicon (sg.lexicon) so the outbound EventFlow scanner in the
 * proxy uses the exact same word lists without its own property set.
 */
function prop(key) {
  var v = context.getVariable('propertyset.sg.' + key);
  return v === null || v === undefined ? '' : String(v);
}
function intProp(key, dflt) {
  var n = parseInt(prop(key), 10);
  return isNaN(n) ? dflt : n;
}

var tStart = new Date().getTime();
context.setVariable('sg.enabled', 'true');
context.setVariable('sg.t_start', String(tStart));

// Inbound mode:  x-static-guardrails = enforce | monitor | disable   (default: property mode.default)
// Outbound mode: x-static-outbound   = enforce | redact | monitor | disable (default: mode.outbound_default)
// The SharedFlow runs if EITHER direction is active: the outbound EventFlow scanner reuses sg.lexicon.
var hdrMode = String(context.getVariable('request.header.x-static-guardrails') || '').toLowerCase();
var mode = (hdrMode === 'enforce' || hdrMode === 'monitor' || hdrMode === 'disable') ? hdrMode : (prop('mode.default') || 'enforce');
context.setVariable('sg.mode', mode);
var hdrOut = String(context.getVariable('request.header.x-static-outbound') || '').toLowerCase();
var outMode = (hdrOut === 'enforce' || hdrOut === 'redact' || hdrOut === 'monitor' || hdrOut === 'disable')
  ? hdrOut : (prop('mode.outbound_default') || 'enforce');
context.setVariable('sg.out_mode', outMode);

// Profile: x-static-profile = balanced | strict   (default: property profile.default, else balanced)
//   balanced - high-precision first line of defence: ambiguous signals are FLAGged for Model Armor
//   strict   - original behaviour: every catalog BLOCK blocks (e.g. agentic / tool-calling apps)
var hdrProfile = String(context.getVariable('request.header.x-static-profile') || '').toLowerCase();
var profile = (hdrProfile === 'balanced' || hdrProfile === 'strict') ? hdrProfile : (prop('profile.default') || 'balanced');
context.setVariable('sg.profile', profile === 'strict' ? 'strict' : 'balanced');
// Per-rule severity overrides without redeploying the SharedFlow: "SG-PI-005:LOG,SG-SSRF-001:BLOCK"
context.setVariable('sg.overrides', JSON.stringify({
  'in': SG.parseOverrides(prop('sev.overrides')),
  out: SG.parseOverrides(prop('sev.overrides_out'))
}));

var body = context.getVariable('request.content') || '';
var texts = [], turns = 0, parseError = false;

function collectParts(parts) {
  if (!parts || !parts.length) { return; }
  for (var p = 0; p < parts.length; p++) {
    if (parts[p] && typeof parts[p].text === 'string') { texts.push(parts[p].text); }
  }
}

if (body) {
  try {
    var j = JSON.parse(body);
    if (j && j.systemInstruction) { collectParts(j.systemInstruction.parts); }
    if (j && j.contents && j.contents.length) {
      turns = j.contents.length;
      for (var c = 0; c < j.contents.length; c++) {
        if (j.contents[c]) { collectParts(j.contents[c].parts); }
      }
    }
  } catch (e) {
    parseError = true;
  }
}

var maxChars = intProp('limit.max_prompt_chars', 8192);
var raw = texts.join('\n');
var chars = raw.length;
// Cap what the regex engines see (ReDoS / cost guard). Oversize is blocked by SG-STR-002 anyway.
if (raw.length > maxChars) { raw = raw.substring(0, maxChars); }

var n = SG.normalize(raw);
context.setVariable('sg.prompt_raw', raw);
context.setVariable('sg.prompt_norm', n.text);
context.setVariable('sg.prompt_folded', SG.fold(n.text));
context.setVariable('sg.metrics', JSON.stringify({
  chars: chars, maxChars: maxChars,
  turns: turns, maxTurns: intProp('limit.max_turns', 20),
  zeroWidth: n.zeroWidth, maxZeroWidth: intProp('limit.max_zero_width', 5),
  control: n.control, maxControl: intProp('limit.max_control_chars', 5),
  tags: n.tags,
  parseError: parseError
}));
context.setVariable('sg.lexicon', JSON.stringify(SG.loadLexicon(prop)));
context.setVariable('sg.min_flag_categories', String(intProp('escalation.min_flag_categories', 2)));
