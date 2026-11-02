// Resolve the Model Armor preset for this request (strict | balanced | permissive) and map it to
// this demo's templates: guardrail-proxy-{in|out}-{preset}.
//
//   x-ma-profile       preset for both directions (default: balanced)
//   x-ma-profile-in    optional per-direction override (tests)
//   x-ma-profile-out   optional per-direction override (tests)
//
// Only the three preset names are accepted; anything else falls back to the default, so a caller can
// never choose an arbitrary template. SUP-userprompt / SMR-modelresponse read ma.template_in / _out.
var PRESETS = { strict: true, balanced: true, permissive: true };
var DEFAULT_PRESET = 'balanced';
var PREFIX = 'guardrail-proxy';

function pick(header, fallback) {
  var v = String(context.getVariable('request.header.' + header) || '').trim().toLowerCase();
  return PRESETS[v] ? v : fallback;
}

var both = pick('x-ma-profile', DEFAULT_PRESET);
var pin = pick('x-ma-profile-in', both);
var pout = pick('x-ma-profile-out', both);

context.setVariable('ma.profile', pin === pout ? pin : pin + '/' + pout);
context.setVariable('ma.profile_in', pin);
context.setVariable('ma.profile_out', pout);
context.setVariable('ma.template_in', PREFIX + '-in-' + pin);
context.setVariable('ma.template_out', PREFIX + '-out-' + pout);
