/*
 * request-validate.js - gateway request validation + inspection text (OWASP API3 / LLM01 / LLM07).
 *
 * 1. Allow-list: the body may only contain "contents". Client-supplied systemInstruction,
 *    safetySettings, tools, toolConfig, generationConfig, cachedContent ... are rejected (400),
 *    so a caller cannot override the app's instructions or Gemini's safety settings.
 * 2. Every turn must have role user|model and text-only parts (no inlineData / functionCall ...).
 * 3. Builds guardrail.inspect_text from ALL text parts of ALL turns, so Model Armor and NeMo also
 *    see attacks placed in an earlier turn or an earlier part (not just the last part).
 *
 * Sets: reqval.reject ("true" to block), reqval.message, reqval.fields, guardrail.inspect_text,
 *       guardrail.inspect_chars, guardrail.turns.
 */
var ALLOWED_KEYS = { contents: true };
var ALLOWED_ROLES = { user: true, model: true };
var MAX_BODY_CHARS = 131072;     // P2: ~128 KB request body; larger -> 413 (OWASP API4 / LLM10)
var MAX_TURNS = 100;             // P2: conversation length cap
var MAX_INSPECT_CHARS = 50000;   // Model Armor input; head + tail kept when longer
var HEAD_CHARS = 10000;

function jsonSafe(s) {
    var j = JSON.stringify(String(s || ''));
    return j.substring(1, j.length - 1);
}
function nameSafe(s) {
    return String(s).replace(/[^A-Za-z0-9_\-.]/g, '').substring(0, 40);
}
function reject(message, fields) {
    context.setVariable('reqval.reject', 'true');
    context.setVariable('reqval.message', jsonSafe(message));
    context.setVariable('reqval.fields', jsonSafe((fields || []).join(',')));
}

context.setVariable('reqval.reject', 'false');
context.setVariable('reqval.too_large', 'false');
var raw = context.getVariable('request.content') || '';
var body = null;
if (raw.length > MAX_BODY_CHARS) {
    // Checked before parsing, so oversized bodies cost almost nothing.
    context.setVariable('reqval.too_large', 'true');
    reject('Request body is too large (' + raw.length + ' characters; limit ' + MAX_BODY_CHARS + ').', ['body']);
    raw = '';
}
try {
    body = raw ? JSON.parse(raw) : null;
} catch (e) {
    body = null;
}

if (context.getVariable('reqval.too_large') === 'true') {
    // already rejected
} else if (!body || typeof body !== 'object' || Array.isArray(body)) {
    reject('Request body must be a JSON object with a "contents" array.', []);
} else {
    var extra = [];
    for (var k in body) {
        if (Object.prototype.hasOwnProperty.call(body, k) && !ALLOWED_KEYS[k]) {
            extra.push(nameSafe(k));
        }
    }
    var contents = body.contents;
    if (extra.length) {
        reject('Client overrides are not allowed. Only "contents" may be sent; the gateway owns system instructions, safety settings, tools and generation settings.', extra.slice(0, 8));
    } else if (!Array.isArray(contents) || contents.length === 0) {
        reject('"contents" must be a non-empty array.', ['contents']);
    } else if (contents.length > MAX_TURNS) {
        reject('Too many conversation turns (' + contents.length + '; limit ' + MAX_TURNS + ').', ['contents']);
    } else {
        var texts = [];
        var bad = null;
        for (var i = 0; i < contents.length && !bad; i++) {
            var turn = contents[i] || {};
            var role = turn.role === undefined ? 'user' : String(turn.role);
            if (!ALLOWED_ROLES[role]) { bad = ['Each turn must have role "user" or "model".', 'contents[' + i + '].role']; break; }
            var parts = turn.parts;
            if (!Array.isArray(parts) || parts.length === 0) { bad = ['Each turn needs a non-empty "parts" array.', 'contents[' + i + '].parts']; break; }
            for (var p = 0; p < parts.length; p++) {
                var part = parts[p] || {};
                var keys = [];
                for (var pk in part) { if (Object.prototype.hasOwnProperty.call(part, pk)) keys.push(pk); }
                if (keys.length !== 1 || keys[0] !== 'text' || typeof part.text !== 'string') {
                    bad = ['Only text parts are accepted (no inlineData, fileData, functionCall or functionResponse).',
                           'contents[' + i + '].parts[' + p + ']'];
                    break;
                }
                texts.push(part.text);
            }
        }
        if (bad) {
            reject(bad[0], [bad[1]]);
        } else {
            var all = texts.join('\n\n');
            if (all.length > MAX_INSPECT_CHARS) {
                all = all.substring(0, HEAD_CHARS) + '\n[...]\n' + all.substring(all.length - (MAX_INSPECT_CHARS - HEAD_CHARS));
            }
            context.setVariable('guardrail.inspect_text', all);
            context.setVariable('guardrail.inspect_chars', String(all.length));
            context.setVariable('guardrail.turns', String(contents.length));
        }
    }
}
