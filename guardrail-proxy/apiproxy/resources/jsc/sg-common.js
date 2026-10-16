/*
 * StaticGuardrails common library.
 * Used by the StaticGuardrails SharedFlow (inbound) and copied by build.py into
 * guardrail-proxy (outbound EventFlow scan). ES5 only (Apigee JavaScript runtime).
 * Requires sg-rules.js (SG_RULES, SG_RE_POLICIES) to be included first.
 *
 * Security notes:
 *  - Never returns / logs the matched user text; hits carry rule id, category, severity only.
 *  - All regexes are bounded (no nested quantifiers); input length is capped by the caller.
 */
var SG = (function () {
  'use strict';

  var ZERO_WIDTH = { 0x00AD: 1, 0x034F: 1, 0x115F: 1, 0x1160: 1, 0x180E: 1, 0x200B: 1, 0x200C: 1,
                     0x200D: 1, 0x200E: 1, 0x200F: 1, 0x202A: 1, 0x202B: 1, 0x202C: 1, 0x202D: 1,
                     0x202E: 1, 0x2060: 1, 0x2061: 1, 0x2062: 1, 0x2063: 1, 0x2064: 1, 0x2066: 1,
                     0x2067: 1, 0x2068: 1, 0x2069: 1, 0x3164: 1, 0xFEFF: 1, 0xFFA0: 1 };
  // Cyrillic / Greek look-alikes (lower-case) -> Latin
  var HOMOGLYPHS = { 0x0430: 'a', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p', 0x0441: 'c', 0x0445: 'x',
                     0x0443: 'y', 0x0456: 'i', 0x0458: 'j', 0x0455: 's', 0x04CF: 'l',
                     0x03B1: 'a', 0x03BF: 'o', 0x03B5: 'e', 0x03B9: 'i', 0x03BA: 'k', 0x03BD: 'v',
                     0x03C1: 'p', 0x03C4: 't', 0x03C5: 'u', 0x03C7: 'x' };
  var LEET = { '@': 'a', '4': 'a', '0': 'o', '1': 'i', '!': 'i', '3': 'e', '5': 's', '$': 's', '7': 't', '+': 't' };

  var MESSAGES = {
    prompt_injection: 'Request blocked: prompt injection / jailbreak pattern detected.',
    code_injection: 'Request blocked: code or SQL injection payload detected.',
    secret_leak: 'Request blocked: credentials or secrets detected. Remove them and retry.',
    harsh_language: 'Request blocked: abusive or harsh language detected.',
    pii: 'Request blocked: sensitive personal data detected.',
    structural_abuse: 'Request blocked: malformed, oversized or obfuscated payload.',
    business_denylist: 'Request blocked: restricted term detected.',
    malicious_url: 'Request blocked: suspicious or malicious URL detected.',
    escalation: 'Request blocked: multiple suspicious signals detected.'
  };

  // Unicode "tag" characters (U+E0020-U+E007E, surrogate pair 0xDB40 + 0xDC20-0xDC7E) are invisible
  // but map 1:1 to ASCII - a known way to smuggle hidden instructions to an LLM ("ASCII smuggling").
  // normalize() decodes them back to visible ASCII (so every rule sees the hidden text) and counts them.
  function normalize(text) {
    var out = [], zw = 0, ctrl = 0, tags = 0, i, c, lo;
    text = text || '';
    for (i = 0; i < text.length; i++) {
      c = text.charCodeAt(i);
      if (c === 0xDB40 && i + 1 < text.length) {
        lo = text.charCodeAt(i + 1);
        if (lo >= 0xDC00 && lo <= 0xDC7F) {
          tags++; i++;
          if (lo >= 0xDC20 && lo <= 0xDC7E) { out.push(String.fromCharCode(lo - 0xDC00)); }
          continue;
        }
      }
      if (c >= 0xFE00 && c <= 0xFE0D) { zw++; continue; }  // variation selectors (keep FE0E/FE0F text/emoji style)
      if (ZERO_WIDTH[c]) { zw++; continue; }
      if (c < 0x20 && c !== 0x0A && c !== 0x09 && c !== 0x0D) { ctrl++; continue; }
      if (c >= 0xFF01 && c <= 0xFF5E) { c -= 0xFEE0; }       // full-width ASCII -> ASCII
      else if (c === 0x3000) { c = 0x20; }                    // ideographic space
      out.push(String.fromCharCode(c));
    }
    var lower = out.join('').toLowerCase(), res = [];
    for (i = 0; i < lower.length; i++) {
      var m = HOMOGLYPHS[lower.charCodeAt(i)];
      res.push(m ? m : lower.charAt(i));
    }
    return { text: res.join('').replace(/\s+/g, ' ').replace(/^ | $/g, ''), zeroWidth: zw, control: ctrl, tags: tags };
  }

  // Leetspeak fold + collapse repeated letters. Applied identically to text and lexicon terms.
  function fold(norm) {
    var res = [], i, ch;
    for (i = 0; i < norm.length; i++) {
      ch = norm.charAt(i);
      res.push(LEET.hasOwnProperty(ch) ? LEET[ch] : ch);
    }
    return res.join('').replace(/([a-z])\1+/g, '$1');
  }

  function isAscii(s) { return /^[\x00-\x7F]*$/.test(s); }
  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function parseList(str) {
    var out = [], parts = (str || '').split(','), i, t;
    for (i = 0; i < parts.length; i++) {
      t = parts[i].replace(/^\s+|\s+$/g, '');
      if (t) { out.push(t); }
    }
    return out;
  }

  // getProp(key) -> property value string (propertyset.sg.<key>)
  function loadLexicon(getProp) {
    var langs = ['en', 'zh', 'ja', 'ko', 'th', 'vi', 'ms', 'id'], tiers = ['t1', 't2', 't3'], lex = { allow: [], deny: [] };
    var ti, li, terms, k;
    for (ti = 0; ti < tiers.length; ti++) {
      lex[tiers[ti]] = { ascii: [], uni: [] };
      for (li = 0; li < langs.length; li++) {
        terms = parseList(getProp('lex.' + tiers[ti] + '.' + langs[li]));
        for (k = 0; k < terms.length; k++) {
          if (isAscii(terms[k])) { lex[tiers[ti]].ascii.push(fold(normalize(terms[k]).text)); }
          else { lex[tiers[ti]].uni.push({ t: normalize(terms[k]).text, lang: langs[li] }); }
        }
      }
    }
    terms = parseList(getProp('lex.allow'));
    for (k = 0; k < terms.length; k++) {
      lex.allow.push({ n: normalize(terms[k]).text, f: fold(normalize(terms[k]).text) });
    }
    terms = parseList(getProp('deny.terms'));
    for (k = 0; k < terms.length; k++) {
      var p = terms[k].split('|'), term = normalize(p[0]).text;
      var sev = (p[1] || 'FLAG').toUpperCase() === 'BLOCK' ? 'BLOCK' : 'FLAG';
      lex.deny.push({ t: isAscii(term) ? fold(term) : term, ascii: isAscii(term), sev: sev });
    }
    return lex;
  }

  function stripAllowed(norm, folded, lex) {
    var i;
    for (i = 0; i < lex.allow.length; i++) {
      if (lex.allow[i].n) { norm = norm.split(lex.allow[i].n).join(' '); }
      if (lex.allow[i].f) { folded = folded.split(lex.allow[i].f).join(' '); }
    }
    return { norm: norm, folded: folded };
  }

  function wordRegex(terms) {
    if (!terms.length) { return null; }
    var esc = [], i;
    for (i = 0; i < terms.length; i++) { esc.push(escapeRe(terms[i])); }
    return new RegExp('(^|[^a-z0-9])(' + esc.join('|') + ')(?=$|[^a-z0-9])');
  }

  function sevFor(rule, direction) { return direction === 'out' ? rule.sevOut : rule.sevIn; }

  // texts = {raw: ..., norm: ...}; direction = 'in' | 'out'; catFilter optional
  function scanRules(texts, direction, catFilter) {
    var hits = [], i, r, sev;
    for (i = 0; i < SG_RULES.length; i++) {
      r = SG_RULES[i];
      sev = sevFor(r, direction);
      if (!sev || (catFilter && r.cat !== catFilter)) { continue; }
      if (r.re.test(r.src === 'raw' ? texts.raw : texts.norm)) {
        hits.push({ id: r.id, cat: r.cat, sev: sev });
      }
    }
    return hits;
  }

  var TIER_SEV = { t1: 'BLOCK', t2: 'BLOCK', t3: 'LOG' };

  function scanLexicon(norm, folded, lex, direction) {
    var hits = [], s = stripAllowed(norm, folded, lex), tiers = ['t1', 't2', 't3'], i, k, re, tier, found;
    for (i = 0; i < tiers.length; i++) {
      tier = tiers[i];
      if (!lex[tier]) { continue; }
      found = false;
      re = wordRegex(lex[tier].ascii);
      if (re && re.test(s.folded)) { found = true; }
      for (k = 0; !found && k < lex[tier].uni.length; k++) {
        if (s.norm.indexOf(lex[tier].uni[k].t) !== -1) { found = true; }
      }
      if (found) {
        hits.push({ id: 'SG-LEX-' + tier.toUpperCase(), cat: 'harsh_language', sev: TIER_SEV[tier] });
      }
    }
    for (k = 0; k < lex.deny.length; k++) {
      var d = lex.deny[k];
      var hit = d.ascii ? wordRegex([d.t]).test(s.folded) : s.norm.indexOf(d.t) !== -1;
      if (hit) { hits.push({ id: 'SG-DENY-001', cat: 'business_denylist', sev: d.sev }); break; }
    }
    return hits;
  }

  function luhnOk(digits) {
    var sum = 0, alt = false, i, n;
    for (i = digits.length - 1; i >= 0; i--) {
      n = digits.charCodeAt(i) - 48;
      if (alt) { n *= 2; if (n > 9) { n -= 9; } }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }

  function nricOk(prefix, digits, check) {
    var w = [2, 7, 6, 5, 4, 3, 2], sum = 0, i;
    prefix = prefix.toUpperCase(); check = check.toUpperCase();
    for (i = 0; i < 7; i++) { sum += (digits.charCodeAt(i) - 48) * w[i]; }
    if (prefix === 'T' || prefix === 'G') { sum += 4; }
    if (prefix === 'M') { return true; } // M-series: format-only check
    var rem = sum % 11;
    var table = (prefix === 'S' || prefix === 'T') ? 'JZIHGFEDCBA' : 'XWUTRQPNMLK';
    return table.charAt(rem) === check;
  }

  function thaiIdOk(d) {
    var sum = 0, i;
    for (i = 0; i < 12; i++) { sum += (d.charCodeAt(i) - 48) * (13 - i); }
    return ((11 - (sum % 11)) % 10) === (d.charCodeAt(12) - 48);
  }

  function scanPII(raw) {
    var hits = [], m, re;
    re = /\b(?:\d[ -]?){12,18}\d\b/g;
    while ((m = re.exec(raw)) !== null) {
      var digits = m[0].replace(/[ -]/g, '');
      if (digits.length >= 13 && digits.length <= 19 && luhnOk(digits)) {
        hits.push({ id: 'SG-PII-001', cat: 'pii', sev: 'FLAG' }); break;
      }
    }
    re = /\b([STFGMstfgm])(\d{7})([A-Za-z])\b/g;
    while ((m = re.exec(raw)) !== null) {
      if (nricOk(m[1], m[2], m[3])) { hits.push({ id: 'SG-PII-002', cat: 'pii', sev: 'FLAG' }); break; }
    }
    re = /\b(\d)[- ]?(\d{4})[- ]?(\d{5})[- ]?(\d{2})[- ]?(\d)\b/g;
    while ((m = re.exec(raw)) !== null) {
      if (thaiIdOk(m[1] + m[2] + m[3] + m[4] + m[5])) { hits.push({ id: 'SG-PII-003', cat: 'pii', sev: 'FLAG' }); break; }
    }
    if (/[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}/.test(raw)) {
      hits.push({ id: 'SG-PII-004', cat: 'pii', sev: 'FLAG' });
    }
    return hits;
  }

  // m = {chars, maxChars, turns, maxTurns, zeroWidth, maxZeroWidth, control, maxControl, parseError, jsonThreat}
  function scanStructural(m) {
    var hits = [];
    if (m.parseError) { hits.push({ id: 'SG-STR-000', cat: 'structural_abuse', sev: 'BLOCK' }); }
    if (m.jsonThreat) { hits.push({ id: 'SG-STR-001', cat: 'structural_abuse', sev: 'BLOCK' }); }
    if (m.chars > m.maxChars || m.turns > m.maxTurns) {
      hits.push({ id: 'SG-STR-002', cat: 'structural_abuse', sev: 'BLOCK' });
    }
    if (m.zeroWidth > m.maxZeroWidth || m.control > m.maxControl) {
      hits.push({ id: 'SG-STR-004', cat: 'structural_abuse', sev: 'BLOCK' });
    }
    if (m.tags > 0) {
      hits.push({ id: 'SG-STR-008', cat: 'structural_abuse', sev: 'BLOCK' });
    }
    return hits;
  }

  // Returns {verdict: block|flag|pass, primary: hit|null, block: [ids], flag: [ids], log: [ids]}
  function decide(hits, minFlagCats) {
    var res = { verdict: 'pass', primary: null, block: [], flag: [], log: [] }, cats = {}, nCats = 0, i, h;
    for (i = 0; i < hits.length; i++) {
      h = hits[i];
      if (h.sev === 'BLOCK') { res.block.push(h.id); if (!res.primary) { res.primary = h; } }
      else if (h.sev === 'FLAG') { res.flag.push(h.id); if (!cats[h.cat]) { cats[h.cat] = 1; nCats++; } }
      else { res.log.push(h.id); }
    }
    if (res.primary) { res.verdict = 'block'; }
    else if (minFlagCats > 0 && nCats >= minFlagCats) {
      res.verdict = 'block';
      res.primary = { id: 'SG-ESC-001', cat: 'escalation', sev: 'BLOCK' };
      res.block.push('SG-ESC-001');
    } else if (res.flag.length) { res.verdict = 'flag'; }
    return res;
  }

  function dedupe(hits) {
    var seen = {}, out = [], i;
    for (i = 0; i < hits.length; i++) {
      if (!seen[hits[i].id]) { seen[hits[i].id] = 1; out.push(hits[i]); }
    }
    return out;
  }

  return {
    normalize: normalize, fold: fold, loadLexicon: loadLexicon, scanRules: scanRules,
    scanLexicon: scanLexicon, scanPII: scanPII, scanStructural: scanStructural,
    decide: decide, dedupe: dedupe, MESSAGES: MESSAGES, luhnOk: luhnOk, nricOk: nricOk
  };
})();
