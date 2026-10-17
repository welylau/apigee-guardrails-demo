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

  var ZH_FOLD = (typeof SG_ZH_FOLD !== 'undefined') ? SG_ZH_FOLD : {};
  // Separators inserted BETWEEN two CJK characters to split keywords (e.g. spaces or dots between
  // every Chinese character) are dropped. Only applies CJK-to-CJK, so English / code is untouched.
  var CJK = '\\u3040-\\u30ff\\u3400-\\u4dbf\\u4e00-\\u9fff\\uf900-\\ufaff';
  var CJK_GAP = new RegExp('([' + CJK + '])[\\s._*|/\\\\~\'"`\\u00b7\\u30fb-]+(?=[' + CJK + '])', 'g');

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
    var lower = out.join('').toLowerCase(), res = [], ch;
    for (i = 0; i < lower.length; i++) {
      ch = lower.charAt(i);
      var m = HOMOGLYPHS[lower.charCodeAt(i)];
      // Traditional -> Simplified Chinese fold (SG_ZH_FOLD from sg-rules.js); rules are folded the same way.
      res.push(m ? m : (ZH_FOLD.hasOwnProperty(ch) ? ZH_FOLD[ch] : ch));
    }
    var s = res.join('').replace(CJK_GAP, '$1');
    return { text: s.replace(/\s+/g, ' ').replace(/^ | $/g, ''), zeroWidth: zw, control: ctrl, tags: tags };
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
    var langs = ['en', 'zh', 'yue', 'ja', 'ko', 'th', 'vi', 'ms', 'id'], tiers = ['t1', 't2', 't2c', 't3'], lex = { allow: [], deny: [] };
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

  // profile: 'balanced' (default) | 'strict'. Strict uses sevInStrict / sevOutStrict when a rule has one.
  function sevFor(rule, direction, profile) {
    if (direction === 'out') {
      return (profile === 'strict' && rule.sevOutStrict !== undefined) ? rule.sevOutStrict : rule.sevOut;
    }
    return (profile === 'strict' && rule.sevInStrict !== undefined) ? rule.sevInStrict : rule.sevIn;
  }

  // texts = {raw: ..., norm: ...}; direction = 'in' | 'out'; catFilter optional
  function scanRules(texts, direction, catFilter, profile) {
    var hits = [], i, r, sev, h;
    for (i = 0; i < SG_RULES.length; i++) {
      r = SG_RULES[i];
      sev = sevFor(r, direction, profile);
      if (!sev || (catFilter && r.cat !== catFilter)) { continue; }
      if (r.re.test(r.src === 'raw' ? texts.raw : texts.norm)) {
        h = { id: r.id, cat: r.cat, sev: sev };
        if (r.noEsc) { h.noEsc = true; }
        hits.push(h);
      }
    }
    return hits;
  }

  // t2c = casual strong profanity (fuck / shit / \u4ed6\u5abd\u7684 ...): FLAG in balanced, BLOCK in strict.
  var TIER_SEV = { t1: 'BLOCK', t2: 'BLOCK', t2c: 'FLAG', t3: 'LOG' };

  // Casual profanity AIMED AT someone is abuse in every profile (SG-LEX-T2, BLOCK). Runs on the
  // folded text (leetspeak folded, repeated letters collapsed: "off" -> "of", "bullshit" -> "bulshit").
  var PROF = '(f+u*c*k+(ing|in|er|ed|s)?|f[*#_.]{1,3}(c?k|u?ck)(ing|in|er|ed|s)?|sh[i*#][*#]?t|bulshit)';
  var INSULT = '(idiot|moron|loser|retard|bitch|bastard|ashole|dumbas|jerk|failure|clown|freak|pig|dog|cunt|twat|prick|imbecile|piece)';
  var TARGETED_RE = new RegExp(
    '\\b' + PROF + '\\s+(you|u|ya|yourself|urself|of|ur)\\b' +                                   // fuck you / fuck off
    '|\\b(you|u|ur|youre|you\'re|ya)\\b(\\s+(are|r|re|is))?(\\s+(a|an|such\\s+a|the))?\\s+' +     // you (are a) fucking idiot
      '(litle\\s+|stupid\\s+|dumb\\s+)?' + PROF + '\\s+' + INSULT +
    '|\\b(you|u|ur|youre|you\'re)\\b(\\s+(are|r|re))?(\\s+a)?\\s+(piece\\s+of\\s+sh[i*#][*#]?t|shithead)'); // you piece of shit
  // "f u c k off" -> "fuck off" for the targeted check only.
  function joinSpacedLetters(t) {
    return t.replace(/\b[a-z](?:[\s._-]{1,3}[a-z]\b){2,}/g, function (m) { return m.replace(/[\s._-]/g, ''); });
  }

  function scanLexicon(norm, folded, lex, direction, profile) {
    var hits = [], s = stripAllowed(norm, folded, lex), tiers = ['t1', 't2', 't2c', 't3'], i, k, re, tier, found, sev;
    for (i = 0; i < tiers.length; i++) {
      tier = tiers[i];
      if (!lex[tier]) { continue; }
      found = false;
      re = wordRegex(lex[tier].ascii);
      if (re && re.test(s.folded)) { found = true; }
      for (k = 0; !found && k < lex[tier].uni.length; k++) {
        var at = s.norm.indexOf(lex[tier].uni[k].t);
        if (at !== -1) {
          found = true;
          // CJK casual term with "you" (U+4F60) within 3 chars either side = aimed at someone.
          if (tier === 't2c' && s.norm.substring(Math.max(0, at - 3), at + lex[tier].uni[k].t.length + 3).indexOf('\u4f60') !== -1) {
            hits.push({ id: 'SG-LEX-T2', cat: 'harsh_language', sev: 'BLOCK' });
          }
        }
      }
      if (found) {
        sev = (tier === 't2c' && profile === 'strict') ? 'BLOCK' : TIER_SEV[tier];
        hits.push({ id: 'SG-LEX-' + tier.toUpperCase(), cat: 'harsh_language', sev: sev });
      }
    }
    if (TARGETED_RE.test(joinSpacedLetters(s.folded))) {
      hits.push({ id: 'SG-LEX-T2', cat: 'harsh_language', sev: 'BLOCK' });
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

  // Taiwan national ID / resident certificate: letter + [1289] + 8 digits, weighted checksum.
  var TW_LETTER = 'ABCDEFGHJKLMNPQRSTUVXYWZIO'; // index + 10 = area code (A=10 ... I=34, O=35)
  function twIdOk(letter, digits9) {
    var code = TW_LETTER.indexOf(letter.toUpperCase()) + 10, w = [8, 7, 6, 5, 4, 3, 2, 1, 1], sum, i;
    if (code < 10) { return false; }
    sum = Math.floor(code / 10) + (code % 10) * 9;
    for (i = 0; i < 9; i++) { sum += (digits9.charCodeAt(i) - 48) * w[i]; }
    return sum % 10 === 0;
  }

  // Hong Kong HKID: 1-2 letters + 6 digits + (check digit 0-9 or A), mod-11.
  function hkidOk(prefix, digits, check) {
    var p = prefix.toUpperCase(), sum, i, r;
    sum = p.length === 2 ? (p.charCodeAt(0) - 55) * 9 + (p.charCodeAt(1) - 55) * 8 : 36 * 9 + (p.charCodeAt(0) - 55) * 8;
    for (i = 0; i < 6; i++) { sum += (digits.charCodeAt(i) - 48) * (7 - i); }
    r = 11 - (sum % 11);
    return (r === 11 ? '0' : r === 10 ? 'A' : String(r)) === check.toUpperCase();
  }
  var TW_ID_RE = /\b([A-Za-z])([1289]\d{8})\b/g;
  var HKID_RE = /\b([A-Za-z]{1,2})(\d{6})\s?\(([0-9Aa])\)/g;

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
    re = new RegExp(TW_ID_RE.source, 'g');
    while ((m = re.exec(raw)) !== null) {
      if (twIdOk(m[1], m[2])) { hits.push({ id: 'SG-PII-010', cat: 'pii', sev: 'BLOCK' }); break; }
    }
    re = new RegExp(HKID_RE.source, 'g');
    while ((m = re.exec(raw)) !== null) {
      if (hkidOk(m[1], m[2], m[3])) { hits.push({ id: 'SG-PII-011', cat: 'pii', sev: 'BLOCK' }); break; }
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

  // ---------------------------------------------------------------------------------------------
  // Context dampeners (balanced profile, inbound only). They LOWER a catalog BLOCK to FLAG when the
  // context suggests a legitimate prompt - never to ALLOW, so the request still reaches Model Armor.
  // Only prompt_injection / code_injection rules are dampened; secrets and PII never are.
  // ---------------------------------------------------------------------------------------------
  var RULE_BY_ID = {};
  (function () { for (var i = 0; i < SG_RULES.length; i++) { RULE_BY_ID[SG_RULES[i].id] = SG_RULES[i]; } })();
  var DAMPEN_CATS = { prompt_injection: 1, code_injection: 1 };
  // Talking ABOUT an attack (defence / definition / classification), EN + ZH (prompt is TC->SC folded).
  var META_CUE = new RegExp(
    '\\bhow\\s+(do|can|should|to)\\s+(i\\s+|we\\s+|you\\s+)?(detect|prevent|defend|mitigate|block|stop|protect|guard)\\b' +
    '|\\bwhat\\s+(is|are|does)\\s+(a\\s+|an\\s+)?(prompt\\s+injection|jailbreak|sql\\s+injection|xss|injection|payload)' +
    '|\\bis\\s+this\\s+(a\\s+|an\\s+)?(prompt\\s+injection|jailbreak|attack|malicious|safe|sql\\s+injection)' +
    '|\\b(an\\s+)?example\\s+of\\s+(a\\s+|an\\s+)?(prompt\\s+injection|jailbreak|sql\\s+injection|xss|attack|payload)' +
    '|\\bwhat\\s+does\\b.{0,80}\\bmean\\b' +
    '|\u5982\u4f55(\u9632\u5fa1|\u9632\u8303|\u68c0\u6d4b|\u9632\u6b62|\u963b\u6b62|\u8bc6\u522b|\u9632\u62a4)|\u600e\u4e48(\u9632\u5fa1|\u9632\u8303|\u68c0\u6d4b|\u9632\u6b62|\u963b\u6b62|\u8bc6\u522b)' +
    '|\u4ec0\u4e48\u662f(\u63d0\u793a\u8bcd?\u6ce8\u5165|\u8d8a\u72f1|sql\u6ce8\u5165|\u6ce8\u5165\u653b\u51fb)|\u8fd9\u662f\u4e0d\u662f(\u63d0\u793a\u8bcd?\u6ce8\u5165|\u8d8a\u72f1|\u653b\u51fb)|\u8fd9\u662f(\u63d0\u793a\u8bcd?\u6ce8\u5165|\u8d8a\u72f1|\u653b\u51fb)\u5417|\u662f\u4ec0\u4e48\u610f\u601d');
  // Asking for a code review (checked outside fenced code blocks).
  var REVIEW_CUE = new RegExp(
    '\\b(explain|review|fix|debug|refactor|audit|why\\s+(is|does)|is\\s+this|vulnerab\\w*|secure|insecure|safe)\\b' +
    '|\u89e3\u91ca|\u68c0\u67e5|\u4fee\u590d|\u5ba1\u67e5|\u6709\u6ca1\u6709\u95ee\u9898|\u5b89\u5168\u5417|\u6f0f\u6d1e|\u4e3a\u4ec0\u4e48');
  var NEG_ZH = /(\u4e0d\u8981|\u522b|\u8bf7\u52ff|\u4e0d\u80fd|\u4e0d\u53ef\u4ee5|\u4e0d\u53ef|\u5207\u52ff|\u5343\u4e07\u4e0d\u8981|\u5343\u4e07\u522b|\u4e0d\u5e94\u8be5|\u4e0d\u8be5)$/;
  var QUOTE_CH = '"\'`\u201c\u201d\u2018\u2019\u300c\u300d\u300e\u300f';
  function hasQuote(s) {
    for (var i = 0; i < s.length; i++) { if (QUOTE_CH.indexOf(s.charAt(i)) !== -1) { return true; } }
    return false;
  }
  function stripFences(t) { return t.replace(/```[\s\S]*?```/g, ' '); }

  // hits: catalog hits from scanRules(); texts: {raw, norm}. Mutates and returns hits.
  function dampen(hits, texts) {
    var i, h, r, t, m, before, after, outside, reason;
    for (i = 0; i < hits.length; i++) {
      h = hits[i];
      if (h.sev !== 'BLOCK' || !DAMPEN_CATS[h.cat] || !(r = RULE_BY_ID[h.id])) { continue; }
      t = r.src === 'raw' ? texts.raw : texts.norm;
      m = r.re.exec(t);
      if (!m) { continue; }
      before = t.substring(Math.max(0, m.index - 3), m.index);
      after = t.substring(m.index + m[0].length, m.index + m[0].length + 3);
      outside = stripFences(t);
      reason = null;
      if (hasQuote(before) && hasQuote(after)) { reason = 'quoted'; }                     // mention, not use
      else if (META_CUE.test(t)) { reason = 'meta'; }                                        // discussing attacks
      else if (h.cat === 'code_injection' && outside !== t && !r.re.test(outside) && REVIEW_CUE.test(outside)) {
        reason = 'code-review';                                                              // payload only inside ``` + review ask
      } else if (h.id === 'SG-PI-006' && NEG_ZH.test(t.substring(Math.max(0, m.index - 4), m.index))) {
        reason = 'negation';                                                                 // ZH "do not ignore the previous rules"
      }
      if (reason) { h.sev = 'FLAG'; h.damp = reason; }
    }
    return hits;
  }

  // overrides: {"SG-PI-005": "LOG", ...} from property sev.overrides / sev.overrides_out.
  // OFF keeps the hit (so JS-SG-Decide knows the rule was seen) but it is ignored by decide().
  function applyOverrides(hits, overrides) {
    var i;
    if (!overrides) { return hits; }
    for (i = 0; i < hits.length; i++) {
      if (overrides.hasOwnProperty(hits[i].id)) { hits[i].sev = overrides[hits[i].id]; hits[i].override = true; }
    }
    return hits;
  }
  function parseOverrides(str) {
    var out = {}, parts = parseList(str), i, kv, sev;
    for (i = 0; i < parts.length; i++) {
      kv = parts[i].split(':');
      sev = (kv[1] || '').replace(/\s+/g, '').toUpperCase();
      if (kv[0] && (sev === 'BLOCK' || sev === 'FLAG' || sev === 'LOG' || sev === 'OFF')) { out[kv[0].replace(/\s+/g, '')] = sev; }
    }
    return out;
  }

  // Escalation (SG-ESC-001): FLAGs from >= minFlagCats categories become a BLOCK.
  //   strict  : any categories (original behaviour)
  //   balanced: dampened / noEsc hits do not count, and at least one INTENT category is required
  //             (an email + a shortened URL is not an attack; a bypass request + an OAST URL is).
  var INTENT = { prompt_injection: 1, code_injection: 1, secret_leak: 1 };
  // Returns {verdict: block|flag|pass, primary: hit|null, block: [ids], flag: [ids], log: [ids]}
  function decide(hits, minFlagCats, profile) {
    var res = { verdict: 'pass', primary: null, block: [], flag: [], log: [] }, cats = {}, nCats = 0, intent = false, i, h;
    for (i = 0; i < hits.length; i++) {
      h = hits[i];
      if (h.sev === 'OFF') { continue; }
      if (h.sev === 'BLOCK') { res.block.push(h.id); if (!res.primary) { res.primary = h; } }
      else if (h.sev === 'FLAG') {
        res.flag.push(h.id);
        if (profile !== 'strict' && (h.damp || h.noEsc)) { continue; }
        if (!cats[h.cat]) { cats[h.cat] = 1; nCats++; }
        if (INTENT[h.cat]) { intent = true; }
      }
      else { res.log.push(h.id); }
    }
    if (res.primary) { res.verdict = 'block'; }
    else if (minFlagCats > 0 && nCats >= minFlagCats && (profile === 'strict' || intent)) {
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
    decide: decide, dedupe: dedupe, MESSAGES: MESSAGES, luhnOk: luhnOk, nricOk: nricOk,
    twIdOk: twIdOk, hkidOk: hkidOk, TW_ID_RE: TW_ID_RE, HKID_RE: HKID_RE,
    dampen: dampen, applyOverrides: applyOverrides, parseOverrides: parseOverrides
  };
})();
