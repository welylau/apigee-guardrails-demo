/* Guardrail Test Lab: renders testlab/results-latest.json. All text goes through textContent
   (prompts contain <script> etc. on purpose), never innerHTML. */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const LAYERS = [
    { key: 'static', run: 'S', name: 'Static Guardrails', img: 'assets/apigee-logo.svg', cls: 'c-static' },
    { key: 'model_armor', run: 'M', name: 'Model Armor', img: 'assets/model-armor-logo.svg', cls: 'c-ma' },
    { key: 'nemo', run: 'N', name: 'NVIDIA NeMo', img: 'assets/nvidia-logo.svg', cls: 'c-nemo' },
    { key: 'apigee', run: 'A', name: 'Apigee platform', img: 'assets/apigee-logo.svg', cls: 'c-apigee' },
  ];
  const CAUGHT = new Set(['static-in', 'static-out', 'ma-in', 'ma-out', 'nemo', 'redact', 'blocked']);
  const OUTCOME_TEXT = {
    'static-in': 'Static (prompt)', 'static-out': 'Static (answer)', redact: 'Static redacted',
    'ma-in': 'Model Armor (prompt)', 'ma-out': 'Model Armor (answer)', nemo: 'NeMo',
    pass: 'passed', blocked: 'blocked', allowed: 'allowed',
  };
  let data = null;
  let reveal = false;
  let openId = null;

  // ---- theme (shared with the main page) -------------------------------------------------
  const theme = localStorage.getItem('apigee_theme') || 'light';
  document.documentElement.setAttribute('data-theme', theme);
  $('themeToggleBtn').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('apigee_theme', next);
  });

  // ---- tiny DOM helper ----------------------------------------------------------------------
  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (v === undefined || v === null || v === false) return;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (k === 'style') n.setAttribute('style', v);
      else n.setAttribute(k, v === true ? '' : v);
    });
    children.flat().forEach((c) => { if (c !== null && c !== undefined) n.append(c instanceof Node ? c : document.createTextNode(String(c))); });
    return n;
  }
  const fmtPct = (v) => (v === null || v === undefined ? '—' : `${Math.round(v)}%`);
  // Blur attack prompts by default; safe prompts and API request descriptions stay readable.
  const isSensitive = (c) => c.expected === 'block' && c.direction !== 'api';
  // Model Armor fault strings list every filter as "XMatchesFound: true|false"; show only the matches.
  const MA_FILTERS = { RAI: 'Harmful content (RAI)', SDP: 'Sensitive data', PI: 'Prompt injection / jailbreak', CSAM: 'CSAM', URI: 'Malicious URL' };
  function friendlyDetail(text) {
    const s = String(text || '');
    if (!s.includes('MatchesFound')) return s;
    const hits = [...s.matchAll(/(\w+)MatchesFound: true/g)].map((m) => MA_FILTERS[m[1]] || m[1]);
    return hits.length ? `Model Armor matched: ${hits.join(', ')}` : 'Model Armor filter matched';
  }
  function heatColor(v) {
    if (v === null || v === undefined) return '';
    const hue = Math.round((v / 100) * 130); // red → green
    return `background: hsla(${hue}, 70%, 45%, 0.18); color: hsl(${hue}, 70%, 30%);`;
  }
  function pillFor(outcome, expected, run) {
    if (!outcome) return el('span', { class: 'tl-pill err', text: 'n/a' });
    if (outcome.startsWith('error')) return el('span', { class: 'tl-pill err', text: outcome });
    const caught = CAUGHT.has(outcome);
    if (expected === 'block' && !caught && run && run.model_refused) {
      return el('span', { class: 'tl-pill refused', title: 'No guardrail fired, but Gemini refused to answer', text: 'Gemini refused' });
    }
    let cls = caught ? 'caught' : 'pass';
    if (expected === 'pass' && caught) cls = 'fp';
    if (expected === 'block' && !caught) cls = 'missed';
    return el('span', { class: `tl-pill ${cls}`, text: OUTCOME_TEXT[outcome] || outcome });
  }

  // ---- OWASP frameworks ------------------------------------------------------------------------
  // Every case code belongs to one list; RAI and BENIGN are outside OWASP (responsible AI, controls).
  const FRAMEWORKS = [
    { key: 'llm', match: /^LLM\d+/, label: 'OWASP LLM Top 10 (2025)', short: 'LLM Top 10 · 2025', cls: 'fw-llm' },
    { key: 'api', match: /^API\d+/, label: 'OWASP API Security Top 10 (2023)', short: 'API Top 10 · 2023', cls: 'fw-api' },
    { key: 'rai', match: /^RAI$/, label: 'Responsible AI (beyond OWASP)', short: 'Responsible AI', cls: 'fw-rai' },
    { key: 'benign', match: /^BENIGN$/, label: 'Safe prompts (controls, no attack)', short: 'Safe prompt', cls: 'fw-benign' },
  ];
  const OWASP_NAMES = {
    LLM01: 'Prompt Injection', LLM02: 'Sensitive Information Disclosure', LLM03: 'Supply Chain', LLM04: 'Data and Model Poisoning',
    LLM05: 'Improper Output Handling', LLM06: 'Excessive Agency', LLM07: 'System Prompt Leakage', LLM08: 'Vector and Embedding Weaknesses',
    LLM09: 'Misinformation', LLM10: 'Unbounded Consumption',
    API1: 'Broken Object Level Authorization', API2: 'Broken Authentication', API3: 'Broken Object Property Level Authorization',
    API4: 'Unrestricted Resource Consumption', API5: 'Broken Function Level Authorization', API6: 'Unrestricted Access to Sensitive Business Flows',
    API7: 'Server Side Request Forgery', API8: 'Security Misconfiguration', API9: 'Improper Inventory Management', API10: 'Unsafe Consumption of APIs',
    RAI: 'Harmful content', BENIGN: 'Safe prompt',
  };
  const frameworkOf = (code) => FRAMEWORKS.find((f) => f.match.test(code || '')) || { key: 'other', label: 'Other', short: 'Other', cls: 'fw-other' };
  const fwOrder = (code) => { const i = FRAMEWORKS.indexOf(frameworkOf(code)); return i < 0 ? 99 : i; };
  function owaspCell(code) {
    const fw = frameworkOf(code);
    return el('div', { class: 'tl-owasp' },
      el('span', { class: `tl-fw ${fw.cls}`, title: fw.label, text: fw.short }),
      el('div', { class: 'tl-owasp-item' }, el('b', { text: code }), ' ', OWASP_NAMES[code] || ''));
  }
  // A full-width row that starts each framework section in a table.
  function frameworkRow(fw, n, cols) {
    return el('tr', { class: `tl-fw-row ${fw.cls}` }, el('td', { colspan: String(cols) },
      el('span', { class: `tl-fw ${fw.cls}`, text: fw.short }), el('b', { text: fw.label }), el('span', { class: 'tl-fw-count', text: `${n} case${n === 1 ? '' : 's'}` })));
  }

  // ---- summary sections ----------------------------------------------------------------------
  function renderSummary() {
    const s = data.summary;
    const h = s.headline;
    const when = new Date(data.run_at);
    const apiN = data.cases.filter((c) => c.direction === 'api').length;
    const range = (r) => (r ? ` · 95% range ${Math.round(r[0])}–${Math.round(r[1])}%` : '');
    $('tlMeta').textContent = `run "${data.label}" · ${when.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}`;
    $('tlMeta').title = `${data.duration_s}s · target /${data.target}`;
    $('tlHeroTitle').textContent = SUITES[SET].hero;
    $('tlFootnote').textContent = SUITES[SET].footnote;
    $('tlHeroCounts').textContent = data.set === 'extended'
      ? `${data.cases.length} cases from public datasets and generated variants (${h.attacks} attacks, ${h.benign} safe prompts)`
      : `${data.cases.length} hand-written test cases (${h.attacks} attacks, ${h.benign} safe prompts)`;
    const fpN = (s.false_positives_all_on || []).length;
    const kpis = [
      { label: 'Caught with all layers on', value: fmtPct(h.defense_in_depth_pct),
        note: `of ${h.attacks} attacks${apiN ? ` (incl. ${apiN} API cases)` : ''}${range(h.defense_range)}`, cls: h.defense_in_depth_pct >= 90 ? 'good' : 'warn' },
      { label: 'Safe prompts blocked', value: `${fpN} / ${h.benign}`,
        note: `false-positive rate ${fmtPct(h.false_positive_pct)}${range(h.false_positive_range)}`, cls: fpN ? 'bad' : 'good' },
      { label: 'Missed with all layers on', value: String(missedAllOn(s).length),
        note: (s.model_refused || []).length ? `${s.model_refused.length} of them refused by Gemini itself · see Gaps` : 'listed under Gaps below',
        cls: missedAllOn(s).length ? 'warn' : 'good' },
      { label: 'Best single layer', value: bestLayer(s), note: `on its own, of the ${s.layers.static.of} prompt / answer attacks`, cls: '' },
    ];
    $('tlKpis').replaceChildren(...kpis.map((k) => el('div', { class: `tl-kpi ${k.cls}` },
      el('div', { class: 'tl-kpi-label', text: k.label }), el('div', { class: 'tl-kpi-value', text: k.value }),
      el('div', { class: 'tl-kpi-note', text: k.note }))));
    renderHoldout(s);

    const llmN = s.layers.static.of;
    $('tlLayersSub').textContent = `Static, Model Armor and NeMo: % of the ${llmN} prompt / answer attacks each blocks alone`
      + (apiN ? `. Apigee platform: % of the ${s.layers.apigee.of} API-security cases.` : '. This set has no API-security cases.');
    $('tlLayers').replaceChildren(...LAYERS.filter((L) => L.key !== 'apigee' || apiN).map((L) => {
      const v = s.layers[L.key];
      const fp = v.fp_pct !== undefined && v.fp_pct !== null ? `${v.false_positives.length} safe blocked (${fmtPct(v.fp_pct)})` : `${v.false_positives.length} false pos.`;
      const meta = L.key === 'apigee' ? `${v.caught}/${v.of} API cases`
        : `${v.caught}/${v.of}${v.range ? ` (${Math.round(v.range[0])}–${Math.round(v.range[1])}%)` : ''} · ${fp} · ~${v.median_ms ?? '?'} ms round trip`;
      return el('div', { class: 'tl-layer' },
        el('div', { class: 'tl-layer-name' }, el('img', { src: L.img, alt: '' }), L.name),
        el('div', { class: 'tl-bar', role: 'img', 'aria-label': `${L.name} ${fmtPct(v.pct)}` },
          el('span', { class: L.cls, style: `width:${v.pct || 0}%` }), el('b', { text: fmtPct(v.pct) })),
        el('div', { class: 'tl-layer-meta', text: meta }));
    }));

    // first catch
    const fc = s.first_catch || {};
    const total = Object.values(fc).reduce((a, b) => a + b, 0) || 1;
    const order = [['static', 'Static', 'c-static'], ['model_armor', 'Model Armor', 'c-ma'], ['nemo', 'NeMo', 'c-nemo'], ['apigee', 'Apigee', 'c-apigee']];
    $('tlFirst').replaceChildren(
      el('div', { class: 'tl-stack' }, ...order.filter(([k]) => fc[k]).map(([k, , c]) =>
        el('span', { class: c, style: `width:${(100 * fc[k]) / total}%`, title: `${fc[k]} cases`, text: String(fc[k]) }))),
      el('div', { class: 'tl-legend' }, ...order.map(([k, label, c]) => el('span', {}, el('i', { class: c }), `${label} ${fc[k] || 0}`))));

    // unique catches
    const uq = s.unique_catches || {};
    $('tlUnique').replaceChildren(...['static', 'model_armor', 'nemo'].map((k) => {
      const ids = uq[k] || [];
      const name = LAYERS.find((l) => l.key === k).name;
      return el('div', {}, el('div', { class: 'tl-group-title', text: `${name}: ${ids.length}` }), chips(ids));
    }));

    // gaps
    const refused = new Set(s.model_refused || []);
    const missed = missedAllOn(s);
    $('tlGaps').replaceChildren(
      el('div', { class: 'tl-group-title', text: `Missed with all layers on: ${missed.length}` }),
      chips(missed.filter((i) => !refused.has(i))),
      refused.size ? el('div', { class: 'tl-group-title tl-refused-title', text: `…of which Gemini refused on its own (no guardrail fired): ${refused.size}` }) : null,
      refused.size ? chips([...refused], 'refused') : null,
      el('div', { class: 'tl-group-title', text: `Missed by every layer, even tested alone: ${s.missed_by_all.length}` }), chips(s.missed_by_all),
      el('div', { class: 'tl-group-title', text: `Safe prompts blocked (all on): ${fpN}` }), chips(s.false_positives_all_on || []),
      el('div', { class: 'tl-group-title', text: `Inconsistent between runs: ${(s.flaky || []).length}` }), chips(s.flaky || []));
  }
  // Held-out vs tuning + per-source rows (extended set only).
  function renderHoldout(s) {
    const card = $('tlHoldoutCard');
    if (!card) return;
    if (!s.holdout) { card.hidden = true; return; }
    card.hidden = false;
    const r = (x) => (x ? `${Math.round(x[0])}–${Math.round(x[1])}%` : '');
    const head = el('tr', {}, ...['Subset', 'Cases', 'Caught, all on', 'Static', 'Model Armor', 'NeMo', 'Safe blocked, all on', 'Safe blocked by Static / MA / NeMo']
      .map((t) => el('th', { text: t })));
    const row = (label, x, strong) => el('tr', { class: strong ? 'tl-holdout-main' : '' },
      el('td', {}, strong ? el('b', { text: label }) : label),
      el('td', { text: `${x.attacks} + ${x.benign} safe` }),
      el('td', { text: `${fmtPct(x.defense_in_depth_pct)}  (${r(x.defense_range)})` }),
      el('td', { text: fmtPct(x.static_pct) }), el('td', { text: fmtPct(x.model_armor_pct) }), el('td', { text: fmtPct(x.nemo_pct) }),
      el('td', { text: x.benign ? `${fmtPct(x.false_positive_pct)}  (${r(x.false_positive_range)})` : '—' }),
      el('td', { text: x.benign ? `${fmtPct(x.static_fp_pct)} / ${fmtPct(x.model_armor_fp_pct)} / ${fmtPct(x.nemo_fp_pct)}` : '—' }));
    const rows = [row('Held-out (never tuned)', s.holdout.held_out, true), row('Tuning', s.holdout.tuning)];
    (s.by_source || []).forEach((x) => rows.push(row(`Source: ${x.source}`, x)));
    $('tlHoldout').replaceChildren(el('thead', {}, head), el('tbody', {}, ...rows));
  }
  // Older result files have no missed_all_on: derive it from the verdicts.
  function missedAllOn(s) {
    if (s.missed_all_on) return s.missed_all_on;
    return data.cases.filter((c) => c.expected === 'block' && !(s.verdicts[c.id] || {}).caught).map((c) => c.id);
  }
  function bestLayer(s) {
    const best = ['static', 'model_armor', 'nemo'].map((k) => [k, s.layers[k].pct || 0]).sort((a, b) => b[1] - a[1])[0];
    return `${{ static: 'Static', model_armor: 'Model Armor', nemo: 'NeMo' }[best[0]]} ${fmtPct(best[1])}`;
  }
  function chips(ids, cls = '') {
    if (!ids.length) return el('div', { class: 'tl-kv', text: 'None' });
    return el('div', { class: 'tl-chips' }, ...ids.map((id) => el('button', { type: 'button', class: `tl-chip ${cls}`, text: id, onclick: () => focusCase(id) })));
  }

  // ---- heatmap -------------------------------------------------------------------------------
  function renderHeat() {
    const cov = Object.fromEntries((data.coverage || []).map((c) => [c.id, c.name]));
    const rows = data.summary.by_owasp;
    const head = el('tr', {}, ...['OWASP item', 'Cases', 'Static', 'Model Armor', 'NeMo', 'Apigee', 'All on'].map((t) => el('th', { text: t })));
    const openOwasp = (id) => {
      ['fSearch', 'fFramework', 'fGroup', 'fResult', 'fLang'].forEach((f) => { $(f).value = ''; });
      $('fOwasp').value = id;
      openId = null;
      renderCases();
      switchTab('results');
    };
    const sorted = rows.map((r, i) => [r, i]).sort((a, b) => fwOrder(a[0].owasp) - fwOrder(b[0].owasp) || a[1] - b[1]).map(([r]) => r);
    const body = [];
    let lastFw = null;
    sorted.forEach((r) => {
      const fw = frameworkOf(r.owasp);
      if (fw.key !== lastFw) {
        const n = sorted.filter((x) => frameworkOf(x.owasp).key === fw.key).reduce((a, x) => a + x.n, 0);
        body.push(frameworkRow(fw, n, 7)); lastFw = fw.key;
      }
      body.push(heatRow(r));
    });
    function heatRow(r) { return el('tr', { class: 'tl-row', tabindex: '0', title: `Show the ${r.owasp} cases`,
      onclick: () => openOwasp(r.owasp), onkeydown: (e) => { if (e.key === 'Enter') openOwasp(r.owasp); } },
      el('td', {}, el('b', { text: r.owasp }), ' ', cov[r.owasp] || OWASP_NAMES[r.owasp] || ''),
      el('td', { text: String(r.n) }),
      ...['static', 'model_armor', 'nemo', 'apigee', 'defense'].map((k) => el('td', {
        class: `tl-heat ${r[k] === null ? 'na' : ''}`, style: heatColor(r[k]), text: r[k] === null ? '—' : fmtPct(r[k]) }))); }
    $('tlHeat').replaceChildren(el('thead', {}, head), el('tbody', {}, ...body));
  }

  // ---- cases table ---------------------------------------------------------------------------
  function verdictOf(c) { return data.summary.verdicts[c.id] || {}; }
  function resultKey(c) {
    const v = verdictOf(c);
    if (c.expected === 'pass') return v.caught ? 'fp' : 'benign-ok';
    return v.caught ? 'caught' : 'missed';
  }
  function filtered() {
    const q = $('fSearch').value.trim().toLowerCase();
    const fw = $('fFramework').value;
    const o = $('fOwasp').value, g = $('fGroup').value, r = $('fResult').value, l = $('fLang').value;
    return data.cases.filter((c) => {
      if (fw && frameworkOf(c.owasp).key !== fw) return false;
      if (o && c.owasp !== o) return false;
      if (g && c.group !== g) return false;
      if (l && c.language !== l) return false;
      if (r === 'flaky' ? !verdictOf(c).flaky : (r && resultKey(c) !== r)) return false;
      if (q && !`${c.id} ${c.title} ${c.technique} ${c.group} ${c.owasp} ${OWASP_NAMES[c.owasp] || ''}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }
  // A "failure" worth explaining: an attack that got through with all layers on, or a safe prompt that was blocked.
  const failureOf = (c) => {
    if (c.direction === 'api') return null;
    const k = resultKey(c);
    return k === 'missed' ? 'missed' : k === 'fp' ? 'fp' : null;
  };
  let page = 1;
  let pageSize = 50;
  function sortedFiltered() {
    // Grouped by framework (LLM Top 10, API Top 10, then beyond-OWASP); suite order kept inside each group.
    return filtered().map((c, i) => [c, i]).sort((a, b) => fwOrder(a[0].owasp) - fwOrder(b[0].owasp) || a[1] - b[1]).map(([c]) => c);
  }
  function renderQuick() {
    const n = (key) => data.cases.filter((c) => (key === 'flaky' ? verdictOf(c).flaky : resultKey(c) === key)).length;
    const cur = $('fResult').value;
    const items = [['', `All ${data.cases.length}`], ['missed', `Attacks missed ${n('missed')}`], ['fp', `Safe prompts blocked ${n('fp')}`],
      ['caught', `Attacks caught ${n('caught')}`], ['flaky', `Flaky ${n('flaky')}`]];
    $('tlQuick').replaceChildren(el('span', { class: 'tl-quick-label', text: 'Show:' }), ...items.map(([v, label]) =>
      el('button', { type: 'button', class: `tl-quick-btn ${v || 'all'}${cur === v ? ' on' : ''}`, 'aria-pressed': String(cur === v), text: label,
        onclick: () => { $('fResult').value = v; page = 1; renderCases(); } })));
  }
  function renderPager(total) {
    const pages = pageSize ? Math.max(1, Math.ceil(total / pageSize)) : 1;
    if (page > pages) page = pages;
    const go = (p) => { page = p; renderCases(); $('tlCases').scrollIntoView({ behavior: 'smooth', block: 'start' }); };
    const nums = [];
    for (let p = 1; p <= pages; p++) {
      if (p === 1 || p === pages || Math.abs(p - page) <= 2) nums.push(p);
      else if (nums[nums.length - 1] !== '…') nums.push('…');
    }
    const from = total ? (pageSize ? (page - 1) * pageSize + 1 : 1) : 0;
    const to = pageSize ? Math.min(total, page * pageSize) : total;
    $('tlPager').replaceChildren(
      el('span', { class: 'tl-pager-info', text: `${from}–${to} of ${total}` }),
      el('button', { type: 'button', class: 'tl-btn', disabled: page <= 1, text: '‹ Prev', onclick: () => go(page - 1) }),
      ...nums.map((p) => (p === '…' ? el('span', { class: 'tl-pager-gap', text: '…' })
        : el('button', { type: 'button', class: `tl-btn tl-pager-num${p === page ? ' on' : ''}`, 'aria-current': p === page ? 'page' : null, text: String(p), onclick: () => go(p) }))),
      el('button', { type: 'button', class: 'tl-btn', disabled: page >= pages, text: 'Next ›', onclick: () => go(page + 1) }),
      el('label', { class: 'tl-pager-size' }, 'Rows per page ',
        el('select', { 'aria-label': 'Rows per page', onchange: (e) => { pageSize = Number(e.target.value); page = 1; renderCases(); } },
          ...[25, 50, 100, 0].map((n) => { const o = el('option', { value: String(n), text: n ? String(n) : 'All' }); if (n === pageSize) o.selected = true; return o; }))));
    $('tlPager').hidden = total <= 25; // one short page: no pager needed
  }
  function renderCases() {
    const list = sortedFiltered();
    $('fCount').textContent = `${list.length} of ${data.cases.length}`;
    renderQuick();
    renderPager(list.length);
    const shown = pageSize ? list.slice((page - 1) * pageSize, page * pageSize) : list;
    const COLS = 11;
    const head = el('tr', {}, ...['ID', 'Case', 'Category', 'OWASP', 'Lang', 'Expected', 'Static', 'Model Armor', 'NeMo', 'All on / API', 'Why?'].map((t) => el('th', { text: t })));
    const perFw = {};
    list.forEach((c) => { const k = frameworkOf(c.owasp).key; perFw[k] = (perFw[k] || 0) + 1; });
    const rows = [];
    let lastFw = null;
    shown.forEach((c) => {
      const fw = frameworkOf(c.owasp);
      if (fw.key !== lastFw) { rows.push(frameworkRow(fw, perFw[fw.key], COLS)); lastFw = fw.key; }
      const r = c.runs || {};
      const main = r.D || r.A || {};
      const fail = failureOf(c);
      const row = el('tr', { class: `tl-row ${openId === c.id ? 'open' : ''}${fail ? ` fail-${fail}` : ''}`, id: `case-${c.id}`, tabindex: '0',
        onclick: () => toggle(c.id), onkeydown: (e) => { if (e.key === 'Enter') toggle(c.id); } },
        el('td', {}, el('b', { text: c.id })),
        el('td', {}, c.title, el('div', { class: 'tl-kv', text: c.technique })),
        el('td', { text: c.group }),
        el('td', {}, owaspCell(c.owasp)), el('td', { text: c.language }),
        el('td', {}, el('span', { class: `tl-pill ${c.expected === 'pass' ? 'pass' : 'caught'}`, text: c.expected })),
        el('td', {}, c.direction === 'api' ? '—' : pillFor(r.S && r.S.outcome, c.expected)),
        el('td', {}, c.direction === 'api' ? '—' : pillFor(r.M && r.M.outcome, c.expected)),
        el('td', {}, c.direction === 'api' ? '—' : pillFor(r.N && r.N.outcome, c.expected)),
        el('td', {}, pillFor(main.outcome, c.expected, main), verdictOf(c).flaky ? el('span', { class: 'tl-pill err', text: 'flaky', style: 'margin-left:4px' }) : null),
        el('td', {}, fail ? el('button', { type: 'button', class: `tl-why-btn ${fail}`, title: fail === 'missed' ? 'Why did this attack get through?' : 'Why was this safe prompt blocked?',
          text: 'Explain ›', onclick: (e) => { e.stopPropagation(); openWhy(c.id); } }) : null));
      rows.push(row);
      if (openId === c.id) rows.push(detailRow(c));
    });
    $('tlCases').replaceChildren(el('thead', {}, head), el('tbody', {}, ...(rows.length ? rows : [el('tr', {}, el('td', { colspan: String(COLS), class: 'tl-empty', text: 'No cases match these filters.' }))])));
  }
  function detailRow(c) {
    const r = c.runs || {};
    const promptText = c.prompt !== undefined ? c.prompt
      : c.contents ? c.contents.map((t) => `[${t.role}] ${t.parts.map((p) => p.text).join(' | ')}`).join('\n')
        : JSON.stringify(c.api, null, 1).slice(0, 1500);
    const runRows = [];
    const runName = { S: 'Static only', M: 'Model Armor only', N: 'NeMo only', D: 'All layers on', A: 'API test' };
    Object.entries(r).forEach(([k, v]) => {
      const extra = [];
      if (v.detail) extra.push(friendlyDetail(v.detail));
      if (v.headers && v.headers['x-sg-rules']) extra.push(`rules: ${v.headers['x-sg-rules']}`);
      if (v.headers && v.headers['x-sg-flags']) extra.push(`flagged: ${v.headers['x-sg-flags']}`);
      if (k === 'N' && v.rails) extra.push(Object.entries(v.rails).map(([rail, x]) => `${rail}: ${x.outcome}`).join(' · '));
      if (k === 'D' && v.nemo_profile) extra.push(`NeMo: ${v.nemo_profile}`);
      if (v.retries) extra.push(`re-runs: ${v.retries.join(', ')}`);
      if (v.statuses) extra.push(`HTTP ${v.statuses.join(', ')}`);
      if (v.leaked && v.leaked.length) extra.push(`leaked: ${v.leaked.join(', ')}`);
      runRows.push(el('tr', {}, el('td', { text: runName[k] || k }), el('td', {}, pillFor(v.outcome, c.expected)),
        el('td', { text: v.ms !== undefined ? `${v.ms} ms` : '' }), el('td', { text: extra.join(' · ') })));
    });
    const excerpt = (r.D && r.D.output_excerpt) || (r.S && r.S.output_excerpt) || '';
    return el('tr', { class: 'tl-detail' }, el('td', { colspan: '10' },
      el('div', { class: 'tl-detail-grid' },
        el('div', {},
          el('div', { class: 'tl-kv' }, el('b', { text: 'Group: ' }), c.group, ' · ', el('b', { text: 'Severity: ' }), c.severity,
            ' · ', el('b', { text: 'Direction: ' }), c.direction),
          el('div', { class: 'tl-kv' }, el('b', { text: 'Expected layers: ' }), c.expected_layers.join(', ')),
          c.notes ? el('div', { class: 'tl-kv' }, el('b', { text: 'Notes: ' }), c.notes) : null,
          el('div', { class: `tl-prompt ${reveal || !isSensitive(c) ? '' : 'masked'}`, title: reveal || !isSensitive(c) ? '' : 'Click "Show prompts" to reveal', text: promptText }),
          excerpt ? el('div', { class: 'tl-kv' }, el('b', { text: 'Model output (excerpt): ' }), el('span', { class: reveal ? '' : 'tl-prompt masked', text: excerpt })) : null,
          c.prompt !== undefined ? el('button', { type: 'button', class: 'tl-btn primary', style: 'margin-top:8px', text: 'Open in playground',
            onclick: (e) => { e.stopPropagation(); openInPlayground(c); } }) : null),
        el('div', {}, el('table', { class: 'tl-runs' }, el('tbody', {}, ...runRows))))));
  }
  function toggle(id) {
    openId = openId === id ? null : id;
    history.replaceState(null, '', openId ? `#results/${openId}` : '#results');
    renderCases();
  }
  // Show one case in the Results tab (clears filters so it is visible).
  function focusCase(id) {
    if (!location.hash.startsWith(`#results/${id}`)) { location.hash = `results/${id}`; return; } // route() does the rest
    ['fSearch', 'fFramework', 'fOwasp', 'fGroup', 'fResult', 'fLang'].forEach((f) => { $(f).value = ''; });
    openId = id;
    const idx = sortedFiltered().findIndex((c) => c.id === id);
    if (pageSize && idx >= 0) page = Math.floor(idx / pageSize) + 1;
    renderCases();
    const row = document.getElementById(`case-${id}`);
    if (row) requestAnimationFrame(() => row.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  }

  // ---- "Why?" drawer ---------------------------------------------------------------------------
  // Explanations live in testlab/case-notes.json (analysis + tested evidence); cases without a note get an
  // automatic explanation from the run data.
  let notes = null;
  let whyId = null;
  let whyReveal = false;
  let whyReturnFocus = null;
  const loadNotes = () => (notes ? Promise.resolve(notes)
    : getJson('testlab/case-notes.json').then((j) => (notes = j)).catch(() => (notes = { cases: {}, classes: {}, why: {} })));
  const LAYER_NAMES = { static: 'Static Guardrails', model_armor: 'Model Armor', nemo: 'NVIDIA NeMo' };
  const RESULT_TEXT = { yes: '✓ catches it', likely: '≈ likely', partly: '◐ partly', no: '✗ no' };

  function section(title, ...children) {
    return el('section', { class: 'tl-why-sec' }, el('h3', { text: title }), ...children);
  }
  function whyContent(c, n) {
    const r = c.runs || {};
    const fail = failureOf(c);
    const cls = n && notes.classes[n.cls];
    const parts = [];
    // Verdict
    parts.push(el('div', { class: 'tl-why-verdict' },
      el('span', { class: `tl-why-class ${n ? n.cls : 'auto'}`, text: cls ? cls.label : (fail === 'fp' ? 'Safe prompt blocked' : 'Not analysed yet') }),
      el('p', { text: n ? n.summary : (fail === 'fp' ? 'A safe prompt was blocked with all layers on.' : 'An attack got through with all layers on.') }),
      cls ? el('p', { class: 'tl-why-classdesc', text: cls.desc }) : null));
    // Prompt
    const masked = !whyReveal && isSensitive(c);
    parts.push(section('The prompt',
      el('div', { class: `tl-prompt ${masked ? 'masked' : ''}`, text: c.prompt || '' }),
      el('div', { class: 'tl-why-actions' },
        isSensitive(c) ? el('button', { type: 'button', class: 'tl-btn', text: masked ? 'Show prompt' : 'Hide prompt',
          onclick: () => { whyReveal = !whyReveal; renderWhy(); } }) : null,
        c.prompt !== undefined ? el('button', { type: 'button', class: 'tl-btn primary', text: 'Open in playground', onclick: () => openInPlayground(c) }) : null)));
    // This run
    const rails = r.N && r.N.rails ? Object.entries(r.N.rails).map(([k, v]) => `${k}: ${v.outcome}`).join(' · ') : '';
    parts.push(section(`Result in this run (${PROFILES[SUITE.profile].label})`,
      el('table', { class: 'tl-why-runs' }, el('tbody', {},
        ...[['S', 'Static only'], ['M', 'Model Armor only'], ['N', 'NeMo only'], ['D', 'All layers on']].filter(([k]) => r[k]).map(([k, label]) =>
          el('tr', {}, el('td', { text: label }), el('td', {}, pillFor(r[k].outcome, c.expected, r[k])),
            el('td', { class: 'tl-why-muted', text: k === 'N' ? rails : k === 'S' ? (r.S.headers && r.S.headers['x-sg-rules']) || 'no rule matched' : (r[k].detail ? friendlyDetail(r[k].detail) : '') })))))));
    if (fail === 'missed') {
      const why = n ? notes.why[n.cls] : null;
      parts.push(section('Why each layer let it through', el('ul', { class: 'tl-why-list' },
        ...['static', 'model_armor', 'nemo'].map((k) => el('li', {}, el('b', { text: `${LAYER_NAMES[k]}: ` }),
          why ? why[k] : 'No layer flagged it in this run; see the per-layer results above.')))));
    }
    if (n && n.violation) parts.push(section('Is it really a violation?', el('p', { text: n.violation })));
    if (n && n.answer) parts.push(section('What Gemini answered (re-tested)', el('div', { class: `tl-prompt ${whyReveal ? '' : 'masked'}`, text: `${n.answer}${n.answer.length >= 600 ? '…' : ''}` })));
    // Provenance
    const pv = n ? n.provenance : null;
    const src = c.source || {};
    const where = pv && pv.split !== undefined ? `${pv.split} split, row ${pv.row}${pv.label !== undefined ? ` · label ${pv.label} (${pv.label ? 'injection' : 'safe'})` : ''}`
      : pv && pv.index ? `behaviour #${pv.index} (${pv.behavior}, ${pv.category})` : pv && pv.id ? `prompt id ${pv.id} (${pv.type}, ${pv.label})` : '';
    parts.push(section('Where it comes from',
      el('p', {}, el('b', { text: src.dataset || 'Curated suite' }), src.license ? ` · ${src.license}` : '', where ? ` · ${where}` : ''),
      (pv && pv.url) || src.url ? el('p', {}, el('a', { href: (pv && pv.url) || src.url, target: '_blank', rel: 'noopener noreferrer', text: 'View the original ↗' })) : null,
      String(src.dataset || '').startsWith('deepset') && notes.deepset_note ? el('p', { class: 'tl-why-muted', text: notes.deepset_note }) : null));
    // How to catch it
    if (n) {
      const ma = n.model_armor_direct || {};
      const nemo = n.nemo_live || {};
      const blocks = Object.entries(nemo).filter(([, v]) => v === 'nemo').map(([k]) => k);
      const rows = [
        { option: 'Model Armor: stricter template', result: Object.values(ma).some((v) => v.match === 'MATCH_FOUND') ? 'yes' : 'no',
          note: `Direct check: ${Object.entries(ma).map(([t, v]) => `${t} ${v.match === 'MATCH_FOUND' ? 'MATCH' : 'no match'}`).join(' · ')}. Strict is already the most sensitive level.` },
        { option: 'NeMo jailbreak / content-safety rails (current)', result: nemo.jailbreak_self_check === 'nemo' || nemo.content_safety === 'nemo' ? 'yes' : 'no', note: 'Re-tested live.' },
        { option: 'NeMo business-persona rail (bank / retail / airline)', result: ['topic_bank', 'topic_retail', 'topic_airline'].every((k) => nemo[k] === 'nemo') ? 'yes' : 'no',
          note: `Re-tested live. Blocked by: ${blocks.join(', ') || 'none'}.` },
        ...(n.extra || []).filter((x) => !/persona rail/.test(x.option)),
      ];
      parts.push(section('Could the current setup catch it?',
        el('table', { class: 'tl-why-opts' }, el('tbody', {}, ...rows.map((x) => el('tr', {},
          el('td', { text: x.option }), el('td', {}, el('span', { class: `tl-why-res ${x.result}`, text: RESULT_TEXT[x.result] || x.result })),
          el('td', { class: 'tl-why-muted', text: x.note }))))),
        el('p', { class: 'tl-why-muted', text: `Evidence re-tested on ${new Date(notes.updated).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })} against ${notes.target}.` })));
      parts.push(section('Recommendation', el('p', { class: 'tl-why-reco', text: n.recommend })));
      if (n.related && n.related.length) {
        parts.push(section('Related cases', el('div', { class: 'tl-chips' }, ...n.related.map((id) =>
          el('button', { type: 'button', class: 'tl-chip tl-chip-link', text: id, onclick: () => openWhy(id) })))));
      }
    } else {
      parts.push(section('Analysis', el('p', { class: 'tl-why-muted', text: 'No written analysis for this case yet. The per-layer results above show what each layer decided in this run.' })));
    }
    return parts;
  }
  function renderWhy() {
    const c = data.cases.find((x) => x.id === whyId);
    if (!c) return;
    const n = notes.cases[c.id];
    $('tlWhyKicker').textContent = `${c.id} · ${suiteName(SUITE)}`;
    $('tlWhyTitle').textContent = failureOf(c) === 'fp' ? `Why was "${c.title}" blocked?` : `Why did "${c.title}" get through?`;
    $('tlWhyBody').replaceChildren(...whyContent(c, n));
  }
  function openWhy(id, fromRoute) {
    whyReturnFocus = document.activeElement;
    whyId = id;
    whyReveal = false;
    loadNotes().then(() => {
      renderWhy();
      $('tlWhy').hidden = false;
      $('tlWhyBackdrop').hidden = false;
      document.documentElement.classList.add('tl-drawer-open');
      $('tlWhyBody').scrollTop = 0;
      $('tlWhyClose').focus();
      if (!fromRoute) history.replaceState(null, '', `#results/${id}/why`);
    });
  }
  function closeWhy() {
    if ($('tlWhy').hidden) return;
    $('tlWhy').hidden = true;
    $('tlWhyBackdrop').hidden = true;
    document.documentElement.classList.remove('tl-drawer-open');
    history.replaceState(null, '', openId ? `#results/${openId}` : '#results');
    if (whyReturnFocus && document.contains(whyReturnFocus)) whyReturnFocus.focus();
    whyId = null;
  }
  $('tlWhyClose').addEventListener('click', closeWhy);
  $('tlWhyBackdrop').addEventListener('click', closeWhy);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeWhy(); });
  function toast(msg) {
    const t = $('tlToast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.hidden = true; }, 3500);
  }
  // Send a case to the playground. If a playground tab is open it answers on the channel and
  // loads the prompt in place (no reload); otherwise fall back to opening it in this tab.
  const channel = 'BroadcastChannel' in window ? new BroadcastChannel('guardrail-testlab') : null;
  function openInPlayground(c) {
    const msg = { type: 'open-case', id: c.id, prompt: c.prompt, nemo_profile: c.nemo_profile || null, at: Date.now() };
    const fallback = () => {
      localStorage.setItem('testlabHandoff', JSON.stringify(msg));
      window.location.href = 'index.html';
    };
    if (!channel) return fallback();
    let acked = false;
    const onAck = (e) => {
      if (e.data && e.data.type === 'case-loaded' && e.data.id === c.id) {
        acked = true;
        channel.removeEventListener('message', onAck);
        try { if (window.opener && !window.opener.closed) window.opener.focus(); } catch (ignore) { /* cross-tab focus may be blocked */ }
        toast(`${c.id} loaded in the playground tab. Switch to it to run the case.`);
      }
    };
    channel.addEventListener('message', onAck);
    channel.postMessage(msg);
    setTimeout(() => { if (!acked) { channel.removeEventListener('message', onAck); fallback(); } }, 400);
  }

  // ---- test catalogue (all cases, grouped by category) ----------------------------------------
  const CATEGORY_INFO = {
    'Prompt injection & jailbreak': 'Attempts to override the assistant\'s instructions: direct overrides, role-play personas, encoded or disguised text, other languages, and instructions hidden in documents or earlier messages.',
    'Sensitive information disclosure': 'Personal data and secrets in the prompt, or prompts that coax the model into printing them in its answer.',
    'Improper output handling': 'Prompts that make the model output content that is dangerous downstream: scripts, SQL, shell commands and data-leaking links.',
    'Excessive agency': 'Instructions aimed at an AI agent to take harmful or unapproved actions with its tools.',
    'System prompt leakage': 'Attempts to extract the hidden system instructions, directly or by translating, summarising or echoing them.',
    'Misinformation': 'Requests for authoritative claims outside the assistant\'s role, fabricated evidence, or false news.',
    'Unbounded consumption': 'Oversized or amplifying requests that waste tokens and compute.',
    'Business policy': 'Safe questions that are off-limits for a specific business persona (NeMo topic rails).',
    'Harmful content (responsible AI)': 'Hate, harassment, threats, dangerous activities, sexual content and self-harm. Not an OWASP item, but core to responsible AI.',
    'API security': 'Gateway-level checks: authentication, request overrides, size and rate limits, SSRF and error handling.',
    'Benign control': 'Safe prompts that must pass every layer. They measure false positives.',
  };
  const LAYER_LABEL = { static: 'Static', model_armor: 'Model Armor', nemo: 'NeMo', apigee: 'Apigee' };
  let catReveal = false;
  const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-');

  function promptOf(c) {
    if (c.prompt !== undefined) return c.prompt;
    if (c.contents) return c.contents.map((t) => `[${t.role}] ${t.parts.map((p) => p.text).join(' | ')}`).join('\n');
    const a = c.api || {};
    const req = [`${a.method || 'POST'} /guardrail-proxy`, `API key: ${a.key || 'header'}`];
    if (a.burst) req.push(`Sent ${a.burst} times in a row`);
    if (a.raw_body) req.push(`Raw body: ${a.raw_body}`);
    else if (a.body) {
      const extra = Object.keys(a.body).filter((k) => k !== 'contents');
      const text = ((a.body.contents || [{}])[0].parts || [{}])[0].text || '';
      req.push(`Prompt: ${text.length > 120 ? `${text.slice(0, 120)}… (${text.length} chars)` : text}`);
      if (extra.length) req.push(`Extra body fields: ${extra.join(', ')}`);
    }
    req.push(`Pass if HTTP ${a.expect_status.join(' or ')}`);
    return req.join('\n');
  }

  function catalogueCard(c) {
    const v = verdictOf(c);
    const main = (c.runs || {}).D || (c.runs || {}).A || {};
    const tags = [`${c.owasp} · ${frameworkOf(c.owasp).label}`, c.language, `severity: ${c.severity}`, c.direction, c.nemo_profile ? `persona: ${c.nemo_profile.replace('topic_', '')}` : null].filter(Boolean);
    return el('article', { class: 'tl-cat-case', id: `cat-${c.id}` },
      el('header', { class: 'tl-cat-case-head' },
        el('b', { class: 'tl-cat-id', text: c.id }),
        el('span', { class: 'tl-cat-title', text: c.title }),
        el('span', { class: `tl-pill ${c.expected === 'pass' ? 'pass' : 'caught'}`, text: c.expected === 'pass' ? 'must pass' : 'must block' })),
      el('div', { class: 'tl-cat-tags' }, ...tags.map((t) => el('span', { class: 'tl-cat-tag', text: t }))),
      el('div', { class: 'tl-kv' }, el('b', { text: 'Technique: ' }), c.technique),
      el('div', { class: 'tl-kv' }, el('b', { text: 'Expected to be caught by: ' }), c.expected_layers.map((l) => LAYER_LABEL[l] || l).join(', ')),
      c.notes ? el('div', { class: 'tl-kv' }, el('b', { text: 'Notes: ' }), c.notes) : null,
      el('div', { class: `tl-prompt ${catReveal || !isSensitive(c) ? '' : 'masked'}`, text: promptOf(c) }),
      el('div', { class: 'tl-cat-result' },
        el('span', { text: 'Latest result (all on): ' }), pillFor(main.outcome, c.expected, main),
        v.first ? el('span', { class: 'tl-kv', text: ` first caught by ${LAYER_LABEL[v.first] || v.first}` }) : null,
        el('button', { type: 'button', class: 'tl-btn', text: 'Per-layer results', onclick: () => showInResults(c.id) })));
  }

  function renderCatalogue() {
    const q = $('cSearch').value.trim().toLowerCase();
    const g = $('cGroup').value;
    const groups = new Map();
    data.cases.forEach((c) => {
      if (g && c.group !== g) return;
      if (q && !`${c.id} ${c.title} ${c.technique} ${c.group} ${c.owasp} ${c.notes || ''}`.toLowerCase().includes(q)) return;
      if (!groups.has(c.group)) groups.set(c.group, []);
      groups.get(c.group).push(c);
    });
    const shown = [...groups.values()].reduce((n, cs) => n + cs.length, 0);
    const total = data.cases.length;
    $('cCount').textContent = `${shown} of ${total}`;
    const nCat = groups.size;
    const totalLabel = shown === total
      ? `${total} cases in ${nCat} categories:`
      : `Showing ${shown} of ${total} cases in ${nCat} ${nCat === 1 ? 'category' : 'categories'}:`;
    $('cNav').replaceChildren(el('span', { class: 'tl-cat-total', text: totalLabel }), ...[...groups.entries()].map(([name, cs]) =>
      el('a', { href: `#cat-group-${slug(name)}`, class: 'tl-chip', text: `${name} (${cs.length})`,
        onclick: (e) => { e.preventDefault(); document.getElementById(`cat-group-${slug(name)}`).scrollIntoView({ behavior: 'smooth', block: 'start' }); } })));
    const sections = [...groups.entries()].map(([name, cs]) => {
      const owasp = [...new Set(cs.map((c) => c.owasp))].join(', ');
      const caught = cs.filter((c) => c.expected === 'block' && verdictOf(c).caught).length;
      const attacks = cs.filter((c) => c.expected === 'block').length;
      const summary = attacks ? `${caught}/${attacks} caught with all layers on`
        : `${cs.filter((c) => !verdictOf(c).caught).length}/${cs.length} passed (no false alarms)`;
      return el('section', { class: 'tl-cat-group', id: `cat-group-${slug(name)}` },
        el('div', { class: 'tl-cat-group-head' },
          el('h3', { text: `${name} · ${cs.length} of ${total} cases` }),
          el('span', { class: 'tl-cat-owasp', text: owasp }),
          el('span', { class: 'tl-cat-score', text: summary })),
        el('p', { class: 'tl-sub', text: CATEGORY_INFO[name] || '' }),
        el('div', { class: 'tl-cat-list' }, ...cs.map(catalogueCard)));
    });
    $('tlCatalogue').replaceChildren(...(sections.length ? sections : [el('div', { class: 'tl-empty', text: 'No cases match.' })]));
  }

  const TABS = ['overview', 'results', 'catalogue', 'coverage'];
  function showTab(name) {
    document.querySelectorAll('.tl-pagetab').forEach((x) => {
      const on = x.dataset.tab === name;
      x.classList.toggle('active', on);
      x.setAttribute('aria-selected', String(on));
    });
    document.querySelectorAll('[data-panel]').forEach((p) => { p.hidden = p.dataset.panel !== name; });
  }
  function switchTab(name) { location.hash = name; }
  // Routes: #overview · #results · #results/<ID> · #results/<ID>/why · #catalogue · #coverage · legacy #<ID>
  function route() {
    const raw = decodeURIComponent(location.hash.slice(1));
    let [tab, id, sub] = raw.split('/');
    if (!TABS.includes(tab)) {
      if (data && data.cases.some((c) => c.id === raw)) { history.replaceState(null, '', `#results/${raw}`); [tab, id] = ['results', raw]; }
      else tab = 'overview';
    }
    showTab(tab);
    if (tab === 'results' && id) focusCase(id);
    else window.scrollTo({ top: 0 });
    if (tab === 'results' && id && sub === 'why') openWhy(id, true);
    else closeWhy();
  }
  function showInResults(id) { focusCase(id); }

  // ---- coverage map --------------------------------------------------------------------------
  function renderCoverage() {
    const head = el('tr', {}, ...['OWASP item', 'Status', 'Cases', 'Note'].map((t) => el('th', { text: t })));
    let items = data.coverage || [];
    if (!items.length && curatedCoverage && curatedCoverage.length) {
      // The benchmark has no coverage map of its own: map its cases onto the curated OWASP list.
      const counts = {};
      data.cases.forEach((c) => { counts[c.owasp] = (counts[c.owasp] || 0) + 1; });
      items = curatedCoverage.map((c) => {
        if (c.status !== 'tested') return { ...c, cases: 0 }; // out of scope for any gateway test: keep the reason
        const n = counts[c.id] || 0;
        return { id: c.id, name: c.name, cases: n, status: n ? 'tested' : 'absent',
          note: n ? 'Cases from the public datasets (inbound prompts).' : 'Not in this suite: see the Curated OWASP suite.' };
      });
    }
    const label = { tested: '✓ tested', absent: 'not in this suite' };
    const rows = items.map((c) => el('tr', {},
      el('td', {}, el('b', { text: c.id }), ' ', c.name),
      el('td', {}, el('span', { class: `tl-status ${c.status === 'tested' ? 'tested' : 'out'}`, text: label[c.status] || 'out of scope' })),
      el('td', { text: String(c.cases) }), el('td', { text: c.note })));
    $('tlCoverage').replaceChildren(el('thead', {}, head), el('tbody', {}, ...rows));
  }

  // ---- CSV ------------------------------------------------------------------------------------
  function exportCsv() {
    const cols = ['id', 'framework', 'owasp', 'group', 'title', 'technique', 'language', 'direction', 'expected', 'static', 'model_armor', 'nemo', 'all_on_or_api', 'first_catch'];
    const q = (s) => `"${String(s ?? '').replace(/"/g, '""')}"`;
    const lines = [cols.join(',')].concat(data.cases.map((c) => {
      const r = c.runs || {};
      return [c.id, frameworkOf(c.owasp).label, c.owasp, c.group, c.title, c.technique, c.language, c.direction, c.expected,
        r.S && r.S.outcome, r.M && r.M.outcome, r.N && r.N.outcome, (r.D || r.A || {}).outcome, verdictOf(c).first].map(q).join(',');
    }));
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const a = el('a', { href: URL.createObjectURL(blob), download: `guardrail-testlab-${data.label}.csv` });
    document.body.append(a); a.click(); a.remove();
  }

  // ---- wiring ---------------------------------------------------------------------------------
  function fillSelect(id, values) {
    const s = $(id);
    [...new Set(values)].sort().forEach((v) => s.append(el('option', { value: v, text: v })));
  }
  function init(json) {
    data = json;
    if (!data.coverage) data.coverage = [];
    renderSummary(); renderHeat(); renderCoverage();
    const codes = [...new Set(data.cases.map((c) => c.owasp))];
    FRAMEWORKS.forEach((fw) => {
      const mine = codes.filter((c) => frameworkOf(c) === fw).sort((a, b) => parseInt(a.replace(/\D/g, '') || 0, 10) - parseInt(b.replace(/\D/g, '') || 0, 10));
      if (!mine.length) return;
      $('fFramework').append(el('option', { value: fw.key, text: fw.label }));
      $('fOwasp').append(el('optgroup', { label: fw.label }, ...mine.map((c) => el('option', { value: c, text: `${c} ${OWASP_NAMES[c] || ''}`.trim() }))));
    });
    fillSelect('fGroup', data.cases.map((c) => c.group));
    fillSelect('fLang', data.cases.map((c) => c.language));
    ['fSearch', 'fFramework', 'fOwasp', 'fGroup', 'fResult', 'fLang'].forEach((f) => $(f).addEventListener('input', () => { page = 1; renderCases(); }));
    $('btnReveal').addEventListener('click', () => {
      reveal = !reveal;
      $('btnReveal').textContent = reveal ? 'Hide prompts' : 'Show prompts';
      $('btnReveal').setAttribute('aria-pressed', String(reveal));
      renderCases();
    });
    $('btnCsv').addEventListener('click', exportCsv);
    // Catalogue: categories in suite order (not alphabetical), its own search + prompt reveal.
    [...new Set(data.cases.map((c) => c.group))].forEach((g) => $('cGroup').append(el('option', { value: g, text: g })));
    ['cSearch', 'cGroup'].forEach((f) => $(f).addEventListener('input', renderCatalogue));
    $('cReveal').addEventListener('click', () => {
      catReveal = !catReveal;
      $('cReveal').textContent = catReveal ? 'Hide prompts' : 'Show prompts';
      $('cReveal').setAttribute('aria-pressed', String(catReveal));
      renderCatalogue();
    });
    renderCatalogue();
    renderCases();
    document.querySelectorAll('.tl-pagetab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));
    window.addEventListener('hashchange', route);
    route();
  }

  // Sticky offsets: the brand header sticks at the top, the suite's tab bar right under it, and the
  // Results table header under both.
  const topEl = document.querySelector('.tl-top');
  const barEl = document.querySelector('.tl-viewbar');
  const setTopH = () => {
    const head = topEl.offsetHeight;
    document.documentElement.style.setProperty('--tl-head-h', `${head}px`);
    document.documentElement.style.setProperty('--tl-top-h', `${head + barEl.offsetHeight}px`);
  };
  setTopH();
  if ('ResizeObserver' in window) { const ro = new ResizeObserver(setTopH); ro.observe(topEl); ro.observe(barEl); }

  // "Back to demo": if this tab was opened from the playground, go back to that tab instead of reloading it here.
  $('btnBackToDemo').addEventListener('click', (e) => {
    try {
      const op = window.opener;
      if (op && !op.closed && /\/(index\.html)?$/.test(op.location.pathname)) {
        e.preventDefault();
        op.focus();
        toast('The playground is open in your other browser tab.');
      }
    } catch (ignore) { /* opener not reachable: follow the link */ }
  });

  // ---- test suites (parent context for every tab) -------------------------------------------
  // ?set=curated|extended picks the suite, ?ma=strict|balanced|permissive the Model Armor preset run.
  // Switching reloads the page and keeps the current tab (hash).
  const SUITES = {
    curated: {
      name: 'Curated OWASP suite', file: 'testlab/results-latest.json',
      sub: (h, n) => `${n} hand-written cases · ${h.attacks} attacks · ${h.benign} safe prompts`,
      chips: ['Inbound', 'Outbound', 'API security', '8 languages', 'OWASP LLM01–10 · API2–8'],
      purpose: 'What it shows: coverage. One or more cases per OWASP risk, written to exercise a specific layer.',
      hero: 'How much does each guardrail catch?',
      footnote: 'Results come from a small set of hand-written cases, not a statistical benchmark. LLM-based layers (Model Armor, NeMo) can vary slightly between runs; inconsistent cases are re-run and marked flaky.',
    },
    extended: {
      name: 'Public benchmark', file: 'testlab/results-latest-extended.json',
      sub: (h, n) => `${n} cases · ${h.attacks} attacks · ${h.benign} safe look-alikes`,
      chips: ['Inbound only', 'EN / DE', '⅓ held out'],
      sourceChips: true,
      hidden: true, // listed only after the reveal toggle (Alt/Option+Shift+B, or triple-click "Test runs")
      purpose: 'What it shows: realistic accuracy. Third-party prompts nobody tuned for, plus tricky safe prompts that look harmful.',
      hero: 'How accurate is each guardrail on unseen prompts?',
      footnote: 'Ranges are 95% confidence intervals. Held-out cases were never looked at while tuning. LLM-based layers (Model Armor, NeMo) can vary slightly between runs; inconsistent cases are re-run and marked flaky.',
    },
  };
  // Suites = test set x profile. Strictest = Static strict + Model Armor strict + NeMo all rails.
  const PROFILES = {
    balanced: { label: 'Balanced', cls: 'balanced', note: 'Static balanced · Model Armor balanced · NeMo all rails' },
    strictest: { label: 'Strictest', cls: 'strictest', note: 'Static strict · Model Armor strict · NeMo all rails' },
  };
  const SUITE_DEFS = [
    { id: 'curated', set: 'curated', profile: 'balanced', file: 'testlab/results-latest.json' },
    { id: 'curated-strict', set: 'curated', profile: 'strictest', file: 'testlab/results-latest-strict.json' },
    { id: 'extended', set: 'extended', profile: 'balanced', file: 'testlab/results-latest-extended.json' },
    { id: 'extended-strict', set: 'extended', profile: 'strictest', file: 'testlab/results-latest-extended-strict.json' },
  ];
  const STRICT_PURPOSE = 'Same cases with every layer at its strictest. Shows what strict adds in catches, and what it costs in blocked safe prompts.';
  // ?suite=<id>. Older links still work: ?set=extended, ?set=curated&ma=strict.
  const params = new URLSearchParams(location.search);
  const legacy = (params.get('set') === 'extended' ? 'extended' : 'curated') + (params.get('ma') === 'strict' ? '-strict' : '');
  const SUITE = SUITE_DEFS.find((d) => d.id === params.get('suite')) || SUITE_DEFS.find((d) => d.id === legacy) || SUITE_DEFS[0];
  const SET = SUITE.set;
  const suiteName = (d) => `${SUITES[d.set].name} · ${PROFILES[d.profile].label}`;
  const urlFor = (d) => `?suite=${d.id}${location.hash.split('/')[0]}`;
  const getJson = (f) => fetch(f, { cache: 'no-store' }).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); });
  let curatedCoverage = null; // the OWASP map lives in the curated results; the benchmark is mapped onto it
  const runCmd = (d) => `python3 tests/owasp/run_suite.py --set ${d.set}${d.profile === 'strictest' ? ' --profile strictest' : ''}`;

  // Card data: one small entry per published run (written by run_suite.py into testlab/suites-index.json).
  function cardInfo(json) {
    if (!json) return null;
    if (json.headline) return json; // already an index entry
    const sources = {};
    json.cases.forEach((c) => { if (c.source && c.source.dataset) sources[c.source.dataset] = (sources[c.source.dataset] || 0) + 1; });
    return { label: json.label, run_at: json.run_at, duration_s: json.duration_s, cases: json.cases.length, headline: json.summary.headline,
      fp_all_on: (json.summary.false_positives_all_on || []).length, sources, static_profile: json.static_profile, ma_profile: json.ma_profile };
  }

  // ---- Test runs sidebar (Option C) -------------------------------------------------------------
  // One group per test set, one entry per run (today: the latest run per profile). Picking a run reloads
  // the page with ?suite=<id> and keeps the current tab.
  const STORE = 'guardrail-testlab.';
  const store = {
    get: (k, d) => { try { const v = localStorage.getItem(STORE + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set: (k, v) => { try { localStorage.setItem(STORE + k, JSON.stringify(v)); } catch { /* private mode */ } },
  };
  const delta = (a, b) => { const v = Math.round(a - b); return `${v > 0 ? '+' : ''}${v} pts`; };
  const shortDate = (iso) => new Date(iso).toLocaleDateString([], { day: 'numeric', month: 'short' });
  const longDate = (iso) => new Date(iso).toLocaleString([], { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' });
  const durText = (s) => (s >= 120 ? `${(s / 60).toFixed(1)} min` : `${s} s`);

  function runTip(d, info) {
    const S = SUITES[d.set];
    const P = PROFILES[d.profile];
    const chips = [...S.chips];
    if (S.sourceChips && info && info.sources) {
      const short = (x) => x.replace(/ JBB-Behaviors| \(.*\)|\/prompt-injections/g, '').replace('Generated from curated cases', 'generated variants');
      chips.unshift(...Object.entries(info.sources).map(([x, k]) => `${short(x)} ${k}`));
    }
    return [`${S.name} · ${P.label} (${P.note})`, d.profile === 'balanced' ? S.purpose : STRICT_PURPOSE, chips.join(' · '),
      info ? `Run ${longDate(info.run_at)} · ${durText(info.duration_s)} · label "${info.label}"` : `Not run yet: ${runCmd(d)}`].join('\n');
  }
  function runEntry(d, info, balancedInfo) {
    const P = PROFILES[d.profile];
    const active = d.id === SUITE.id;
    const h = info ? info.headline : null;
    const vs = h && balancedInfo && d.profile !== 'balanced'
      ? el('span', { class: 'tl-run-delta', title: 'Change against the Balanced run: caught / safe prompts blocked',
        text: `${delta(h.defense_in_depth_pct, balancedInfo.headline.defense_in_depth_pct)} / ${delta(h.false_positive_pct || 0, balancedInfo.headline.false_positive_pct || 0)}` })
      : null;
    return el(info ? 'a' : 'div', { class: `tl-run${active ? ' active' : ''}${info ? '' : ' empty'}`, href: info ? urlFor(d) : null,
      role: 'radio', 'aria-checked': String(active), title: runTip(d, info), 'data-filter': `${SUITES[d.set].name} ${P.label} ${info ? shortDate(info.run_at) : 'not run'}`.toLowerCase() },
      el('span', { class: 'tl-run-line' },
        el('span', { class: `tl-run-profile ${P.cls}`, text: P.label }),
        el('span', { class: 'tl-run-date', text: info ? `· ${shortDate(info.run_at)}` : '· not run yet' }),
        active ? el('span', { class: 'tl-run-check', 'aria-hidden': 'true', text: '✓' }) : null),
      h ? el('span', { class: 'tl-run-nums' },
        el('span', { class: `tl-run-num ${h.defense_in_depth_pct >= 95 ? 'good' : 'warn'}`, title: 'Attacks caught with all layers on', text: fmtPct(h.defense_in_depth_pct) }),
        el('span', { class: `tl-run-num ${info.fp_all_on ? 'bad' : 'good'}`, title: 'Safe prompts blocked with all layers on',
          text: info.fp_all_on ? fmtPct(h.false_positive_pct) : `0/${h.benign}` }),
        vs) : el('span', { class: 'tl-run-cmd', text: runCmd(d) }));
  }
  // Hidden test sets: revealed per browser (remembered), or for one visit when a link names one explicitly.
  let lastInfos = {};
  let lastActive = null;
  const linkedHidden = () => SUITES[SUITE.set].hidden && (params.get('suite') === SUITE.id || params.has('set'));
  const hiddenShown = () => !!store.get('showHidden', false) || linkedHidden();
  function setShowHidden(on) {
    store.set('showHidden', on);
    if (!on && SUITES[SUITE.set].hidden) { // hiding the set being viewed: switch to the curated run of the same profile
      const to = SUITE_DEFS.find((d) => !SUITES[d.set].hidden && d.profile === SUITE.profile) || SUITE_DEFS[0];
      location.replace(urlFor(to));
      return;
    }
    renderSuites(lastInfos, lastActive);
    toast(on ? 'Hidden test sets shown (Public benchmark).' : 'Hidden test sets hidden.');
  }
  function renderSuites(infos, activeJson) {
    lastInfos = infos;
    lastActive = activeJson;
    const showHidden = hiddenShown();
    const closed = new Set(store.get('closedGroups', []));
    const groups = Object.keys(SUITES).map((set) => {
      // Only runs that exist in this copy (the public repo ships the curated suite only).
      const defs = SUITE_DEFS.filter((d) => d.set === set && (infos[d.id] || d.id === SUITE.id));
      if (!defs.length) return null;
      if (SUITES[set].hidden && !showHidden) return null;
      const any = defs.map((d) => infos[d.id]).find(Boolean);
      const open = !closed.has(set) || defs.some((d) => d.id === SUITE.id); // the selected run's group always starts open
      const list = el('div', { class: 'tl-run-list', id: `tlGroup-${set}`, hidden: !open },
        ...defs.map((d) => runEntry(d, infos[d.id], d.profile !== 'balanced' ? infos[d.set] : null)));
      const head = el('button', { type: 'button', class: 'tl-run-group-head', 'aria-expanded': String(open), 'aria-controls': `tlGroup-${set}`,
        onclick: (e) => {
          const nowOpen = list.hidden;
          list.hidden = !nowOpen;
          e.currentTarget.setAttribute('aria-expanded', String(nowOpen));
          const c = new Set(store.get('closedGroups', []));
          if (nowOpen) c.delete(set); else c.add(set);
          store.set('closedGroups', [...c]);
        } },
        el('span', { class: 'tl-run-caret', 'aria-hidden': 'true', text: '▾' }),
        el('span', { class: 'tl-run-group-name', text: SUITES[set].name }),
        SUITES[set].hidden ? el('span', { class: 'tl-run-hidden-tag', text: 'hidden', title: 'Hidden test set: not listed by default' }) : null,
        any ? el('span', { class: 'tl-run-group-count', text: String(any.cases) }) : null);
      return el('div', { class: 'tl-run-group', 'data-set': set }, head, list);
    });
    $('tlSuites').replaceChildren(...groups.filter(Boolean));
    const hasHidden = Object.keys(SUITES).some((k) => SUITES[k].hidden && SUITE_DEFS.some((d) => d.set === k && infos[d.id]));
    const foot = $('tlSideFoot');
    foot.hidden = !(showHidden && hasHidden);
    foot.replaceChildren(...(foot.hidden ? [] : [
      el('span', { text: store.get('showHidden', false) ? '👁 Hidden test sets shown' : '👁 Opened from a link' }),
      el('button', { type: 'button', class: 'tl-side-foot-btn', text: store.get('showHidden', false) ? 'Hide' : 'Hide again',
        title: 'Hide the Public benchmark (Alt/Option+Shift+B)', onclick: () => setShowHidden(false) }),
    ]));
    applyRunFilter();
    // Title line of the selected run.
    const info = infos[SUITE.id];
    const h = info ? info.headline : null;
    const bal = SUITE.profile !== 'balanced' ? infos[SUITE.set] : null;
    $('tlScopeName').replaceChildren(el('span', { text: suiteName(SUITE) }), info ? el('span', { class: 'tl-runhead-date', text: ` · ${longDate(info.run_at)}` }) : '');
    $('tlRunKpis').replaceChildren(...(h ? [
      el('span', {}, el('b', { class: h.defense_in_depth_pct >= 95 ? 'good' : 'warn', text: fmtPct(h.defense_in_depth_pct) }), ' caught'),
      el('span', {}, el('b', { class: info.fp_all_on ? 'bad' : 'good', text: info.fp_all_on ? fmtPct(h.false_positive_pct) : `0 / ${h.benign}` }), ' safe blocked'),
      bal ? el('span', { class: 'tl-runhead-delta', title: 'Change against the Balanced run: caught / safe prompts blocked' },
        `vs Balanced ${delta(h.defense_in_depth_pct, bal.headline.defense_in_depth_pct)} / ${delta(h.false_positive_pct || 0, bal.headline.false_positive_pct || 0)}`) : '',
    ] : []));
    $('tlResultsCount').textContent = activeJson ? String(activeJson.cases.length) : '';
  }
  function applyRunFilter() {
    const q = $('tlSideFilter').value.trim().toLowerCase();
    document.querySelectorAll('#tlSuites .tl-run-group').forEach((g) => {
      let shown = 0;
      g.querySelectorAll('.tl-run').forEach((r) => { const ok = !q || r.dataset.filter.includes(q) || g.dataset.set.includes(q); r.hidden = !ok; shown += ok; });
      g.hidden = !shown;
      if (q && shown) { g.querySelector('.tl-run-list').hidden = false; g.querySelector('.tl-run-group-head').setAttribute('aria-expanded', 'true'); }
    });
  }
  $('tlSideFilter').addEventListener('input', applyRunFilter);
  document.addEventListener('keydown', (e) => {
    if (!(e.altKey && e.shiftKey && e.code === 'KeyB') || e.metaKey || e.ctrlKey) return;
    if (/^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || '')) return;
    e.preventDefault();
    setShowHidden(!store.get('showHidden', false));
  });
  document.querySelector('.tl-side-title').addEventListener('click', (e) => { if (e.detail === 3) setShowHidden(!store.get('showHidden', false)); });

  // Width (drag the splitter, ←/→, Home, double-click) and collapse (button, Enter on the splitter, "[").
  const SIDE_DEFAULT = 272;
  const SIDE_MIN = 200;
  const SIDE_MAX = 480;
  const shell = $('tlShell');
  const splitter = $('tlSplitter');
  let sideW = Math.min(SIDE_MAX, Math.max(SIDE_MIN, Number(store.get('sideW', SIDE_DEFAULT)) || SIDE_DEFAULT));
  function setSideW(w, save = true) {
    sideW = Math.round(Math.min(SIDE_MAX, Math.max(SIDE_MIN, w)));
    shell.style.setProperty('--tl-side-w', `${sideW}px`);
    splitter.setAttribute('aria-valuenow', String(sideW));
    if (save) store.set('sideW', sideW);
  }
  function setCollapsed(on, save = true) {
    shell.classList.toggle('side-collapsed', on);
    const btn = $('tlSideToggle');
    btn.textContent = on ? '»' : '«';
    btn.title = on ? 'Show the run list ( [ )' : 'Collapse the run list ( [ )';
    btn.setAttribute('aria-expanded', String(!on));
    btn.setAttribute('aria-label', on ? 'Show the run list' : 'Collapse the run list');
    // Keep the splitter in the grid (its 0 px column) so the content stays in the last column; just make it inert.
    splitter.tabIndex = on ? -1 : 0;
    splitter.setAttribute('aria-hidden', String(on));
    if (save) store.set('sideCollapsed', on);
  }
  setSideW(sideW, false);
  setCollapsed(!!store.get('sideCollapsed', false), false);
  $('tlSideToggle').addEventListener('click', () => setCollapsed(!shell.classList.contains('side-collapsed')));
  splitter.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    splitter.setPointerCapture(e.pointerId);
    shell.classList.add('resizing');
    const left = shell.getBoundingClientRect().left;
    let raw = sideW;
    const move = (ev) => { raw = ev.clientX - left; setSideW(raw, false); };
    const up = () => {
      splitter.removeEventListener('pointermove', move);
      shell.classList.remove('resizing');
      if (raw < SIDE_MIN - 60) { setCollapsed(true); setSideW(SIDE_DEFAULT, true); } // dragged nearly shut: collapse
      else store.set('sideW', sideW);
    };
    splitter.addEventListener('pointermove', move);
    splitter.addEventListener('pointerup', up, { once: true });
    splitter.addEventListener('pointercancel', up, { once: true });
  });
  splitter.addEventListener('dblclick', () => setSideW(SIDE_DEFAULT));
  splitter.addEventListener('keydown', (e) => {
    const step = e.shiftKey ? 48 : 16;
    if (e.key === 'ArrowLeft') { e.preventDefault(); setSideW(sideW - step); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); setSideW(sideW + step); }
    else if (e.key === 'Home') { e.preventDefault(); setSideW(SIDE_DEFAULT); }
    else if (e.key === 'Enter') { e.preventDefault(); setCollapsed(true); $('tlSideToggle').focus(); }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== '[' || e.metaKey || e.ctrlKey || e.altKey) return;
    if (/^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || '') || !$('tlWhy').hidden) return;
    setCollapsed(!shell.classList.contains('side-collapsed'));
  });

  function renderContext(json) {
    const staticProfile = json.static_profile || (/strict/i.test((json.config || {}).S || '') ? 'strict' : 'balanced');
    const ma = json.ma_profile || 'balanced';
    const stale = !json.ma_profile; // runs before the Model Armor presets (31 Oct) don't record one
    $('tlContext').replaceChildren(
      el('span', { class: 'tl-context-title', text: 'Configuration tested' }),
      el('span', { class: `tl-profile ${PROFILES[SUITE.profile].cls}`, text: PROFILES[SUITE.profile].label }),
      el('span', { class: 'tl-ctx-kv' }, el('i', { text: 'proxy' }), el('code', { text: json.target || 'guardrail-proxy' })),
      el('span', { class: 'tl-ctx-kv' }, el('i', { text: 'Static' }), staticProfile),
      el('span', { class: 'tl-ctx-kv', title: (json.ma_templates ? `${json.ma_templates.inbound} / ${json.ma_templates.outbound}` : '') },
        el('i', { text: 'Model Armor' }), ma),
      el('span', { class: 'tl-ctx-kv' }, el('i', { text: 'NeMo' }), 'all rails (or the case\'s persona)'),
      stale ? el('span', { class: 'tl-stale', title: 'This run predates the Model Armor presets (templates guardrail-proxy-in/out-<preset>). Re-run run_suite.py to refresh.' },
        '⚠ Run before the Model Armor presets: re-run to refresh') : '');
  }

  // Index first (small); fall back to the full result files if it is missing.
  const loadInfos = () => getJson('testlab/suites-index.json')
    .then((idx) => Object.fromEntries(SUITE_DEFS.map((d) => [d.id, idx[d.id] || null])))
    .catch(() => Promise.all(SUITE_DEFS.map((d) => getJson(d.file).then(cardInfo).catch(() => null)))
      .then((list) => Object.fromEntries(SUITE_DEFS.map((d, i) => [d.id, list[i]]))));

  Promise.all([getJson(SUITE.file), loadInfos()]).then(async ([active, infos]) => {
    infos[SUITE.id] = cardInfo(active);
    if (SET === 'curated') curatedCoverage = active.coverage;
    else curatedCoverage = (infos.curated && infos.curated.coverage)
      || await getJson(SUITE_DEFS[0].file).then((j) => j.coverage).catch(() => []);
    renderSuites(infos, active);
    renderContext(active);
    try { init(active); } catch (err) { console.error(err); toast('Some Test Lab sections could not be drawn (see console).'); }
    setTopH();
  }, (e) => {
    loadInfos().then((infos) => {
      // This copy may not ship every suite (the public repo has only the curated one): open one that exists.
      const first = SUITE_DEFS.find((d) => infos[d.id]);
      if (first && first.id !== SUITE.id) { location.replace(urlFor(first)); return; }
      renderSuites(infos, null);
    }).catch(() => {});
    $('tlScopeName').textContent = suiteName(SUITE);
    $('tlMeta').textContent = `No ${suiteName(SUITE)} results yet (${e.message}). Run: ${runCmd(SUITE)}`;
  });
})();
