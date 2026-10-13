/**
 * Guided Tour engine - welcome chooser, spotlight + coachmark, mission
 * progress, completion detection and "What just happened?" explainer.
 * (Pattern adapted from the Biscuit Coffee demo's Guided Tour.)
 *
 * Integration contract (provided by app.js):
 *   window.guardrailApp            { loadScenario(id), run(), isRunning(), layersSummary() }
 *   window 'guardrail:ready'       app.js finished wiring (guardrailApp available)
 *   window 'guardrail:runresult'   detail { outcome, streamedChars, message } after each run
 * Scenario chips carry data-scenario="<id>" and data-group="<tab>".
 */
import { MISSIONS, OUTCOME_LABEL, archOpen } from './tour-missions.js';

const STORE_KEY = 'guardrailTour.v1';
const HIDE_WELCOME_KEY = 'guardrailTour.hideWelcome';
const SEEN_KEY = 'guardrailTour.seenThisSession';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const resolve = (v, ...args) => (typeof v === 'function' ? v(...args) : v);
const CLOSE_BTN = '<button type="button" class="tour-close" data-act="dismiss" title="Close (Esc)" aria-label="Close tour">×</button>';
const RUN_BTN = '#btnRunStream';
const RESULT_CARD = '#cardStream';

export class GuidedTour {
  constructor(app) {
    this.app = app;
    this.state = this.load();
    this.hint = '';
    this.mode = 'idle'; // idle | step | explainer | finished
    this.phase = 'pick'; // scenario steps: pick -> loaded -> running
    this.build();
    this.bind();

    const params = new URLSearchParams(window.location.search);
    const forced = params.get('tour');
    if (forced && forced !== '0') {
      const idx = MISSIONS.findIndex((m) => m.id === forced);
      if (idx >= 0) this.start(idx); else this.showWelcome();
    } else if (this.state.active) {
      this.showStep(); // resume an in-progress tour after reload
    } else if (forced !== '0' && !localStorage.getItem(HIDE_WELCOME_KEY) && !sessionStorage.getItem(SEEN_KEY)) {
      this.showWelcome();
    }
  }

  // ------------------------------------------------------------------ state
  load() {
    try {
      const s = JSON.parse(localStorage.getItem(STORE_KEY) || '{}');
      return { active: !!s.active, mission: s.mission || 0, step: s.step || 0, completed: s.completed || [] };
    } catch { return { active: false, mission: 0, step: 0, completed: [] }; }
  }
  save() { try { localStorage.setItem(STORE_KEY, JSON.stringify(this.state)); } catch { /* storage unavailable */ } }
  get mission() { return MISSIONS[this.state.mission]; }
  get step() { return this.mission?.steps[this.state.step]; }

  // ------------------------------------------------------------------ DOM
  build() {
    const main = MISSIONS.filter((m) => !m.bonus).length;
    const root = document.createElement('div');
    root.className = 'tour-root';
    root.innerHTML = `
      <div class="tour-welcome-backdrop" id="tourWelcome" hidden>
        <div class="tour-welcome" role="dialog" aria-modal="true" aria-labelledby="tourWelcomeTitle">
          <div class="tour-welcome-icon">🛡️</div>
          <h2 id="tourWelcomeTitle">Welcome to Apigee and Guardrails Solutions</h2>
          <p class="tour-welcome-sub">See how Apigee layers Static Guardrails, Model Armor and NVIDIA NeMo to protect a streaming Gemini app</p>
          <div class="tour-choice-grid">
            <button type="button" class="tour-choice selected" data-choice="tour">
              <span class="tour-choice-badge">Recommended</span>
              <span class="tour-choice-icon">🗺️</span>
              <span class="tour-choice-title">Guided Tour</span>
              <span class="tour-choice-meta">${main} short missions + bonus · about 8 min</span>
              <ul class="tour-choice-list">
                <li>Fast regex guardrails in Apigee</li>
                <li>Model Armor on prompts and mid-stream</li>
                <li>NeMo topic and jailbreak rails</li>
                <li>Defense in depth and audit logs</li>
              </ul>
            </button>
            <button type="button" class="tour-choice" data-choice="explore">
              <span class="tour-choice-icon">🧭</span>
              <span class="tour-choice-title">Explore on my own</span>
              <span class="tour-choice-meta">Go straight to the scenarios and policies. You can start the tour later from the header.</span>
            </button>
          </div>
          <div class="tour-welcome-footer">
            <label class="tour-check"><input type="checkbox" id="tourHideWelcome"> Don't show this again</label>
            <div class="tour-welcome-actions">
              <button type="button" class="tour-btn tour-btn-text" id="tourResumeBtn" hidden></button>
              <button type="button" class="tour-btn tour-btn-text" id="tourSkipBtn">Skip</button>
              <button type="button" class="tour-btn tour-btn-primary" id="tourStartBtn">Start Guided Tour</button>
            </div>
          </div>
        </div>
      </div>

      <div class="tour-dim" id="tourDim" hidden><i></i><i></i><i></i><i></i></div>
      <div class="tour-spotlight" id="tourSpotlight" hidden></div>

      <div class="tour-stepper" id="tourStepper" hidden>
        <button type="button" class="tour-stepper-list" id="tourChecklistBtn" title="Show all missions">☰ Missions</button>
        <div class="tour-dots" id="tourDots"></div>
        <span class="tour-stepper-label" id="tourStepperLabel"></span>
        <button type="button" class="tour-btn tour-btn-text tour-exit" id="tourExitBtn">Exit tour</button>
      </div>

      <div class="tour-checklist" id="tourChecklist" hidden></div>
      <div class="tour-pop" id="tourPop" role="dialog" aria-live="polite" hidden></div>
      <aside class="tour-explainer" id="tourExplainer" aria-live="polite" hidden></aside>
      <div class="tour-toast" id="tourToast" role="status" hidden></div>
    `;
    document.body.appendChild(root);
    const $ = (id) => root.querySelector(`#${id}`);
    Object.assign(this, {
      root, welcome: $('tourWelcome'), spot: $('tourSpotlight'), dim: $('tourDim'), stepper: $('tourStepper'),
      dots: $('tourDots'), stepperLabel: $('tourStepperLabel'), checklist: $('tourChecklist'),
      pop: $('tourPop'), explainer: $('tourExplainer'), toast: $('tourToast'),
    });

    let choice = 'tour';
    root.querySelectorAll('.tour-choice').forEach((btn) => btn.addEventListener('click', () => {
      choice = btn.dataset.choice;
      root.querySelectorAll('.tour-choice').forEach((b) => b.classList.toggle('selected', b === btn));
      $('tourStartBtn').textContent = choice === 'tour' ? 'Start Guided Tour' : 'Start exploring';
    }));
    const closeWelcome = () => {
      try {
        if ($('tourHideWelcome').checked) localStorage.setItem(HIDE_WELCOME_KEY, '1');
        sessionStorage.setItem(SEEN_KEY, '1');
      } catch { /* storage unavailable */ }
      this.welcome.hidden = true;
    };
    $('tourStartBtn').addEventListener('click', () => {
      closeWelcome();
      if (choice === 'tour') this.start(0, true); else this.exit(false);
    });
    $('tourSkipBtn').addEventListener('click', () => { closeWelcome(); this.exit(false); });
    $('tourResumeBtn').addEventListener('click', () => { closeWelcome(); this.start(this.state.mission); });
    $('tourExitBtn').addEventListener('click', () => this.exit(true));
    $('tourChecklistBtn').addEventListener('click', () => this.toggleChecklist());
  }

  bind() {
    window.addEventListener('guardrail:runresult', (e) => this.onRunResult(e.detail || {}));
    document.addEventListener('click', (e) => {
      if (this.mode !== 'step') return;
      const s = this.step;
      if (s?.done?.click && e.target.closest(s.done.click)) { setTimeout(() => this.completeStep(), 300); return; }
      // The user pressed the real Run button during a scenario step.
      if (s?.kind === 'scenario' && e.target.closest(RUN_BTN) && !e.target.closest(RUN_BTN).disabled) {
        this.phase = 'running';
        this.hint = 'Streaming… watch the result panel on the right.';
        this.renderPop();
        setTimeout(() => this.position(), 50);
      }
    }, true);
    window.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape') return;
      if (!this.checklist.hidden) { this.toggleChecklist(false); e.stopImmediatePropagation(); return; }
      if (archOpen() || this.adminOpen() || !this.welcome.hidden) return; // let the app close its own layer
      if (['step', 'explainer', 'finished'].includes(this.mode)) this.dismiss();
    }, true);

    let raf = 0;
    const reflow = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => this.position()); };
    window.addEventListener('resize', reflow);
    window.addEventListener('scroll', reflow, true);
    // Panels resize (splitter, streaming output); keep the spotlight glued on.
    setInterval(() => { if (this.mode === 'step') this.position(); }, 300);
  }

  // ------------------------------------------------------------------ helpers
  adminOpen() { return !!document.getElementById('adminDrawer')?.classList.contains('open'); }
  closeArch() { if (archOpen()) document.getElementById('archModalCloseBtn')?.click(); }
  closeAdmin() { if (this.adminOpen()) document.getElementById('btnCloseAdminDrawer')?.click(); }
  showToast(html) {
    this.toast.innerHTML = html;
    this.toast.hidden = false;
    clearTimeout(this.toastTimer);
    this.toastTimer = setTimeout(() => { this.toast.hidden = true; }, 5000);
  }
  /** Make sure the scenario chip's tab is visible so the spotlight can find it. */
  revealChip(sel) {
    const chip = sel && document.querySelector(sel);
    if (chip && chip.hidden && chip.dataset.group) {
      document.querySelector(`.scn-tab[data-group="${chip.dataset.group}"]`)?.click();
    }
  }

  // ------------------------------------------------------------------ flow
  showWelcome() {
    const resume = this.root.querySelector('#tourResumeBtn');
    const canResume = this.state.completed.length > 0 && this.state.mission < MISSIONS.length;
    resume.hidden = !canResume;
    if (canResume) resume.textContent = `Resume (Mission ${this.state.mission + 1})`;
    this.mode = 'idle';
    this.hideOverlays();
    this.welcome.hidden = false;
  }

  /** Public: (re)open the chooser, e.g. from the header button. */
  open() { this.showWelcome(); }

  start(missionIdx = 0, fresh = false) {
    if (fresh) this.state = { active: true, mission: 0, step: 0, completed: [] };
    this.state.active = true;
    this.state.mission = Math.max(0, Math.min(missionIdx, MISSIONS.length - 1));
    this.state.step = 0;
    this.save();
    this.showStep();
  }

  exit(confirmed) {
    this.state.active = false;
    this.save();
    this.mode = 'idle';
    this.hideOverlays();
    if (confirmed) this.showToast('🗺️ Guided Tour paused. Reopen it any time from <b>Guided Tour</b> in the header.');
  }

  hideOverlays() {
    [this.dim, this.spot, this.stepper, this.checklist, this.pop, this.explainer].forEach((el) => { el.hidden = true; });
  }

  showStep() {
    const s = this.step;
    if (!s) return this.finish();
    this.mode = 'step';
    this.hint = '';
    this.phase = 'pick';
    this.explainer.hidden = true;
    if (s.before) s.before(this);
    this.revealChip(s.target);
    this.renderStepper();
    this.renderPop();
    const el = s.target && document.querySelector(s.target);
    if (el) el.scrollIntoView({ block: 'nearest', behavior: 'auto' });
    setTimeout(() => this.position(), 350);
  }

  completeStep() {
    if (this.mode !== 'step') return;
    const m = this.mission;
    if (this.state.step < m.steps.length - 1) {
      this.state.step += 1;
      this.save();
      return this.showStep();
    }
    if (!this.state.completed.includes(m.id)) this.state.completed.push(m.id);
    this.save();
    this.showExplainer();
  }

  nextMission() {
    this.closeArch();
    if (this.state.mission >= MISSIONS.length - 1) return this.finish();
    this.state.mission += 1;
    this.state.step = 0;
    this.save();
    this.showStep();
  }

  back() {
    let mi = this.state.mission, si = this.state.step - 1;
    if (si < 0) {
      if (mi === 0) return;
      mi -= 1;
      si = MISSIONS[mi].steps.length - 1;
    }
    this.state.mission = mi;
    this.state.step = si;
    this.save();
    this.showStep();
  }

  finish() {
    this.state.active = false;
    this.state.mission = MISSIONS.length;
    this.save();
    this.hideOverlays();
    this.closeArch();
    const done = this.state.completed.length;
    this.explainer.innerHTML = `${CLOSE_BTN}
      <div class="tour-exp-head"><span class="tour-exp-kicker">Guided Tour</span><h3>🎉 Tour complete</h3></div>
      <p class="tour-exp-text">You finished <b>${done}</b> of ${MISSIONS.length} missions. You've seen Apigee:</p>
      <ul class="tour-exp-summary">
        <li>Let safe prompts through without false alarms</li>
        <li>Stop known attacks in ~80 ms with Static Guardrails</li>
        <li>Block jailbreaks and harmful prompts with Model Armor</li>
        <li>Cut a harmful answer mid-stream (SanitizeModelResponse)</li>
        <li>Enforce business topic rules with NVIDIA NeMo</li>
        <li>Log every guardrail decision for audit</li>
      </ul>
      <div class="tour-exp-actions">
        <button type="button" class="tour-btn tour-btn-text" data-act="restart">Restart tour</button>
        <button type="button" class="tour-btn tour-btn-primary" data-act="close">Continue exploring</button>
      </div>`;
    this.mode = 'finished';
    this.explainer.classList.remove('tour-explainer-low');
    this.explainer.hidden = false;
    this.explainer.querySelector('[data-act="restart"]').onclick = () => this.start(0, true);
    this.explainer.querySelectorAll('[data-act="close"], [data-act="dismiss"]').forEach((b) => {
      b.onclick = () => { this.explainer.hidden = true; this.mode = 'idle'; };
    });
  }

  // ------------------------------------------------------------------ events
  onRunResult({ outcome, message }) {
    this.lastRun = { outcome, message };
    if (!this.state.active || this.mode !== 'step') return;
    const s = this.step;
    if (s?.kind !== 'scenario' || !s.done?.outcome) return;
    if (s.done.outcome.includes(outcome)) return setTimeout(() => this.completeStep(), 900);
    this.phase = 'loaded';
    let got = `<b>${esc(OUTCOME_LABEL[outcome] || outcome)}</b>`;
    if (outcome === 'error' && message) got += `: <code>${esc(message)}</code>`;
    this.hint = `Got ${got}. Expected something else. Check that the scenario's layer settings were applied, then run it again.`;
    this.renderPop();
    this.position();
  }

  // ------------------------------------------------------------------ render
  renderStepper() {
    const main = MISSIONS.filter((m) => !m.bonus);
    this.dots.innerHTML = MISSIONS.map((m, i) => {
      const cls = this.state.completed.includes(m.id) ? 'done' : (i === this.state.mission ? 'current' : '');
      const label = m.bonus ? '★' : i + 1;
      return `${i ? '<span class="tour-dot-line"></span>' : ''}<button type="button" class="tour-dot ${cls} ${m.bonus ? 'bonus' : ''}" data-idx="${i}" title="${esc(m.title)}">${cls === 'done' ? '✓' : label}</button>`;
    }).join('');
    this.dots.querySelectorAll('.tour-dot').forEach((d) => d.addEventListener('click', () => this.start(Number(d.dataset.idx))));
    const m = this.mission;
    this.stepperLabel.textContent = m.bonus ? 'Guided Tour · Bonus mission' : `Guided Tour · Mission ${this.state.mission + 1}/${main.length}`;
    const header = document.querySelector('header');
    if (header) this.stepper.style.top = `${Math.round(header.getBoundingClientRect().bottom) + 6}px`;
    this.stepper.hidden = false;
  }

  toggleChecklist(force) {
    const show = force ?? this.checklist.hidden;
    if (!show) { this.checklist.hidden = true; return; }
    const doneCount = this.state.completed.length;
    const pct = Math.round((doneCount / MISSIONS.length) * 100);
    this.checklist.innerHTML = `
      <div class="tour-cl-head">
        <div class="tour-ring" style="--pct:${pct}"><span>${doneCount}/${MISSIONS.length}</span></div>
        <div><div class="tour-cl-title">Mission checklist</div><div class="tour-cl-sub">Click a mission to jump to it</div></div>
      </div>
      <ol class="tour-cl-list">
        ${MISSIONS.map((m, i) => {
          const st = this.state.completed.includes(m.id) ? 'done' : (i === this.state.mission ? 'current' : 'todo');
          return `<li class="${st}" data-idx="${i}"><span class="tour-cl-mark">${st === 'done' ? '✓' : (m.bonus ? '★' : i + 1)}</span>
            <span class="tour-cl-name">${esc(m.title)}</span><span class="tour-cl-badge">${esc(m.badge)}</span></li>`;
        }).join('')}
      </ol>`;
    this.checklist.querySelectorAll('li').forEach((li) => li.addEventListener('click', () => {
      this.toggleChecklist(false);
      this.start(Number(li.dataset.idx));
    }));
    this.checklist.hidden = false;
  }

  renderPop() {
    const s = this.step, m = this.mission;
    if (!s) return;
    const multi = m.steps.length > 1;
    const kicker = `${m.bonus ? 'BONUS MISSION' : `MISSION ${this.state.mission + 1} OF ${MISSIONS.filter((x) => !x.bonus).length}`}${multi ? ` · STEP ${this.state.step + 1}/${m.steps.length}` : ''}`;

    let primary = '';
    if (s.kind === 'scenario' && this.phase === 'running') primary = '<button type="button" class="tour-btn tour-btn-primary" disabled>Running…</button>';
    else if (s.kind === 'scenario' && this.phase === 'loaded') primary = '<button type="button" class="tour-btn tour-btn-primary" data-act="run">Run ⚡</button>';
    else if (s.kind === 'scenario') primary = '<button type="button" class="tour-btn tour-btn-primary" data-act="load">Load this scenario</button>';
    else if (s.action) primary = `<button type="button" class="tour-btn tour-btn-primary" data-act="action">${esc(resolve(s.action.label, this))}</button>`;

    const layers = s.kind === 'scenario' && this.phase !== 'pick' && this.app.layersSummary
      ? `<div class="tour-layers">Layers set: <code>${esc(this.app.layersSummary())}</code></div>` : '';

    this.pop.innerHTML = `${CLOSE_BTN}
      <span class="tour-pop-arrow"></span>
      <div class="tour-pop-kicker">${kicker}</div>
      <h3 class="tour-pop-title">${esc(s.title)}</h3>
      <div class="tour-pop-body">${s.body}</div>
      ${layers}
      ${s.expect ? `<div class="tour-expect">Expected: <b>${esc(s.expect)}</b></div>` : ''}
      ${this.hint ? `<div class="tour-hint">${this.hint}</div>` : ''}
      <div class="tour-pop-actions">
        <button type="button" class="tour-btn tour-btn-text" data-act="back" ${this.state.mission === 0 && this.state.step === 0 ? 'disabled' : ''}>Back</button>
        <button type="button" class="tour-btn tour-btn-text" data-act="skip">Skip</button>
        ${primary}
      </div>`;
    this.pop.hidden = false;

    const on = (act, fn) => { const b = this.pop.querySelector(`[data-act="${act}"]`); if (b) b.onclick = fn; };
    on('load', () => {
      this.app.loadScenario(s.scenario);
      this.phase = 'loaded';
      this.hint = 'Prompt and layers are set. Press <b>Run</b> here or the blue <b>Run Streaming Request</b> button.';
      this.renderPop(); this.position();
    });
    on('run', () => document.querySelector(RUN_BTN)?.click());
    on('action', () => s.action.run(this));
    on('skip', () => this.completeStep());
    on('back', () => this.back());
    on('dismiss', () => this.dismiss());
  }

  showExplainer() {
    const m = this.mission, ex = m.explainer || {};
    this.mode = 'explainer';
    this.spot.hidden = true; this.dim.hidden = true;
    this.pop.hidden = true;
    this.renderStepper();
    const next = MISSIONS[this.state.mission + 1];
    const icon = { ok: '✓', fail: '✕', skip: '–', miss: '!' };
    const ho = ex.handoff;
    const handoff = ho ? `
      <div class="tour-handoff">
        <div class="tour-handoff-row">
          <span class="tour-handoff-layer missed"><span class="tour-handoff-x">✕</span>${esc(ho.missed)}<small>missed it</small></span>
          <span class="tour-handoff-arrow" aria-hidden="true">→</span>
          <span class="tour-handoff-layer caught"><span class="tour-handoff-x">🛡</span>${esc(ho.caught)}<small>blocked it</small></span>
        </div>
        <p class="tour-handoff-text">${esc(ho.text)}</p>
      </div>` : '';
    // Model Armor findings from the actual run, e.g. "PIMatchesFound: true".
    const FINDING = { PI: 'Prompt injection & jailbreak', RAI: 'Harmful content (RAI)', SDP: 'Sensitive data (SDP)', CSAM: 'CSAM', URI: 'Malicious URL' };
    const hits = this.lastRun && /^ma-/.test(this.lastRun.outcome)
      ? [...String(this.lastRun.message || '').matchAll(/\b([A-Z]+)MatchesFound:\s*true\b/g)].map((x) => x[1]) : [];
    const findings = hits.length ? `
      <div class="tour-findings"><span class="tour-findings-label">Model Armor detected</span>
        ${hits.map((h) => `<span class="tour-finding"><code>${esc(h)}MatchesFound: true</code> ${esc(FINDING[h] || '')}</span>`).join('')}
      </div>` : '';
    this.explainer.innerHTML = `${CLOSE_BTN}
      <div class="tour-exp-head"><span class="tour-exp-kicker">What just happened?</span><h3>${esc(ex.title || m.title)}</h3></div>
      ${handoff}
      <ol class="tour-flow">
        ${(ex.flow || []).map((f, i) => `<li class="${f.state}"><span class="tour-flow-n">${icon[f.state] || i + 1}</span><span class="tour-flow-text">${esc(f.text)}</span>${f.tag ? `<span class="tour-flow-tag">${esc(f.tag)}</span>` : ''}</li>`).join('')}
      </ol>
      ${findings}
      ${ex.note ? `<p class="tour-exp-note">${ex.note}</p>` : ''}
      <div class="tour-exp-done">Mission complete!</div>
      <div class="tour-exp-actions">
        ${next?.bonus ? '<button type="button" class="tour-btn tour-btn-text" data-act="finish">Finish tour</button>' : '<button type="button" class="tour-btn tour-btn-text" data-act="later">Pause</button>'}
        <button type="button" class="tour-btn tour-btn-primary" data-act="next">${next ? `${next.bonus ? 'Bonus' : 'Next'}: ${esc(next.title.replace(/^Bonus:\s*/, ''))}` : 'Finish tour'}</button>
      </div>`;
    this.explainer.hidden = false;
    this.explainer.classList.toggle('tour-explainer-low', archOpen());
    const on = (act, fn) => { const b = this.explainer.querySelector(`[data-act="${act}"]`); if (b) b.onclick = fn; };
    on('next', () => { this.explainer.hidden = true; this.nextMission(); });
    on('finish', () => this.finish());
    on('later', () => this.dismiss());
    on('dismiss', () => this.dismiss());
  }

  /** Close the current tour pop-up (× or Esc). Progress is kept for Resume. */
  dismiss() {
    if (this.mode === 'step') return this.exit(true);
    if (this.mode === 'explainer') {
      this.state.mission = Math.min(this.state.mission + 1, MISSIONS.length - 1);
      this.state.step = 0;
      return this.exit(true);
    }
    if (this.mode === 'finished') { this.explainer.hidden = true; this.mode = 'idle'; }
  }

  // ------------------------------------------------------------------ layout
  position() {
    if (this.mode !== 'step' || this.pop.hidden) return;
    const s = this.step;
    const isVisible = (rect) => rect && rect.width > 0 && rect.height > 0 && rect.bottom > 0
      && rect.top < window.innerHeight && rect.right > 0 && rect.left < window.innerWidth;
    // Scenario steps: chip -> Run button (loaded) -> result card (running). No dimming once
    // the user is expected to act or watch, so the UI stays fully usable.
    let sel = s?.target;
    let shade = true;
    if (s?.kind === 'scenario' && this.phase === 'loaded') { sel = RUN_BTN; shade = false; }
    if (s?.kind === 'scenario' && this.phase === 'running') { sel = RESULT_CARD; shade = false; }
    const el = sel ? document.querySelector(sel) : null;
    const r = el?.getBoundingClientRect();
    const visible = isVisible(r);

    const pw = this.pop.offsetWidth, ph = this.pop.offsetHeight;
    const vw = window.innerWidth, vh = window.innerHeight, gap = 16, pad = 12;
    this.pop.classList.remove('place-right', 'place-left', 'place-bottom', 'place-top', 'place-center');

    if (!visible) {
      this.spot.hidden = true; this.dim.hidden = true;
      this.pop.classList.add('place-center');
      this.pop.style.left = `${(vw - pw) / 2}px`;
      this.pop.style.top = `${Math.max(80, (vh - ph) / 2)}px`;
      return;
    }

    const p = 6;
    // Clip the highlight to the viewport (the result card can be taller than the screen).
    const top0 = Math.max(4, r.top - p), bot0 = Math.min(vh - 4, r.bottom + p);
    Object.assign(this.spot.style, { left: `${r.left - p}px`, top: `${top0}px`, width: `${r.width + p * 2}px`, height: `${bot0 - top0}px` });
    this.spot.hidden = false;
    if (!shade) {
      this.dim.hidden = true;
    } else {
      const t = Math.max(0, r.top - p), b = Math.min(vh, r.bottom + p);
      const l = Math.max(0, r.left - p), rt = Math.min(vw, r.right + p);
      const [dTop, dBottom, dLeft, dRight] = this.dim.children;
      Object.assign(dTop.style, { left: '0px', top: '0px', width: `${vw}px`, height: `${t}px` });
      Object.assign(dBottom.style, { left: '0px', top: `${b}px`, width: `${vw}px`, height: `${Math.max(0, vh - b)}px` });
      Object.assign(dLeft.style, { left: '0px', top: `${t}px`, width: `${l}px`, height: `${Math.max(0, b - t)}px` });
      Object.assign(dRight.style, { left: `${rt}px`, top: `${t}px`, width: `${Math.max(0, vw - rt)}px`, height: `${Math.max(0, b - t)}px` });
      this.dim.hidden = false;
    }

    const a = { left: r.left, right: r.right, top: Math.max(r.top, 0), bottom: Math.min(r.bottom, vh) };
    a.height = a.bottom - a.top; a.width = r.width;
    let place, left, top;
    if (a.right + gap + pw < vw - pad) { place = 'right'; left = a.right + gap; top = a.top + a.height / 2 - ph / 2; }
    else if (a.left - gap - pw > pad) { place = 'left'; left = a.left - gap - pw; top = a.top + a.height / 2 - ph / 2; }
    else if (a.bottom + gap + ph < vh - pad) { place = 'bottom'; top = a.bottom + gap; left = a.left + a.width / 2 - pw / 2; }
    else { place = 'top'; top = a.top - gap - ph; left = a.left + a.width / 2 - pw / 2; }

    left = Math.max(pad, Math.min(left, vw - pw - pad));
    top = Math.max(pad, Math.min(top, vh - ph - pad));
    this.pop.classList.add(`place-${place}`);
    this.pop.style.left = `${left}px`;
    this.pop.style.top = `${top}px`;
    const arrow = this.pop.querySelector('.tour-pop-arrow');
    if (arrow) {
      if (place === 'right' || place === 'left') {
        arrow.style.top = `${Math.max(16, Math.min(ph - 16, a.top + a.height / 2 - top))}px`; arrow.style.left = '';
      } else {
        arrow.style.left = `${Math.max(16, Math.min(pw - 16, a.left + a.width / 2 - left))}px`; arrow.style.top = '';
      }
    }
  }
}

// Bootstrap once app.js has exposed window.guardrailApp.
function boot() {
  if (window.guardrailTour || !window.guardrailApp) return;
  window.guardrailTour = new GuidedTour(window.guardrailApp);
  document.getElementById('headerTourBtn')?.addEventListener('click', () => window.guardrailTour.open());
}
if (window.guardrailApp) boot(); else window.addEventListener('guardrail:ready', boot, { once: true });
