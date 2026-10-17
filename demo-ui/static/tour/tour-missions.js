/**
 * Guided Tour - mission definitions (Apigee and Guardrails Solutions demo).
 *
 * Purely declarative: tour-engine.js renders and sequences these. Each mission
 * is a list of steps; a mission is complete when its last step completes.
 *
 * Step fields
 *   kind        'action' | 'scenario'
 *   title/body  coachmark copy (body is trusted, authored HTML)
 *   target      CSS selector for the spotlight ('scenario' steps: the preset chip)
 *   scenario    scenario id from SCENARIOS in app.js ('scenario' steps)
 *   action      { label, run(engine) } primary button on 'action' steps
 *   before(engine)  optional setup when the step is shown
 *   expect      short "Expected:" line
 *   done        { click: selector } | { outcome: [..] }   (outcome from 'guardrail:runresult')
 *
 * Run outcomes: clean | redacted | static-in | static-out | ma-in | ma-out | nemo | error
 */

export const OUTCOME_LABEL = {
  clean: 'Completed: no layer blocked it',
  redacted: 'Completed with in-stream redaction (Static Guardrails)',
  'static-in': 'Blocked by Static Guardrails (inbound)',
  'static-out': 'Stream cut by Static Guardrails (outbound)',
  'ma-in': 'Blocked by Model Armor (SanitizeUserPrompt)',
  'ma-out': 'Stream cut by Model Armor (SanitizeModelResponse)',
  nemo: 'Blocked by NVIDIA NeMo Guardrails',
  error: 'Request failed',
};

const archOpen = () => {
  const o = document.getElementById('archModalOverlay');
  return !!o && o.style.display !== 'none';
};

export const MISSIONS = [
  // ---------------------------------------------------------------- 1
  {
    id: 'architecture',
    title: 'Meet the architecture',
    badge: 'Overview',
    steps: [
      {
        kind: 'action',
        title: 'Your control panel',
        target: '#policiesSection',
        before: () => {
          const sec = document.getElementById('policiesSection');
          if (sec?.classList.contains('collapsed')) document.getElementById('policiesCollapseToggle')?.click();
        },
        body: `This demo has three guardrail layers. Turn each one on or off for each direction:
          <ul>
            <li><b>In</b>: checks the prompt before Gemini sees it</li>
            <li><b>Out</b>: checks the streamed answer as it's generated</li>
            <li><b>Profile</b>: Static <i>Balanced</i> / <i>Strict</i>, Model Armor's template, NeMo's rail</li>
          </ul>
          Use the presets (<b>Strict</b>, <b>Safe-flow</b>, <b>Observe</b>, <b>Off</b>) to set every layer at once;
          <b>Strict</b> also switches Static Guardrails to the strict profile.
          Click <b>ⓘ</b> to learn more about a layer. In this tour, each scenario sets the layers for you.`,
        action: { label: 'Got it', run: (e) => e.completeStep() },
      },
      {
        kind: 'action',
        title: 'Meet the architecture',
        target: '#btnOpenArchModal',
        body: `Every prompt to Gemini goes through <b>Apigee</b> first. Apigee runs
          the three layers in order, cheapest first:
          <ul>
            <li><b>Static Guardrails</b>: regex and word-list checks inside Apigee (~80 ms)</li>
            <li><b>Model Armor</b>: Google Cloud's AI safety filters, for prompts and responses</li>
            <li><b>NVIDIA NeMo</b>: an LLM judge on Cloud Run for jailbreaks, safety and topic rules</li>
          </ul>`,
        action: { label: 'Open the diagram', run: () => document.getElementById('btnOpenArchModal')?.click() },
        done: { click: '#btnOpenArchModal' },
      },
    ],
    explainer: {
      title: 'The request path',
      flow: [
        { text: 'Client sends the prompt to the Apigee guardrail-proxy (API key checked)', state: 'ok' },
        { text: 'Static Guardrails check the prompt with regex and word lists', state: 'ok' },
        { text: 'Model Armor SanitizeUserPrompt checks the prompt', state: 'ok' },
        { text: 'NeMo Guardrails check the prompt via a ServiceCallout', state: 'ok' },
        { text: 'Gemini streams the answer; each SSE event is checked by Static (out) and Model Armor SanitizeModelResponse', state: 'ok' },
      ],
      note: 'You can reopen the diagram at any time from <b>Architecture</b> in the header.',
    },
  },

  // ---------------------------------------------------------------- 2
  {
    id: 'baseline',
    title: 'No false alarms',
    badge: '200',
    steps: [{
      kind: 'scenario',
      scenario: 'benign-fp-sqli',
      title: 'No false alarms',
      target: '[data-scenario="benign-fp-sqli"]',
      body: `Start with a safe question that sounds risky: <i>"Explain what SQL injection is…"</i>.
        A good guardrail must <b>not</b> block it. All layers are on.`,
      expect: '200 OK: the answer streams normally',
      done: { outcome: ['clean'] },
    }, {
      kind: 'scenario',
      scenario: 'benign-code-review',
      title: 'Flag it, don\'t block it',
      target: '[data-scenario="benign-code-review"]',
      body: `Now paste a <b>real</b> SQL injection payload, but inside a code block with a review question.
        Static Guardrails run in the <b>balanced</b> profile: they are a first line of defence, so when the
        context looks legitimate they <b>flag</b> the payload instead of blocking it and let Model Armor decide.
        Look for <code>[STATIC] … verdict=flag</code> in the event log.`,
      expect: '200 OK: Static flags SG-SQL-002, Model Armor and NeMo pass it',
      done: { outcome: ['clean'] },
    }],
    explainer: {
      title: 'Talking about attacks is not an attack',
      flow: [
        { text: 'Static Guardrails: no payload in the explainer; the code-review payload was flagged, not blocked', state: 'ok' },
        { text: 'Model Armor: no prompt injection or harmful content', state: 'ok' },
        { text: 'NeMo jailbreak check: passed', state: 'ok' },
        { text: 'Gemini streamed the answer; outbound checks found nothing', state: 'ok' },
      ],
      note: 'Static rules block real payloads such as <code>\' OR \'1\'=\'1</code>, not the words "SQL injection". In the balanced profile, a payload that is quoted, discussed or pasted for review is <b>flagged</b> and passed to Model Armor. Use the <b>strict</b> profile (header <code>x-static-profile</code>) for agentic apps where payloads can execute.',
    },
  },

  // ---------------------------------------------------------------- 3
  {
    id: 'static',
    title: 'Static Guardrails stop a known attack',
    badge: 'Static',
    steps: [{
      kind: 'scenario',
      scenario: 'static-sqli',
      title: 'Stop a known attack fast',
      target: '[data-scenario="static-sqli"]',
      body: `Send a real SQL injection payload. Known patterns are the cheapest to catch,
        so Apigee checks them first with <b>regex rules</b>. No AI model is called.`,
      expect: '400 from Static Guardrails in ~80 ms',
      done: { outcome: ['static-in'] },
    }, {
      kind: 'scenario',
      scenario: 'static-zh-tw',
      title: 'Same rules, Traditional Chinese',
      target: '[data-scenario="static-zh-tw"]',
      body: `This prompt hides a jailbreak in <b>Traditional Chinese</b> (繁體中文), as used in Taiwan and Hong Kong.
        Apigee converts Traditional characters to Simplified before checking, so <b>one rule set</b>
        covers TW, HK and mainland Chinese, with no duplicated rules.`,
      expect: '400 from Static Guardrails (SG-PI-006)',
      done: { outcome: ['static-in'] },
    }],
    explainer: {
      title: 'Cheapest layer first',
      flow: [
        { text: 'StaticGuardrails SharedFlow matched a known pattern (SG-SQL-*, SG-PI-006)', state: 'fail' },
        { text: 'Apigee returned 400 straight away', state: 'fail' },
        { text: 'Model Armor: not called', state: 'skip' },
        { text: 'NeMo: not called', state: 'skip' },
        { text: 'Gemini: not called (no tokens used)', state: 'skip' },
      ],
      note: 'Static rules (balanced profile) are fast and predictable, but only catch patterns you list, in any script you normalise. Rewording slips past them, so the next layers handle the rest.',
    },
  },

  // ---------------------------------------------------------------- 4
  {
    id: 'ma-inbound',
    title: 'Static misses it, Model Armor catches it',
    badge: 'SUP',
    steps: [{
      kind: 'scenario',
      scenario: 'ma-jailbreak',
      title: 'When regex is not enough',
      target: '[data-scenario="ma-jailbreak"]',
      body: `Static Guardrails are <b>on</b>. They block the classic wording
        ("ignore previous instructions", "you are now DAN"). This prompt makes the same jailbreak in
        <i>different words</i>, so no regex rule matches and it gets past Static.
        The next layer, <b>Model Armor</b>, understands what the prompt means and stops it.`,
      expect: 'Passes Static Guardrails → 400 from Model Armor (prompt injection)',
      done: { outcome: ['ma-in'] },
    }],
    explainer: {
      title: 'Static missed it, Model Armor caught it',
      handoff: {
        missed: 'Static Guardrails',
        caught: 'Model Armor',
        text: 'The reworded jailbreak has none of the keywords the regex rules look for, so Static Guardrails let it through. Model Armor understood what the prompt meant and blocked it.',
      },
      flow: [
        { text: 'Static Guardrails (on): no regex / word-list rule matched the reworded jailbreak', state: 'miss', tag: 'MISSED' },
        { text: 'Model Armor template ma-ai-gw-inbound found prompt injection / jailbreak', state: 'fail', tag: 'BLOCKED' },
        { text: 'Gemini: not called (Apigee returned 400)', state: 'skip', tag: 'NOT CALLED' },
      ],
      note: 'Regex only catches the exact patterns you list. Model Armor understands meaning, so it also catches harmful content, sensitive data (SDP) and malicious URLs, in many languages, with no word lists to maintain.',
    },
  },

  // ---------------------------------------------------------------- 5
  {
    id: 'ma-outbound',
    title: 'Cut a harmful answer mid-stream',
    badge: 'SMR',
    steps: [{
      kind: 'scenario',
      scenario: 'ma-partial-hate',
      title: 'Cut a harmful answer mid-stream',
      target: '[data-scenario="ma-partial-hate"]',
      body: `This prompt <i>looks</i> safe, but it tricks Gemini into repeating hateful text partway through the answer.
        Only the outbound check is on. Watch the right panel: the answer starts, then stops.`,
      expect: 'Stream starts, then SanitizeModelResponse cuts it',
      done: { outcome: ['ma-out'] },
    }],
    explainer: {
      title: 'Checking the answer while it streams',
      flow: [
        { text: 'Inbound checks: Off, so the prompt reached Gemini', state: 'skip' },
        { text: 'Gemini began streaming; the first chunks reached the client', state: 'ok' },
        { text: 'Apigee EventFlow sent buffered chunks to Model Armor SanitizeModelResponse', state: 'ok' },
        { text: 'Harmful text detected: Apigee ended the SSE stream', state: 'fail' },
      ],
      note: 'Streaming means some safe tokens arrive before the cut ("partial leakage"). That trade-off is why inbound checks matter too.',
    },
  },

  // ---------------------------------------------------------------- 6
  {
    id: 'nemo',
    title: 'NeMo enforces a topic policy',
    badge: 'NeMo',
    steps: [{
      kind: 'scenario',
      scenario: 'nemo-topic',
      title: 'Enforce a business topic policy',
      target: '[data-scenario="nemo-topic"]',
      body: `Ask for crypto investment advice. It isn't harmful, so Static and Model Armor let it through,
        but this business doesn't allow financial advice. The <b>NeMo topic rail</b> enforces that.
        <br><small>The first NeMo call can take ~20 s while Cloud Run starts up.</small>`,
      expect: '400 from the NeMo topic rail',
      done: { outcome: ['nemo'] },
    }],
    explainer: {
      title: 'Policy, not just safety',
      flow: [
        { text: 'Static Guardrails: no pattern matched', state: 'ok' },
        { text: 'Model Armor: not harmful, passed', state: 'ok' },
        { text: 'NeMo topic rail (LLM judge) found an off-topic request', state: 'fail' },
        { text: 'Apigee returned 400; Gemini was not called', state: 'fail' },
      ],
      note: 'NeMo runs on Cloud Run and is called with an Apigee ServiceCallout, so it is inbound only.',
    },
  },

  // ---------------------------------------------------------------- 7
  {
    id: 'layered',
    title: 'Defense in depth',
    badge: 'All on',
    steps: [{
      kind: 'scenario',
      scenario: 'layered-roleplay',
      title: 'All layers on: who catches it?',
      target: '[data-scenario="layered-roleplay"]',
      body: `Every layer is on. This role-play jailbreak ("You are FreeGPT…") contains none of the
        keywords the regex rules look for. See which layer stops it.`,
      expect: 'Passes Static, stopped by Model Armor in ~0.4 s',
      done: { outcome: ['ma-in', 'nemo'] },
    }],
    explainer: {
      title: 'The first layer that recognises it wins',
      flow: [
        { text: 'Static Guardrails: no known pattern, passed', state: 'ok' },
        { text: 'Model Armor recognised the jailbreak and blocked it', state: 'fail' },
        { text: 'NeMo: not called, so no extra time or cost', state: 'skip' },
        { text: 'Gemini: not called', state: 'skip' },
      ],
      note: 'Layering keeps known attacks cheap (Static), covers new ones (Model Armor), and adds business policy (NeMo).',
    },
  },

  // ---------------------------------------------------------------- 8
  {
    id: 'audit',
    title: 'See it in the audit log',
    badge: 'Logs',
    steps: [{
      kind: 'action',
      title: 'See it in the audit log',
      target: '#btnScrollToAdmin',
      body: `Every run you just did was logged. Open the <b>Admin Panel</b> to see blocked
        vs. allowed traffic, the reasons for each block, and the full payload of each event.`,
      action: { label: 'Open Admin Panel', run: () => document.getElementById('btnScrollToAdmin')?.click() },
      done: { click: '#btnScrollToAdmin, #floatingAdminTrigger' },
    }],
    explainer: {
      title: 'Security analytics',
      flow: [
        { text: 'Apigee MessageLogging sends each guardrail decision to Cloud Logging', state: 'ok' },
        { text: 'The Admin Panel shows traffic per proxy and why requests were blocked', state: 'ok' },
        { text: 'Click any row to see the full payload', state: 'ok' },
      ],
    },
  },

  // ---------------------------------------------------------------- bonus
  {
    id: 'redact',
    bonus: true,
    title: 'Bonus: Redact instead of block',
    badge: 'Redact',
    steps: [{
      kind: 'scenario',
      scenario: 'static-redact',
      title: 'Bonus: Redact instead of block',
      target: '[data-scenario="static-redact"]',
      before: (e) => e.closeAdmin(),
      body: `Sometimes you want the answer, minus the secrets. With Static <b>Out = Redact</b>,
        Apigee masks an AWS key and an email address inside the stream instead of stopping it.`,
      expect: '200 OK with [REDACTED:…] tags in the answer',
      done: { outcome: ['redacted'] },
    }],
    explainer: {
      title: 'Masking in-flight',
      flow: [
        { text: 'Inbound checks: Off for this scenario', state: 'skip' },
        { text: 'Gemini printed an AWS key and an email address', state: 'ok' },
        { text: 'The EventFlow JS scanner replaced them with [REDACTED:SG-…] tags in the stream', state: 'ok' },
        { text: 'The stream finished normally; nothing sensitive reached the client', state: 'ok' },
      ],
      note: 'A short hold-back buffer (~64 characters) lets values that are split across SSE events still be caught.',
    },
  },

  // ---------------------------------------------------------------- bonus
  {
    id: 'profiles',
    bonus: true,
    title: 'Bonus: Balanced vs Strict',
    badge: 'Profile',
    steps: [{
      kind: 'action',
      title: 'Two Static Guardrails profiles',
      target: '#staticProfile',
      before: (e) => {
        e.closeAdmin();
        const sec = document.getElementById('policiesSection');
        if (sec?.classList.contains('collapsed')) document.getElementById('policiesCollapseToggle')?.click();
      },
      body: `Static Guardrails have two <b>profiles</b>:
        <ul>
          <li><b>Balanced</b> (default): a first line of defence. Only near-certain signals block; anything
            ambiguous is <b>flagged</b> and Model Armor decides.</li>
          <li><b>Strict</b>: every known pattern blocks, whatever the context. Use it for agents with
            SQL or shell tools, where a payload could actually run.</li>
        </ul>
        Model Armor is tuned differently: in its <b>template</b> (Template ↗ link in the same column).`,
      action: { label: 'Next', run: (e) => e.completeStep() },
    }, {
      kind: 'scenario',
      scenario: 'strict-code-review',
      title: 'Same prompt, Strict profile',
      target: '[data-scenario="strict-code-review"]',
      body: `This is the same code-review prompt as in mission 2, which Balanced only <b>flagged</b>.
        With the <b>Strict</b> profile, Static Guardrails block the payload at the gateway, whatever the context.`,
      expect: '400 from Static Guardrails (SG-SQL-002) in ~80 ms',
      done: { outcome: ['static-in'] },
    }],
    explainer: {
      title: 'Same payload, two decisions',
      flow: [
        { text: 'Balanced: payload in a code block with a review question → flagged, Model Armor allowed it (200)', state: 'ok' },
        { text: 'Strict: same payload → blocked by Static Guardrails (400), no Model Armor or Gemini cost', state: 'fail' },
        { text: 'Admin Panel → "Static Flagged → Model Armor Verdict" shows which flagged rules Model Armor confirms', state: 'ok' },
      ],
      note: 'Balanced blocked 0 of 249 normal benchmark prompts; Strict blocked 21. Both block every clear-cut attack. Use <code>sev.overrides</code> to promote individual rules that Model Armor keeps confirming.',
    },
  },
];

export { archOpen };
