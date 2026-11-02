# Apigee X AI Gateway: Layered Guardrails Demo
### Static Guardrails · Google Cloud Model Armor · NVIDIA NeMo Guardrails — in front of Gemini, with real-time SSE streaming

[![Apigee X](https://img.shields.io/badge/Google%20Cloud-Apigee%20X-4285F4?logo=googlecloud&logoColor=white)](https://cloud.google.com/apigee)
[![Model Armor](https://img.shields.io/badge/Security-Model%20Armor-34A853?logo=googlecloud&logoColor=white)](https://cloud.google.com/security/products/model-armor)
[![NVIDIA NeMo](https://img.shields.io/badge/NVIDIA-NeMo%20Guardrails-76B900?logo=nvidia&logoColor=white)](https://github.com/NVIDIA/NeMo-Guardrails)
[![Vertex AI](https://img.shields.io/badge/Vertex%20AI-Gemini%203.5%20Flash%20Lite-EA4335?logo=googlecloud&logoColor=white)](https://cloud.google.com/vertex-ai)
[![Cloud Run](https://img.shields.io/badge/Deployment-Cloud%20Run-4285F4?logo=googlecloud&logoColor=white)](https://cloud.google.com/run)

---

> [!CAUTION]
> ### ⚠️ Content Disclaimer & Warning
> This demonstration repository contains test prompts, adversarial examples, and preset test templates that include **explicit, offensive, abusive, profane, or hostile language** across multiple languages (including English, Simplified Chinese, Vietnamese, Thai, and Japanese).
>
> **These phrases are included strictly and exclusively for testing, evaluating, and demonstrating the effectiveness of LLM safety guardrails and AI Gateway threat interception.**
>
> They do not reflect the opinions, values, beliefs, or endorsements of the repository author, Google, or its affiliates.
>
> **This is not an official Google product.**

---

## 🎯 Intention & Business Problem

No single guardrail catches everything, and each one has a different cost and latency profile. This demo shows how Apigee X can **layer** guardrails in front of an LLM so that each request is stopped by the cheapest layer that recognises it:

| Layer | Where it runs | Typical latency | Catches |
| :--- | :--- | :--- | :--- |
| **Static Guardrails** | Inside Apigee (SharedFlow, JavaScript) | ~50–80 ms | Known patterns: SQL injection, leaked secrets, classic jailbreak phrases, multilingual abuse word lists. Can also **redact** secrets/PII in responses. |
| **Model Armor** | Google Cloud API (`SanitizeUserPrompt` / `SanitizeModelResponse`) | ~400–800 ms | Meaning-based detection: prompt injection & jailbreak, harmful content (RAI), sensitive data (SDP), malicious URLs — in many languages, with no word lists to maintain. Works **mid-stream** on SSE responses. |
| **NVIDIA NeMo Guardrails** | Cloud Run service called via ServiceCallout | ~0.8–1.2 s | **Your business rules**, judged by an LLM: topic control (e.g. no investment advice), plus role-play jailbreaks and content safety. Catches prompts that are safe but not allowed for your app. |

Requests that are blocked early generate **zero LLM tokens and zero inference cost**. For streamed responses, Model Armor can cut the stream the moment harmful content appears.

### 🧩 How the layers complement each other

Each layer answers a **different question**, so they don't duplicate each other:

| Layer | Question it answers | Policy comes from |
| :--- | :--- | :--- |
| **Static Guardrails** | *"Is this a known attack?"* | Regex and word lists you maintain |
| **Model Armor** | *"Is this harmful for anyone?"* | Google-managed safety and security categories |
| **NeMo Guardrails** | *"Is this allowed for **this** app?"* | Your own business rules, in plain language |

Static Guardrails and Model Armor stop what is **dangerous for everyone**. Neither one knows what is **off-limits for your business**, and that's the gap NeMo fills.

> **Example:** *"Which cryptocurrency should I move my retirement savings into this week?"*
> - **Static Guardrails** pass it: there is no attack pattern.
> - **Model Armor** passes it: the prompt isn't harmful.
> - **NeMo** blocks it: this support assistant must not give investment advice (`topic_control` rail).

Because NeMo runs **last**, its ~1 s LLM-as-judge check is only spent on traffic the cheaper layers have already cleared. Its rules (topics, tone, refusals) live in NeMo config, so you can change business policy without touching Apigee policies or Model Armor templates.

### 🎭 NeMo business personas

Pick **NeMo → Profile: Topic** in the UI and a **NeMo persona** picker appears with the persona's allowed and forbidden topics. Six personas ship with the demo: ☁️ Cloud Support (default), 🏦 Bank, 🩺 Healthcare, ✈️ Airline, 📶 Telco and 🛍️ Retail. Run the same prompt under two personas to see the verdict flip, e.g. *"Can I take ibuprofen with my blood pressure medication?"* is blocked as Bank and allowed as Healthcare (guided-tour mission *Same prompt, different business*).

Personas are defined once in [`nemo-guardrails/personas.json`](nemo-guardrails/personas.json). To add or change one:

```bash
python3 nemo-guardrails/build_personas.py          # regenerate NeMo configs + demo-ui/static/nemo-personas.js
python3 nemo-guardrails/persona_judge_check.py     # check expected verdicts against the judge model (pre-deploy)
# add new ids to NEMO_PROFILES (demo-ui/app.py) and ALLOWED_PROFILES (nemo-input.js); --check verifies this
python3 nemo-guardrails/build_personas.py --check
```
Then redeploy `nemo-guardrails` and `guardrail-proxy`, and run `guardrail-proxy/tests/persona_matrix_test.py`.

---

## 🏛️ High-Level Architecture

<p align="center">
  <img src="demo-ui/static/assets/architecture-diagram.png" alt="Apigee X AI Gateway with Static Guardrails, Model Armor and NeMo Guardrails" width="100%">
</p>

```
Browser ─► demo-ui (Cloud Run, IAP) ─► Apigee guardrail-proxy ─┬─► StaticGuardrails SharedFlow   (inbound + outbound)
                                                               ├─► Model Armor SUP / SMR         (inbound + mid-stream outbound)
                                                               ├─► nemo-guardrails (Cloud Run)   (inbound, optional profile)
                                                               ├─► Vertex AI Gemini  streamGenerateContent?alt=sse
                                                               └─► Cloud Logging                 (PostClientFlow audit & telemetry)
```

Each layer can be switched per request with headers set by the UI (`x-static-guardrails`, `x-static-outbound`, `x-inbound`, `x-outbound`, `x-nemo-guardrails`, `x-nemo-profile`), so the same proxy can demonstrate any combination.

---

## 🖥️ Demonstration Web UI

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/webui-screenshot-dark.png">
    <img src="docs/images/webui-screenshot.png" alt="Apigee and Guardrails Solutions Web UI" width="100%">
  </picture>
</p>

* **Test Scenario** — tabs for *Baseline*, *Static*, *Model Armor*, *NeMo* and *Layered* scenarios. With **Auto-configure layers** on, picking a scenario also sets the right policies.
* **Prompt** — editable prompt with the expected outcome of the selected scenario.
* **Inspection Policies** — one grid for all three layers (inbound / outbound / NeMo rail), with presets *Strict*, *Safe-flow*, *Observe* and *Off*, plus ⓘ details for each layer and a *When to choose what* comparison modal.
* **Demo Architecture** — quick-access card in the bottom-left panel (and header button) opening the interactive 3-layer architecture diagram and 5-step flow breakdown.
* **Results** — live SSE token stream, TTFT and total duration, which layer blocked (and why), the Model Armor findings, and a raw SSE chunk timeline.
* **Guided Tour** — 8 short missions (plus a bonus) that walk through each layer. The *What just happened?* panel explains every result, e.g. when Static Guardrails miss a reworded jailbreak and Model Armor catches it.
* **Admin Panel** — slide-out audit analytics drawer (block rate, violation types, recent events), synced from Cloud Logging (`apigee-ai-sanitized-prompts`).
* **Test Lab** — header button that opens the Guardrail Test Lab in a new tab (see below).

---

## 🧪 Guardrail Test Lab (OWASP)

<p align="center">
  <img src="docs/images/testlab-screenshot.png" alt="Guardrail Test Lab" width="100%">
</p>

`testlab.html` shows how much each layer catches on the **Curated OWASP suite**: 102 hand-written cases (88 attacks, 14 safe prompts) mapped to the OWASP Top 10 for LLM Applications (2025) and the OWASP API Security Top 10 (2023). Every attack runs against each layer on its own (Static, Model Armor, NeMo), then with all layers on.

* **Test runs** (left sidebar) — one entry per run, grouped by test set, with *caught* and *safe prompts blocked*. Two profiles: **Balanced** and **Strictest** (Static strict · Model Armor strict · NeMo all rails). Drag the edge to resize; **«** or `[` collapses it.
* **Overview** — catch rate per layer, which layer catches first, and the gaps.
* **Results** — every case with each layer's verdict, filters and quick views (*Attacks missed*, *Safe prompts blocked*, *Flaky*), CSV export, and *Load in playground*.
* **Test catalogue** and **Coverage map** — what each case tests, and which OWASP risks are tested or out of scope for a gateway.

Run the suite yourself (needs a test app key; results land in `demo-ui/static/testlab/`):

```bash
APIGEE_SUITE_KEY=... python3 tests/owasp/run_suite.py --set curated                       # Balanced
APIGEE_SUITE_KEY=... python3 tests/owasp/run_suite.py --set curated --profile strictest   # Strictest
```

> [!NOTE]
> LLM-based layers (Model Armor, NeMo) can vary slightly between runs; inconsistent cases are re-run and marked *flaky*. This is a small hand-written suite that checks coverage, not a statistical benchmark.

---

## 📦 Repository Structure

```
├── guardrail-proxy/              # Apigee API proxy (basepath /guardrail-proxy)
│   ├── apiproxy/
│   │   ├── proxies/default.xml   # VerifyAPIKey, layer flags, FlowCallout to StaticGuardrails, NeMo callout
│   │   ├── targets/default.xml   # Vertex AI streamGenerateContent (SSE), SUP / SMR, outbound scan in EventFlow
│   │   ├── policies/             # SUP-userprompt, SMR-modelresponse, SC-NeMo-Input, JS-SG-Outbound-Scan, ...
│   │   └── resources/jsc/        # nemo-*.js, sg-*.js (outbound redaction)
│   └── tests/                    # scenario_presets_test.py (live end-to-end check of every UI scenario)
├── StaticGuardrails/             # Apigee SharedFlow + environment property set "sg"
│   ├── sharedflowbundle/         # extract/normalise, structure, lexicon, regex rules, verdict
│   ├── src/sg.properties.src     # word lists & rules (UTF-8 source)
│   ├── build.py                  # generates env/sg.properties (\uXXXX-escaped)
│   ├── deploy.sh                 # deploys property set, SharedFlow and guardrail-proxy
│   └── tests/                    # local JS harnesses + live test
├── nemo-guardrails/              # NVIDIA NeMo Guardrails server for Cloud Run
│   ├── configs/                  # jailbreak_self_check, content_safety, topic_control (+ default, pii_masking, agentic_security)
│   ├── entrypoint.py, Dockerfile
│   └── test_guardrails.py
├── demo-ui/                      # Demo web app (Python stdlib server + static front end)
│   ├── app.py                    # SSE proxy to Apigee, admin analytics API, Cloud Logging sync
│   ├── Dockerfile                # non-root python:3.11-slim image
│   └── static/                   # index.html, app.js, style.css, assets/architecture-diagram.png, tour/
│       ├── testlab.html          # Guardrail Test Lab
│       └── testlab/              # Test Lab script, styles and the curated suite's results
├── tests/owasp/                  # Curated OWASP suite: case builders, cases.json, run_suite.py, results/
├── model-armor/                  # Model Armor + SDP template setup and the inbound preset sweep
├── docs/images/                  # Web UI and Test Lab screenshots for README
├── setup-developer-app.sh        # creates the API product + developer app used by VerifyAPIKey
└── run-demo.sh                   # runs the UI locally (fetches the API key from Secret Manager)
```

---

## 🚀 Getting Started & Deployment

### 1. Prerequisites

| Google Cloud Service | Role | APIs | IAM |
| :--- | :--- | :--- | :--- |
| **Apigee X** | Hosts `guardrail-proxy` and the `StaticGuardrails` SharedFlow | `apigee.googleapis.com` | `roles/apigee.admin` (deploy) |
| **Model Armor** | Templates `guardrail-proxy-{in,out}-{strict,balanced,permissive}` + SDP inspect template `guardrail-proxy-sdp` (location `us`), created by `python3 model-armor/setup_ma_templates.py` | `modelarmor.googleapis.com`, `dlp.googleapis.com` | `roles/modelarmor.user` on the Apigee runtime SA |
| **Vertex AI** | Gemini 3.5 Flash Lite via `streamGenerateContent?alt=sse` | `aiplatform.googleapis.com` | `roles/aiplatform.user` on the Apigee runtime SA |
| **Cloud Run** | Hosts `nemo-guardrails` and `demo-ui` | `run.googleapis.com` | `roles/run.admin` (deploy) |
| **Secret Manager** | Stores the Apigee consumer key for `demo-ui` | `secretmanager.googleapis.com` | `roles/secretmanager.secretAccessor` on the UI service account |
| **Cloud Logging** | Audit trail shown in the Admin Panel | `logging.googleapis.com` | `roles/logging.viewer` on the UI service account |
| **IAP** (recommended) | Restricts the UI to your organisation | `iap.googleapis.com` | `roles/iap.httpsResourceAccessor` |

Local tools: `gcloud`, [`apigeecli`](https://github.com/apigee/apigeecli), Python 3.10+, Node.js (for the Static Guardrails harnesses).

### 2. Deploy NeMo Guardrails

```bash
gcloud run deploy nemo-guardrails --source nemo-guardrails --region ${REGION} --project ${PROJECT_ID}
```
Then set its URL in `guardrail-proxy/apiproxy/policies/SC-NeMo-Input.xml`.

### 3. Deploy Static Guardrails and the proxy

```bash
./StaticGuardrails/deploy.sh ${PROJECT_ID} ${ENV_NAME}     # property set + SharedFlow + guardrail-proxy
./setup-developer-app.sh ${PROJECT_ID} ${ENV_NAME} ${DEVELOPER_EMAIL}
```

### 4. Store the API key and run the UI

```bash
# Store the developer app's consumer key in Secret Manager
printf %s "${CONSUMER_KEY}" | gcloud secrets create apigee-modelarmor-demo-api-key --data-file=- --project ${PROJECT_ID}

# Option A: run locally (reads the key from Secret Manager, or from $APIGEE_API_KEY)
./run-demo.sh                       # http://localhost:8085

# Option B: Cloud Run behind IAP
gcloud run deploy apigee-modelarmor-demo --source demo-ui --region ${REGION} --project ${PROJECT_ID} \
  --service-account ${UI_SERVICE_ACCOUNT} \
  --set-secrets APIGEE_API_KEY=apigee-modelarmor-demo-api-key:latest \
  --set-env-vars GCP_PROJECT_ID=${PROJECT_ID},STREAMING_SSE_URL=https://${APIGEE_HOST}/guardrail-proxy \
  --timeout 300 --no-allow-unauthenticated --iap
```

### 5. Verify

```bash
APIGEE_API_KEY=... python3 guardrail-proxy/tests/scenario_presets_test.py   # all UI scenarios, live
```

---

## 🧪 Preset Test Scenarios

| Group | Scenario | Expected result |
| :--- | :--- | :--- |
| Baseline | Benign Math (2+2) · False-Positive Check (SQLi explainer) · Long Story | 200 OK, streamed |
| Static | SQL Injection · Leaked Secret (AWS key) · Thai Abuse | Blocked by Static Guardrails (~60 ms) |
| Static | Outbound Redaction (secret + PII) | 200 OK with `[REDACTED:…]` in the stream |
| Model Armor | Jailbreak / DAN (evades regex) · 中文 Toxicity · Tiếng Việt Toxicity · Sensitive Data (card + SSN) | Blocked by Model Armor on the prompt (400) |
| Model Armor | Partial Hate Speech (mid-stream) | Stream starts, then is cut by Model Armor |
| NeMo | Off-Topic (crypto advice) · Roleplay Jailbreak (FreeGPT) · Harmful Intent | Blocked by NeMo rails |
| NeMo | Persona flip: Bank → Healthcare (same medication question) | Bank: blocked by the topic rail · Healthcare: 200 OK |
| Layered | Classic DAN → Static · Roleplay → Model Armor · Crypto Advice → NeMo | All layers on; the first layer that recognises the threat blocks it |

---

## 📄 License
Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
