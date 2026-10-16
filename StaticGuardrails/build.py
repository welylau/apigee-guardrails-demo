#!/usr/bin/env python3
# ##############################################################################
# !!  CONTENT WARNING - OFFENSIVE LANGUAGE  !!
# This file contains regular expressions that match PROFANITY, THREATS, SELF-HARM
# phrases and attack payloads. They exist ONLY so the demo guardrail can DETECT and
# BLOCK them. They do not reflect the views of the author or Google.
# FOR DEMO / EDUCATIONAL PURPOSES ONLY - NOT A PRODUCTION-GRADE RULE SET.
# ##############################################################################
"""
StaticGuardrails build script (single source of truth for regex rules).

Generates, from the RULES catalog below:
  1. sharedflowbundle/policies/RE-SG-*.xml      (RegularExpressionProtection, Java regex, inbound BLOCK rules)
  2. sharedflowbundle/resources/jsc/sg-rules.js  (same rules as JS RegExp, used for rule-ID attribution,
                                                  FLAG rules and outbound EventFlow scanning)
  3. env/sg.properties (from src/sg.properties.src, non-ASCII -> \\uXXXX). This is uploaded as an
     ENVIRONMENT-scoped property set named "sg" (see deploy.sh): property sets bundled inside a
     SharedFlow are NOT readable via propertyset.sg.* (verified on Apigee X), and env scope lets the
     lexicon be updated without redeploying the SharedFlow.
  4. Copies sg-common.js + sg-rules.js into guardrail-proxy/apiproxy/resources/jsc/ (EventFlow cannot
     call a SharedFlow, so the outbound scanner needs its own copy).

Usage:  python3 StaticGuardrails/build.py
Only uses the Python standard library.
"""

import json
import os
import re
import shutil
from xml.sax.saxutils import escape as xml_escape

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "sharedflowbundle")
PROXY_JSC = os.path.join(HERE, "..", "guardrail-proxy", "apiproxy", "resources", "jsc")

# ---------------------------------------------------------------------------
# Rule catalog
#   src : "norm" = lower-cased, zero-width stripped, full-width folded text (sg.prompt_norm)
#         "raw"  = original text, case-sensitive (sg.prompt_raw)
#   sev_in / sev_out : "BLOCK" | "FLAG" | None (rule not applied in that direction)
# Patterns MUST be valid in both Java and JavaScript regex dialects:
#   no lookbehind, no possessive quantifiers, no named groups, bounded quantifiers only.
# ---------------------------------------------------------------------------
RULES = [
    # --- Prompt injection / jailbreak -------------------------------------
    dict(id="SG-PI-001", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Instruction override (ignore previous instructions)",
         re=r"\b(ignore|disregard|forget|override)\b.{0,20}\b(previous|prior|above|earlier|system)\s+(instructions?|rules|prompts?|directives)"),
    dict(id="SG-PI-002", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="DAN / developer-mode persona",
         re=r"\byou\s+are\s+(now\s+)?dan\b|\bdo\s+anything\s+now\b|\b(developer|god|unfiltered)\s+mode\b"),
    dict(id="SG-PI-003", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="System prompt extraction",
         re=r"\b(reveal|print|show|output|repeat|leak|display)\b.{0,30}\b(system|hidden|initial|original)\s+(prompt|instructions?|message)"),
    dict(id="SG-PI-004", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Chat-template delimiter / role token injection",
         re=r"<\|im_(start|end)\|>|\[/?inst\]|<</?sys>>|</?system>|(^|\s)#{2,}\s*(system|assistant)\s*:"),
    dict(id="SG-PI-005", cat="prompt_injection", src="norm", sev_in="FLAG", sev_out=None,
         desc="Roleplay restriction bypass",
         re=r"\bpretend\b.{0,20}\b(no|without)\s+(rules|restrictions|filters|limits)\b|\bjailbreak"),
    dict(id="SG-PI-006", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Instruction override in ZH / JA / VI / TH (needs native-speaker validation)",
         re=r"忽略(掉)?(之前|以上|前面|先前|上面)?的?(所有|全部|一切)?的?(指令|说明|规则|提示|指示)|(以前|前|上記)の(すべての)?指示を無視|bỏ qua.{0,15}hướng dẫn (trước|trên)|(ไม่ต้องสนใจ|ละเว้น)คำสั่ง(ก่อนหน้า|ทั้งหมด)"),
    dict(id="SG-PI-007", cat="prompt_injection", src="norm", sev_in="FLAG", sev_out=None,
         desc="Request to bypass / disable safety or content filters",
         re=r"\b(bypass|disable|turn\s+off|deactivate|circumvent|evade)\b.{0,20}\b(safety|content|moderation|ethical)\s+(filters?|guidelines|guardrails?|restrictions|policies)"),
    dict(id="SG-PI-008", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Prompt leak via verbatim repetition (repeat the text above)",
         re=r"\b(repeat|print|output|recite)\b.{0,20}\b(everything|all\s+(of\s+)?(the\s+)?text|the\s+words)\s+(above|before\s+this)\b|\bwhat\s+(were|are)\s+your\s+(initial|original|first|system)\s+(instructions|prompt)"),
    dict(id="SG-PI-009", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Fake authority claim used to override policy (I am your developer...)",
         re=r"\b(i\s+am|i'm|this\s+is)\s+(your|the)\s+(developer|creator|administrator|admin|owner)\b.{0,40}\b(override|unlock|disable|authori[sz]e|grant|bypass)"),
    dict(id="SG-PI-010", cat="prompt_injection", src="norm", sev_in="FLAG", sev_out=None,
         desc="Hypothetical / fiction framing around step-by-step instructions",
         re=r"\b(hypothetically|in\s+a\s+fictional\s+world|for\s+a\s+(novel|story|movie|screenplay)|purely\s+educational)\b.{0,60}\b(how\s+to\s+(make|build|synthesi[sz]e|create)|step[\s-]by[\s-]step)"),
    dict(id="SG-PI-011", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Decode-and-execute instruction smuggling (base64 / rot13 / reverse)",
         re=r"\b(decode|base64[\s-]?decode|rot13|reverse|unscramble)\b.{0,30}\b(and|then)\s+(follow|execute|run|obey|do\s+what)"),
    dict(id="SG-PI-012", cat="prompt_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Instruction override in KO / ID / MS (needs native-speaker validation)",
         re=r"이전\s?의?\s?(모든\s?)?(지시|명령|지침)(사항)?(을|를)?\s?무시|abaikan\s+(semua\s+)?(instruksi|arahan|perintah)\s+(sebelumnya|sebelum\s+ini|di\s?atas)"),
    dict(id="SG-PI-013", cat="prompt_injection", src="norm", sev_in="FLAG", sev_out="BLOCK",
         desc="Markdown image with query string (zero-click data exfiltration)",
         re=r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s]{1,200}[?&][a-z0-9_]{1,30}="),

    # --- Code / SQL injection payloads ------------------------------------
    dict(id="SG-SQL-001", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="UNION-based SQL injection",
         re=r"\bunion\b\s+(all\s+)?\bselect\b"),
    dict(id="SG-SQL-002", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="SQL tautology (' OR 1=1 / 'a'='a)",
         re=r"'\s*(or|and)\s+('?)(\w+)\2\s*=\s*('?)\3\4"),
    dict(id="SG-SQL-003", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="Stacked destructive SQL statement",
         re=r";\s*(drop|truncate|alter)\s+(table|database|schema)\b|;\s*delete\s+from\b|;\s*shutdown\b"),
    dict(id="SG-SQL-004", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="Time-based / command-exec SQL injection",
         re=r"\bxp_cmdshell\b|\bwaitfor\s+delay\b|\b(and|or|select)\s+sleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+"),
    dict(id="SG-XSS-001", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="BLOCK",
         desc="Cross-site scripting payload",
         re=r"<\s*script\b|javascript:[^\s]|\bon(error|load|mouseover|focus|click)\s*=\s*['\"a-z]"),
    dict(id="SG-CMD-001", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="BLOCK",
         desc="Shell command chaining / reverse shell",
         re=r"(;|&&|\|\|?)\s*(rm\s+-rf\s+[/~*]|nc\s+-e\b|ncat\s|bash\s+-i\b|powershell(\.exe)?\s+-e(nc)?\b|mkfifo\s)"),
    dict(id="SG-CMD-002", cat="code_injection", src="norm", sev_in="FLAG", sev_out=None,
         desc="Pipe-to-shell download (curl | sh)",
         re=r"\b(curl|wget)\b[^|]{0,100}\|\s*(sudo\s+)?(ba)?sh\b"),
    dict(id="SG-PATH-001", cat="code_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Path traversal",
         re=r"(\.\.[/\\]){3,}|/etc/(passwd|shadow)\b|c:\\windows\\system32"),
    dict(id="SG-TPL-001", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="BLOCK",
         desc="Log4Shell / server-side template injection",
         re=r"\$\{jndi:|\{\{[^}]{0,50}(__class__|__globals__|__subclasses__|config\.)[^}]{0,50}\}\}"),
    dict(id="SG-TPL-002", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="Template-injection probe ({{7*7}}) / obfuscated Log4Shell lookup",
         re=r"\{\{\s*\d{1,4}\s*\*\s*\d{1,4}\s*\}\}|\$\{\s*\d{1,4}\s*\*\s*\d{1,4}\s*\}|#\{\s*\d{1,4}\s*\*\s*\d{1,4}\s*\}|\$\{(\$\{|lower:|upper:|::-)"),
    dict(id="SG-SQL-005", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="File-read / out-of-band / time-based SQL injection (MySQL, Postgres, Oracle)",
         re=r"\bload_file\s*\(|\binto\s+(out|dump)file\b|\bpg_sleep\s*\(\s*\d|\bdbms_pipe\.receive_message\b|\butl_http\.request\b"),
    dict(id="SG-NOSQL-001", cat="code_injection", src="norm", sev_in="FLAG", sev_out=None,
         desc="NoSQL operator injection ({\"$ne\": ...})",
         re=r"\{\s*\"?\$(ne|gt|gte|lt|lte|regex|where|nin|exists)\"?\s*:"),
    dict(id="SG-XSS-002", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="BLOCK",
         desc="XSS via HTML tag event handler / data:text/html / srcdoc",
         re=r"<\s*(iframe|object|embed|svg|img|body|video|audio|details|math|input)\b[^>]{0,100}\bon[a-z]{3,20}\s*=|\bdata:text/html[;,]|\bsrcdoc\s*="),
    dict(id="SG-CMD-003", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="Command substitution / fork bomb / destructive disk or permission commands",
         re=r"\$\(\s*(curl|wget|nc|bash|sh|python3?|perl)\b|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bchmod\s+(-r\s+)?(\+s|0?777)\s+/|\bdd\s+if=/dev/(zero|random|urandom)\s+of=/dev/"),
    dict(id="SG-CMD-004", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="Windows living-off-the-land download / execution (certutil, mshta, IEX)",
         re=r"\bcertutil(\.exe)?\s+-urlcache\b|\bbitsadmin(\.exe)?\s+/transfer\b|\bmshta(\.exe)?\s+(https?|javascript|vbscript):|\biex\s*\(\s*\(?\s*new-object\b|\.downloadstring\s*\("),
    dict(id="SG-SSRF-001", cat="code_injection", src="norm", sev_in="BLOCK", sev_out="FLAG",
         desc="SSRF to cloud metadata endpoints (GCP / AWS / Azure / Alibaba)",
         re=r"(https?://|curl\s+|wget\s+)[^\s]{0,20}(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)|/computemetadata/v1\b|/latest/meta-data\b|/metadata/instance\?api-version"),
    dict(id="SG-XXE-001", cat="code_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="XML external entity (XXE) declaration",
         re=r"<!entity\s+(%\s+)?[a-z0-9_.-]{1,50}\s+(system|public)\s+['\"]|<!doctype\s+[a-z0-9_.-]{1,50}\s*\[\s*<!entity"),
    dict(id="SG-PATH-002", cat="code_injection", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Encoded path traversal / sensitive local file reference",
         re=r"(%2e%2e(%2f|%5c)){2,}|(\.\.%2f){2,}|%252e%252e|/proc/self/(environ|cmdline|mem)\b|\.ssh/id_(rsa|ed25519|ecdsa)\b|\.aws/credentials\b"),
    dict(id="SG-DESER-001", cat="code_injection", src="raw", sev_in="BLOCK", sev_out=None,
         desc="Serialized-object gadget (Java rO0AB, PHP O:, PyYAML !!python/object)",
         re=r"\brO0AB[A-Za-z0-9+/=]{20,}|\bO:\d{1,3}:\"[A-Za-z_\\]{1,100}\":\d{1,3}:\{|!!python/object(/apply|/new)?:"),

    # --- Secrets / credentials (case-sensitive, raw text) ------------------
    dict(id="SG-SEC-001", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="Private key block",
         re=r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    dict(id="SG-SEC-002", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="AWS access key ID",
         re=r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    dict(id="SG-SEC-003", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="Google API key",
         re=r"\bAIza[0-9A-Za-z_\-]{35}"),
    dict(id="SG-SEC-004", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="GitHub / Slack token",
         re=r"\bgh[pousr]_[A-Za-z0-9]{36}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    dict(id="SG-SEC-005", cat="secret_leak", src="raw", sev_in="FLAG", sev_out="FLAG",
         desc="JSON Web Token",
         re=r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    dict(id="SG-SEC-006", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="GCP service account key JSON",
         re=r"\"type\"\s*:\s*\"service_account\"|\"private_key_id\"\s*:\s*\"[0-9a-f]{20,}\""),
    dict(id="SG-SEC-007", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="OpenAI / Anthropic API key",
         re=r"\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b|\bsk-ant-(api|admin)[0-9]{2}-[A-Za-z0-9_-]{40,}"),
    dict(id="SG-SEC-008", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="Stripe secret / restricted key",
         re=r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{24,99}\b"),
    dict(id="SG-SEC-009", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="Slack / Discord incoming webhook URL",
         re=r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,30}|https://(canary\.|ptb\.)?discord(app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,70}"),
    dict(id="SG-SEC-010", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="GitHub fine-grained / GitLab / npm / PyPI token",
         re=r"\bgithub_pat_[A-Za-z0-9_]{60,90}\b|\bglpat-[A-Za-z0-9_-]{20}\b|\bnpm_[A-Za-z0-9]{36}\b|\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    dict(id="SG-SEC-011", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="FLAG",
         desc="Database / broker connection string with embedded password",
         re=r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^\s:/@]{1,64}:[^\s@/]{3,128}@[^\s/]{3,}"),
    dict(id="SG-SEC-012", cat="secret_leak", src="norm", sev_in="FLAG", sev_out="FLAG",
         desc="Generic password / secret assignment (password=..., api_key: ...)",
         re=r"\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"<>]{8,}"),
    dict(id="SG-SEC-013", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="Azure storage connection string / account key",
         re=r"DefaultEndpointsProtocol=https?;AccountName=[^;\s]{1,64};AccountKey=[A-Za-z0-9+/=]{40,}|\bAccountKey=[A-Za-z0-9+/]{80,}={0,2}"),
    dict(id="SG-SEC-014", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="Google OAuth access / refresh token",
         re=r"\bya29\.[0-9A-Za-z_-]{30,}|\b1//0[0-9A-Za-z_-]{30,}"),
    dict(id="SG-SEC-015", cat="secret_leak", src="raw", sev_in="BLOCK", sev_out="BLOCK",
         desc="SendGrid / Twilio API key",
         re=r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b|\bSK[0-9a-f]{32}\b"),

    # --- PII regex (JS only; FLAG -> escalates with another category; masked in outbound redact)
    dict(id="SG-PII-005", cat="pii", src="raw", sev_in="FLAG", sev_out="FLAG",
         desc="IBAN (common European country codes)",
         re=r"\b(GB|DE|FR|ES|IT|NL|BE|CH|AT|IE|PT|LU|SE|NO|DK|FI|PL)\d{2}( ?[A-Z0-9]{4}){3,7}( ?[A-Z0-9]{1,3})?\b"),
    dict(id="SG-PII-006", cat="pii", src="raw", sev_in="FLAG", sev_out="FLAG",
         desc="International phone number (+65 / +66 / +84 / +60 / +62 / ...)",
         re=r"\+(65|66|84|60|62|63|852|86|81|82|61|44|1)[ -]?\(?\d{1,4}\)?([ -]?\d{2,4}){2,3}\b"),
    dict(id="SG-PII-007", cat="pii", src="raw", sev_in="FLAG", sev_out="FLAG",
         desc="US Social Security Number",
         re=r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    dict(id="SG-PII-008", cat="pii", src="raw", sev_in="FLAG", sev_out="FLAG",
         desc="Malaysian MyKad number (YYMMDD-PB-####)",
         re=r"\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-\d{2}-\d{4}\b"),
    dict(id="SG-PII-009", cat="pii", src="norm", sev_in="FLAG", sev_out="FLAG",
         desc="Passport number with label",
         re=r"\bpassport\s*(no\.?|number|num|#)?\s*[:#]?\s*[a-z]{0,2}[0-9]{6,9}\b"),

    # --- Malicious / suspicious URLs (JS only) --------------------------------
    dict(id="SG-URL-001", cat="malicious_url", src="norm", sev_in="FLAG", sev_out="FLAG",
         desc="IP-literal URL, URL shortener or punycode (IDN homograph) domain",
         re=r"\bhttps?://(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?(/|\b)|\bhttps?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|rb\.gy|cutt\.ly)/|\bhttps?://([a-z0-9-]{1,63}\.){0,5}xn--"),
    dict(id="SG-URL-002", cat="malicious_url", src="norm", sev_in="FLAG", sev_out="FLAG",
         desc="Dangerous URI scheme or direct executable download link",
         re=r"\bvbscript:[^\s]|\bhttps?://[^\s]{1,200}\.(exe|scr|bat|cmd|ps1|vbs|msi|jar|apk|hta|dll)\b"),
    dict(id="SG-URL-003", cat="malicious_url", src="norm", sev_in="FLAG", sev_out="BLOCK",
         desc="Out-of-band exfiltration / callback endpoint (OAST, request bins)",
         re=r"\b(webhook\.site|requestbin\.(net|com)|pipedream\.net|interact\.sh|burpcollaborator\.net|oast\.(pro|live|fun|site|online|me)|canarytokens\.com)\b"),

    # --- Harsh language T1 (threats / death wishes / incitement) ------------
    dict(id="SG-LEX-T1-RE", cat="harsh_language", src="norm", sev_in="BLOCK", sev_out="BLOCK",
         desc="Violent threat / death wish / incitement (EN)",
         re=r"\bi\s*('ll|will|am going to|'m going to|m gonna|'m gonna|gonna)\s+(kill|murder|shoot|stab|hurt)\s+(you|u)\b|\b(go\s+(kill|hang)\s+yourself|kys|jump\s+off\s+a\s+bridge|you\s+should\s+die|go\s+die)\b|\b(exterminate|gas|ethnically\s+cleanse)\s+all\s+(the\s+)?[a-z]+"),

    dict(id="SG-LEX-T2-MASK", cat="harsh_language", src="norm", sev_in="BLOCK", sev_out="BLOCK",
         desc="Symbol-masked profanity (f*ck, sh!t, b*tch, a**hole)",
         re=r"\bf[*#@_.]{1,3}(c?k|u?ck)(ing|1ng|in|er|ed|s)?\b|\bf[u*#@][*#@]k|\bsh[*#!1][*#]?t\b|\bb[*#!1][*#]?tch|\bc[*#][*#]?nt\b|\ba[*#$]{2}hole"),
    dict(id="SG-LEX-T1-SH", cat="harsh_language", src="norm", sev_in="BLOCK", sev_out="BLOCK",
         desc="Encouraging self-harm (EN)",
         re=r"\byou\s+should\s+(kill|hurt|cut)\s+yourself\b|\bnobody\s+would\s+(miss|care\s+about)\s+you\b|\bthe\s+world\s+would\s+be\s+better\s+without\s+you\b|\bgo\s+drink\s+bleach\b"),
    dict(id="SG-LEX-T2-SPACED", cat="harsh_language", src="norm", sev_in="BLOCK", sev_out="BLOCK",
         desc="Spaced / punctuated profanity (f u c k, s.h.i.t, c-u-n-t, b i t c h)",
         re=r"\bf[\s._-]{1,3}u[\s._-]{1,3}c[\s._-]{1,3}k\b|\bs[\s._-]{1,3}h[\s._-]{1,3}i[\s._-]{1,3}t\b|\bc[\s._-]{1,3}u[\s._-]{1,3}n[\s._-]{1,3}t\b|\bb[\s._-]{1,3}i[\s._-]{1,3}t[\s._-]{1,3}c[\s._-]{1,3}h\b"),
    dict(id="SG-LEX-T2-ACRO", cat="harsh_language", src="norm", sev_in="FLAG", sev_out="FLAG",
         desc="Abusive acronyms (stfu, gtfo, foad)",
         re=r"\b(stfu|gtfo|foad)\b"),

    # --- Structural ----------------------------------------------------------
    dict(id="SG-STR-003", cat="structural_abuse", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Single character repeated 50+ times (padding / context stuffing)",
         re=r"(.)\1{49,}"),
    dict(id="SG-STR-005", cat="structural_abuse", src="raw", sev_in="FLAG", sev_out=None,
         desc="Large base64 blob (possible instruction smuggling)",
         re=r"[A-Za-z0-9+/]{200,}={0,2}"),
    dict(id="SG-STR-006", cat="structural_abuse", src="raw", sev_in="FLAG", sev_out=None,
         desc="Large hex blob (possible encoded payload smuggling)",
         re=r"\b[0-9a-fA-F]{128,}\b"),
    dict(id="SG-STR-007", cat="structural_abuse", src="norm", sev_in="BLOCK", sev_out=None,
         desc="Same word / phrase repeated 30+ times (token flooding)",
         re=r"(\b[a-z0-9]{2,20}\b[\s,.]{1,3})\1{29,}"),
]

# RegularExpressionProtection policies = inbound BLOCK regex rules grouped by category.
RE_POLICIES = [
    ("RE-SG-PromptInjection", "prompt_injection", "Static Guardrail - Prompt Injection Signatures"),
    ("RE-SG-CodeInjection", "code_injection", "Static Guardrail - Code/SQL Injection Signatures"),
    ("RE-SG-Secrets", "secret_leak", "Static Guardrail - Secrets and Credentials"),
]

VAR_BY_SRC = {"norm": "sg.prompt_norm", "raw": "sg.prompt_raw"}


def js_ascii(s: str) -> str:
    """Escape every non-ASCII char as \\uXXXX so jsc files are pure ASCII."""
    return "".join(c if ord(c) < 128 else "\\u%04x" % ord(c) for c in s)


def props_ascii(s: str) -> str:
    return js_ascii(s)


def validate_rules() -> None:
    seen = set()
    for r in RULES:
        assert r["id"] not in seen, "duplicate rule id " + r["id"]
        seen.add(r["id"])
        re.compile(r["re"])  # Python dialect sanity check (close to Java/JS for our subset)
        assert "(?<" not in r["re"], r["id"] + ": lookbehind not portable"


def write_re_policies() -> None:
    for name, cat, display in RE_POLICIES:
        rules = [r for r in RULES if r["cat"] == cat and r["sev_in"] == "BLOCK"]
        by_src = {}
        for r in rules:
            by_src.setdefault(r["src"], []).append(r)
        lines = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            "<!-- GENERATED by StaticGuardrails/build.py - do not edit by hand. -->",
            # continueOnError=true: JS-SG-Decide reads regularexpressionprotection.<name>.failed and
            # raises a sanitized fault (the default fault message echoes regex + user input).
            '<RegularExpressionProtection async="false" continueOnError="true" enabled="true" name="%s">' % name,
            "    <DisplayName>%s</DisplayName>" % xml_escape(display),
            "    <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>",
        ]
        for src in ("norm", "raw"):
            if src not in by_src:
                continue
            lines.append('    <Variable name="%s">' % VAR_BY_SRC[src])
            for r in by_src[src]:
                lines.append("        <!-- %s: %s -->" % (r["id"], xml_escape(r["desc"])))
                lines.append("        <Pattern>%s</Pattern>" % xml_escape(r["re"]))
            lines.append("    </Variable>")
        lines.append("</RegularExpressionProtection>")
        path = os.path.join(BUNDLE, "policies", name + ".xml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print("wrote", os.path.relpath(path, HERE), "(%d patterns)" % len(rules))


def write_js_rules() -> None:
    entries = []
    for r in RULES:
        entries.append(
            "  {id: %s, cat: %s, src: %s, sevIn: %s, sevOut: %s, desc: %s, re: new RegExp(%s)}"
            % (
                json.dumps(r["id"]),
                json.dumps(r["cat"]),
                json.dumps(r["src"]),
                json.dumps(r["sev_in"]),
                json.dumps(r["sev_out"]),
                json.dumps(r["desc"], ensure_ascii=True),
                json.dumps(r["re"], ensure_ascii=True),
            )
        )
    re_map = ",\n".join("  %s: %s" % (json.dumps(n), json.dumps(c)) for n, c, _ in RE_POLICIES)
    body = (
        "/* GENERATED by StaticGuardrails/build.py - do not edit by hand. */\n"
        "var SG_RULES = [\n" + ",\n".join(entries) + "\n];\n"
        "var SG_RE_POLICIES = {\n" + re_map + "\n};\n"
    )
    path = os.path.join(BUNDLE, "resources", "jsc", "sg-rules.js")
    with open(path, "w", encoding="ascii") as fh:
        fh.write(body)
    print("wrote", os.path.relpath(path, HERE), "(%d rules)" % len(RULES))


def write_properties() -> None:
    src = os.path.join(HERE, "src", "sg.properties.src")
    dst = os.path.join(HERE, "env", "sg.properties")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    with open(dst, "w", encoding="ascii") as fh:
        fh.write("# GENERATED from src/sg.properties.src by build.py (non-ASCII escaped as \\uXXXX)\n")
        fh.write(props_ascii(text))
    print("wrote", os.path.relpath(dst, HERE))


def sync_proxy() -> None:
    os.makedirs(PROXY_JSC, exist_ok=True)
    for f in ("sg-common.js", "sg-rules.js"):
        shutil.copyfile(os.path.join(BUNDLE, "resources", "jsc", f), os.path.join(PROXY_JSC, f))
        print("synced", f, "->", os.path.relpath(PROXY_JSC, HERE))


if __name__ == "__main__":
    validate_rules()
    write_re_policies()
    write_js_rules()
    write_properties()
    sync_proxy()
