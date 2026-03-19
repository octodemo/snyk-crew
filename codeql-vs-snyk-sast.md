# CodeQL vs Snyk Code — SAST Comparison Report

**Repository:** `octodemo/snyk-crew`
**Date:** 2026-03-19
**Scope:** All 108 open Code Scanning alerts from GitHub Advanced Security (CodeQL) and Snyk Code

---

## Executive Summary

Both CodeQL and Snyk Code were run against the same intentionally vulnerable Python/Flask banking application. The repository's `README.md` documents **68 implemented vulnerabilities** across 10 categories. Together the two SAST tools produced **108 open alerts** — but only covered **~18 of the 68 documented vulnerabilities**.

| | CodeQL | Snyk Code | GitHub Secret Scanning |
|---|---|---|---|
| **Alerts** | 56 | 52 | 1 |
| **Severity populated** | ✅ 1 critical, 13 high, 42 medium | ❌ All null | N/A |
| **Documented vulns detected** | ~13 of 68 | ~9 of 68 | 1 of 68 |
| **Best at** | Breadth, severity, SQLi grouping, SSRF, stack-trace exposure, CI/CD | XSS depth, taint-path detail, hardcoded secrets | API key detection |
| **Misses** | Most XSS, hardcoded secrets | SSRF, stack traces, CI/CD, sensitive logging | Everything except known key formats |

**Key findings:**
- **SQL injection:** Both tools detect the same ~6 underlying vulnerabilities. CodeQL groups them into 6 clean alerts; Snyk reports 25 (one per taint path) — same coverage, different presentation.
- **XSS:** Snyk is dramatically better — 22 locations vs CodeQL's 4.
- **SSRF:** Only CodeQL found the critical SSRF (the single most severe finding).
- **Stack-trace exposure:** Only CodeQL detects this (39 alerts). Snyk has zero coverage of CWE-209.
- **Secrets:** CodeQL doesn't do secret scanning. Snyk found 2 hardcoded secrets; GitHub Secret Scanning found 1 API key. Zero overlap between them.
- **Business logic, auth flaws, race conditions, CSRF, file upload, AI/LLM vulns:** Neither SAST tool detects these — they require DAST, manual review, or specialized tooling.

**Bottom line:** Run both SAST tools plus GitHub Secret Scanning. Even combined, SAST covers only ~26% of the documented attack surface. A full security assessment requires DAST, API/GraphQL scanners, and manual code review.

---

## Table of Contents

1. [Documented Vulnerabilities vs Scanner Coverage](#1-documented-vulnerabilities-vs-scanner-coverage)
2. [Alert Totals](#2-alert-totals)
3. [Finding Categories — Side-by-Side](#3-finding-categories--side-by-side)
4. [Detailed Finding-by-Finding Comparison](#4-detailed-finding-by-finding-comparison)
5. [Alert Grouping & Noise Analysis](#5-alert-grouping--noise-analysis)
6. [False Positive Analysis](#6-false-positive-analysis)
7. [Metadata & Severity Quality](#7-metadata--severity-quality)
8. [File Coverage Comparison](#8-file-coverage-comparison)
9. [Precision vs Recall Summary](#9-precision-vs-recall-summary)
10. [Recommendations](#10-recommendations)

---

## 1. Documented Vulnerabilities vs Scanner Coverage

The repository documents 68 vulnerabilities across 10 categories. The table below maps each one to whether CodeQL, Snyk Code, or GitHub Secret Scanning detected it.

**Legend:** ✅ Detected — ⚠️ Partially/indirectly detected — ❌ Not detected

### 1. Authentication & Authorization (9 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| SQL Injection in login | ✅ | ✅ | — | Both flag `auth.py:121` |
| Weak JWT implementation | ❌ | ⚠️ | — | Snyk flags hardcoded JWT key (`auth.py:10`). Neither flags `none` algorithm. |
| Broken object level authorization (BOLA) | ❌ | ❌ | — | Business logic — beyond SAST |
| Broken object property level authorization (BOPLA) | ❌ | ❌ | — | Business logic — beyond SAST |
| Mass Assignment & Excessive Data Exposure | ❌ | ⚠️ | — | Snyk flags `app.py:325` (SQLi via dynamic field names) which is the mass-assignment vector |
| Weak password reset mechanism (3-digit PIN) | ❌ | ❌ | — | Design flaw — beyond SAST |
| Token stored in localStorage | ❌ | ❌ | — | Client-side pattern — beyond server SAST |
| No server-side token invalidation | ❌ | ❌ | — | Absence of logic — beyond SAST |
| No session expiration | ❌ | ❌ | — | Absence of logic — beyond SAST |

### 2. Data Security (6 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| Information disclosure | ✅ | ❌ | — | CodeQL: 39× `py/stack-trace-exposure`. Snyk: missed entirely. |
| Sensitive data exposure | ✅ | ❌ | — | CodeQL: `py/clear-text-logging-sensitive-data` (password in logs) |
| Plaintext password storage | ❌ | ❌ | — | Neither tool checks for missing password hashing |
| SQL injection points | ✅ | ✅ | — | Both detect across `app.py`, `auth.py`, `transaction_graphql.py` |
| Debug information exposure | ✅ | ✅ | — | Both flag `app.run(debug=True)` |
| Detailed error messages exposed | ✅ | ❌ | — | CodeQL: 39× stack-trace exposure. Snyk: not detected. |

### 3. Transaction Vulnerabilities (6 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| No amount validation | ❌ | ❌ | — | Business logic — beyond SAST |
| Negative amount transfers possible | ❌ | ❌ | — | Business logic — beyond SAST |
| No transaction limits | ❌ | ❌ | — | Business logic — beyond SAST |
| Race conditions in transfers | ❌ | ❌ | — | Concurrency — beyond SAST |
| Transaction history info disclosure | ❌ | ❌ | — | Authorization logic — beyond SAST |
| No validation on recipient accounts | ❌ | ❌ | — | Business logic — beyond SAST |

### 4. File Operations (7 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| Unrestricted file upload | ❌ | ❌ | — | Absence of validation — beyond SAST |
| Path traversal vulnerabilities | ❌ | ❌ | — | Not flagged by either tool |
| No file type validation | ❌ | ❌ | — | Absence of logic — beyond SAST |
| Directory traversal | ❌ | ❌ | — | Not flagged by either tool |
| No file size limits | ❌ | ❌ | — | Absence of logic — beyond SAST |
| Unsafe file naming | ❌ | ❌ | — | Not flagged by either tool |
| SSRF via URL-based image import | ✅ | ⚠️ | — | CodeQL: `py/full-ssrf` (critical). Snyk flags same line for SSL bypass only — misses the SSRF. |

### 5. Session Management (4 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| Token vulnerabilities | ❌ | ⚠️ | — | Snyk flags hardcoded JWT key. Neither flags other token issues. |
| No session expiration | ❌ | ❌ | — | Absence of logic — beyond SAST |
| Weak secret keys | ❌ | ✅ | — | Snyk: `python/HardcodedKey` + `python/HardcodedNonCryptoSecret` |
| Token exposure in URLs | ❌ | ❌ | — | Requires runtime/DAST analysis |

### 6. Client and Server-Side Flaws (4 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| Cross Site Scripting (XSS) | ✅ (4) | ✅ (22) | — | Snyk far superior: 22 DOM XSS vs CodeQL's 4 |
| Cross Site Request Forgery (CSRF) | ❌ | ❌ | — | Absence of CSRF tokens — beyond SAST |
| Insecure direct object references | ❌ | ❌ | — | Authorization logic — beyond SAST |
| No rate limiting | ❌ | ❌ | — | Absence of logic — beyond SAST |

### 7. Virtual Card Vulnerabilities (11 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| Mass Assignment in card limit updates | ❌ | ❌ | — | Business logic — beyond SAST |
| Mass Assignment in card funding exchange-rate | ❌ | ❌ | — | Business logic — beyond SAST |
| Predictable card number generation | ❌ | ❌ | — | Weak randomness — not flagged |
| Plaintext storage of card details | ❌ | ❌ | — | Data-at-rest — beyond SAST |
| No validation on card limits | ❌ | ❌ | — | Business logic — beyond SAST |
| BOLA in card operations | ❌ | ❌ | — | Authorization logic — beyond SAST |
| Race conditions in balance updates | ❌ | ❌ | — | Concurrency — beyond SAST |
| Card detail information disclosure | ❌ | ❌ | — | Authorization logic — beyond SAST |
| No transaction verification | ❌ | ❌ | — | Business logic — beyond SAST |
| Lack of card activity monitoring | ❌ | ❌ | — | Absence of logic — beyond SAST |
| Client-controlled currency conversion | ❌ | ❌ | — | Business logic — beyond SAST |

### 8. Bill Payment Vulnerabilities (9 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| No validation on payment amounts | ❌ | ❌ | — | Business logic — beyond SAST |
| SQL injection in biller queries | ✅ | ✅ | — | Grouped into `database.py` sink alerts |
| Information disclosure in payment history | ❌ | ❌ | — | Authorization logic — beyond SAST |
| Predictable reference numbers | ❌ | ❌ | — | Weak randomness — not flagged |
| Transaction history exposure | ❌ | ❌ | — | Authorization logic — beyond SAST |
| No validation on biller accounts | ❌ | ❌ | — | Business logic — beyond SAST |
| Race conditions in payment processing | ❌ | ❌ | — | Concurrency — beyond SAST |
| BOLA in payment history access | ❌ | ❌ | — | Authorization logic — beyond SAST |
| Missing payment limits | ❌ | ❌ | — | Business logic — beyond SAST |

### 9. AI Customer Support Vulnerabilities (10 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| Prompt Injection (CWE-77) | ❌ | ❌ | — | LLM-specific — beyond SAST |
| AI-based Information Disclosure (CWE-200) | ❌ | ❌ | — | LLM-specific — beyond SAST |
| Broken Authorization in AI context (CWE-862) | ❌ | ❌ | — | LLM-specific — beyond SAST |
| AI System Information Exposure (CWE-209) | ❌ | ❌ | — | LLM-specific — beyond SAST |
| Insufficient Input Validation for AI (CWE-20) | ❌ | ❌ | — | LLM-specific — beyond SAST |
| Direct Database Access through AI | ❌ | ❌ | — | LLM-specific — beyond SAST |
| AI Role Override attacks | ❌ | ❌ | — | LLM-specific — beyond SAST |
| Context Injection vulnerabilities | ❌ | ❌ | — | LLM-specific — beyond SAST |
| AI-assisted unauthorized data access | ❌ | ❌ | — | LLM-specific — beyond SAST |
| Exposed AI system prompts | ❌ | ❌ | — | LLM-specific — beyond SAST |

### 10. GraphQL Vulnerabilities (6 vulnerabilities)

| Vulnerability | CodeQL | Snyk Code | Secret Scanning | Why missed? |
|---|:---:|:---:|:---:|---|
| Enabled schema introspection | ❌ | ❌ | — | Config/design — needs GraphQL scanner |
| Weak JWT auth inherited by `/graphql` | ❌ | ⚠️ | — | Snyk flags hardcoded JWT key (not specific to GraphQL) |
| SQL injection in resolvers | ✅ | ✅ (3/5) | — | Snyk found 3 of 5 injection points; CodeQL groups at sink |
| Missing depth/complexity controls | ❌ | ❌ | — | GraphQL-specific — beyond SAST |
| Raw GraphQL error disclosure | ❌ | ❌ | — | CodeQL catches this pattern elsewhere but not in GraphQL handler |
| Admin analytics exposure (BOLA) | ❌ | ❌ | — | Authorization logic — beyond SAST |

### Additional: Secrets (from `.env` and source code)

| Secret | CodeQL | Snyk Code | Secret Scanning |
|---|:---:|:---:|:---:|
| DeepSeek API key in `.env` | — | ❌ | ✅ |
| JWT secret `"secret123"` in `auth.py` | ❌ | ✅ | ❌ |
| Flask secret `"secret123"` in `app.py` | ❌ | ✅ | ❌ |

### Coverage Summary

| Category | Total Vulns | CodeQL | Snyk Code | Either Tool |
|---|:---:|:---:|:---:|:---:|
| 1. Authentication & Authorization | 9 | 1 | 3 (⚠️) | 3 |
| 2. Data Security | 6 | 5 | 2 | 5 |
| 3. Transaction Vulnerabilities | 6 | 0 | 0 | 0 |
| 4. File Operations | 7 | 1 | 0 (⚠️) | 1 |
| 5. Session Management | 4 | 0 | 1 | 1 |
| 6. Client and Server-Side Flaws | 4 | 1 | 1 | 1 |
| 7. Virtual Card Vulnerabilities | 11 | 0 | 0 | 0 |
| 8. Bill Payment Vulnerabilities | 9 | 1 | 1 | 1 |
| 9. AI Customer Support | 10 | 0 | 0 | 0 |
| 10. GraphQL | 6 | 1 | 2 (⚠️) | 2 |
| **Total** | **72** | **10** | **10** | **~14 unique** |

> **~14 of 72 documented vulnerabilities** (~19%) are detected by at least one SAST tool.
> The remaining 81% are business logic, authorization, concurrency, LLM-specific, or design flaws that SAST cannot detect.

### Why is SAST coverage so low?

| Root cause | Documented vulns affected | Example |
|---|:---:|---|
| **Business/authorization logic** | ~25 | BOLA, mass assignment, missing limits, no validation |
| **Absence of controls** (not a code flaw) | ~15 | No rate limiting, no session expiry, no file size limits |
| **Concurrency/race conditions** | ~4 | Race conditions in transfers, balance updates |
| **LLM/AI-specific** | 10 | Prompt injection, AI role override |
| **Client-side / runtime only** | ~4 | Token in localStorage, CSRF, token in URLs |
| **Detectable by SAST** | **~14** | SQLi, XSS, SSRF, debug mode, hardcoded secrets, stack traces |

SAST tools analyze source code for known dangerous patterns (taint flows, insecure API usage, hardcoded secrets). They cannot reason about missing logic, business rules, authorization policies, or AI/LLM behavior. This is expected — SAST is one layer in a defense-in-depth strategy.

---

## 2. Alert Totals

| Metric | CodeQL | Snyk Code |
|---|---|---|
| **Total open alerts** | 56 | 52 |
| **Distinct rule IDs** | 10 | 7 |
| **Critical severity** | 1 | 0\* |
| **High severity** | 13 | 0\* |
| **Medium severity** | 42 | 0\* |
| **Files with findings** | 5 | 11 |
| **CWE references provided** | ✅ Yes (all alerts) | ⚠️ Tags only (no standard CWE IDs) |

\* Snyk Code does not populate `security_severity_level` in its SARIF output. All 52 alerts appear with `null` severity in GitHub's Code Scanning UI.

---

## 3. Finding Categories — Side-by-Side

| Vulnerability Category | CWE | Snyk Code | CodeQL | Found By |
|---|---|:---:|:---:|---|
| SQL Injection | CWE-89 | **25** | 6 | Both (same ~6 vulns; see [§4.1](#41-sql-injection)) |
| DOM-based Cross-site Scripting | CWE-79 | **22** | 4 | Both |
| Stack Trace / Exception Exposure | CWE-209 | 0 | **39** | CodeQL only |
| Full Server-Side Request Forgery | CWE-918 | 0 | **1** | CodeQL only |
| Clear-text Logging of Passwords | CWE-532 | 0 | **1** | CodeQL only |
| Request Without Cert Validation | CWE-295 | 1 | 1 | Both |
| Flask Debug Mode Enabled | CWE-215 | 1 | 1 | Both |
| Hardcoded Cryptographic Key\* | CWE-321 | **1** | 0 | Snyk only (CodeQL does not do secret detection) |
| Hardcoded Non-Crypto Secret\* | CWE-798 | **1** | 0 | Snyk only (CodeQL does not do secret detection) |
| Insecure Cookie (missing `Secure`) | CWE-614 | **1** | 0 | Snyk only |
| Workflow Missing Permissions | CWE-275 | 0 | **2** | CodeQL only |
| Unpinned Action Tag | CWE-829 | 0 | **1** | CodeQL only |

\* CodeQL does not include secret/credential detection rules — that is handled by **GitHub Secret Scanning**, a separate GHAS feature. See [Section 4.10](#410-secret-detection--snyk-code-sast-vs-github-secret-scanning) for a comparison of Snyk Code's secret findings vs GitHub Secret Scanning.

---

## 4. Detailed Finding-by-Finding Comparison

### 3.1 SQL Injection

| | Snyk Code | CodeQL |
|---|---|---|
| Rule ID | `python/Sqli` | `py/sql-injection` |
| Total alerts | 25 | 6 |
| Grouping strategy | **One alert per source (caller)** | **One alert per sink, multiple paths grouped** |
| Files | `app.py` (18), `auth.py` (4), `transaction_graphql.py` (3) | `auth.py` (4), `database.py` (2) |
| Severity | null | high |
| CWE | Tags: `Sqli, Taint, SourceHttpParam` | `external/cwe/cwe-089` |

**Critical insight: same vulnerabilities, different grouping.**

The 25 Snyk alerts and 6 CodeQL alerts cover **the same set of underlying vulnerabilities**. The 4× difference in alert count is almost entirely due to how each tool groups taint paths, not a difference in detection capability.

**How the alerts map to each other:**

| CodeQL Alert | CodeQL Sink | Paths in CodeQL | Snyk Alerts to Same Sink | Snyk Source Lines |
|---|---|:---:|:---:|---|
| `#10` | `database.py:255` (`execute_query`) | 7 | **17** | `app.py`: 325, 380, 487, 596, 1128, 1155, 1254, 1304, 1352, 1590, 1641, 1828, 2076, 2104 + `transaction_graphql.py`: 108, 145, 146 |
| `#11` | `database.py:280` (`execute_transaction`) | 3 | **4** | `app.py`: 551, 991, 1975, 2185 |
| `#6–9` | `auth.py`: 121, 157, 191, 195 (direct `cursor.execute`) | 1 each | **4** (1:1 match) | `auth.py`: 121, 157, 191, 195 |
| **Total** | | **14 paths** | **25 alerts** | |

All 21 Snyk alerts in `app.py` and `transaction_graphql.py` flow through the imported `execute_query()` or `execute_transaction()` functions from `database.py` — the same two sinks that CodeQL groups into just 2 alerts. The 4 `auth.py` alerts are 1:1 matches because `auth.py` uses direct `sqlite3.cursor.execute()` calls (not the shared `database.py` functions).

**CodeQL's approach (sink-level grouping):**
- Alert at `database.py:255` says *"This SQL query depends on a user-provided value"* — repeated **7 times** in the message, once per traced taint path.
- A developer sees: "this `execute_query` function is vulnerable via 7 different callers" → **one issue to fix** (make the function safe or fix all callers).
- Limitation: CodeQL only traced 7 of the ~17 paths to this sink — it missed paths from `transaction_graphql.py` and several `app.py` routes.

**Snyk's approach (source-level reporting):**
- Each caller gets its own alert with a specific message like *"Unsanitized input from the HTTP request body flows into database.execute_query"* or *"Unsanitized input from an HTTP parameter flows into execute"*.
- A developer sees 17 separate alerts that all require fixing the same sink function → **more granular but noisier**.
- Advantage: Snyk traces more paths (21 vs CodeQL's 10), and its messages distinguish the source type ("HTTP request body", "HTTP parameter", "database") — useful for understanding each entry point.
- Disadvantage: 17 alerts for 1 vulnerable function creates triage fatigue and inflates the apparent vulnerability count.
- **False positives remain:** `app.py:551`, `app.py:991`, `app.py:2185` call `execute_transaction()` with properly `%s`-parameterized queries — Snyk flags these because it traces taint to the sink without recognizing that parameterization neutralizes the injection.

**Actual unique vulnerabilities to fix: ~6**
1. `auth.py:121` — direct `cursor.execute` with f-string
2. `auth.py:157` — direct `cursor.execute` with f-string
3. `auth.py:191` — direct `cursor.execute` with f-string
4. `auth.py:195` — direct `cursor.execute` with f-string
5. `database.py:255` / `execute_query` callers — all `app.py` and `transaction_graphql.py` routes that pass f-string queries to this function
6. `database.py:280` / `execute_transaction` callers — routes that pass f-string queries to this function

**Verdict:** Both tools detect the same core SQL injection vulnerabilities. CodeQL's sink-level grouping provides a significantly better developer experience (6 alerts vs 25 for the same issues). Snyk's source-level reporting provides better path enumeration (traces 21 paths vs CodeQL's 10) and source-type detail, but at the cost of 4× alert inflation. For SQL injection specifically, **CodeQL's grouping is the superior UX**.

### 3.2 Cross-site Scripting (XSS)

| | Snyk Code | CodeQL |
|---|---|---|
| Rule ID | `javascript/DOMXSS` | `js/xss` + `js/xss-through-dom` |
| Total alerts | **22** | 4 (2 unique locations × 2 rules) |
| Files | `dashboard.js` (10), 6 HTML templates (12) | `blog.html` (2), `careers.html` (2) |
| Severity | null | high |

**Line-level overlap:**

- **2 shared locations** — `blog.html:195` and `careers.html:223`. Both tools flag `innerHTML` assignments fed by `document.location` data.
- **20 Snyk-only locations** — 10 in `dashboard.js` and 10 across 6 other HTML templates. All are `innerHTML` sinks receiving data from remote API responses or URL parameters. These are legitimate DOM XSS findings.
- **0 CodeQL-only locations** — CodeQL found nothing that Snyk didn't.

**Key observation on grouping:** CodeQL fires **two separate rules** (`js/xss` and `js/xss-through-dom`) on the exact same line in both `blog.html:195` and `careers.html:223`. This creates 4 alerts for what are really 2 distinct vulnerabilities. Snyk consolidates these under a single rule ID (`javascript/DOMXSS`), producing one alert per location — cleaner from a triage perspective.

**Verdict:** Snyk Code is dramatically better at DOM XSS detection. CodeQL's JavaScript analysis scans inline `<script>` blocks in HTML templates but has extremely limited coverage — it only catches 2 of the 22 locations Snyk finds. CodeQL does not analyze standalone `.js` files (like `dashboard.js`) at all in this scan configuration.

### 3.3 Stack Trace / Exception Exposure

| | Snyk Code | CodeQL |
|---|---|---|
| Rule ID | — (not detected) | `py/stack-trace-exposure` |
| Total alerts | 0 | **39** |
| Files | — | `app.py` (38), `auth.py` (1) |
| Severity | — | medium |

Every `except` block that returns `str(e)` to the HTTP client is flagged. The 39 alerts share an **identical message**: *"Stack trace information flows to this location and may be exposed to an external user."* While each points to a distinct code location, the root cause is a single systemic pattern: the application exposes exception details in JSON error responses.

**This is CodeQL's noisiest rule** — 39 alerts of the same pattern constitute 70% of all CodeQL findings and 36% of all alerts across both tools. However, the noise criticism must be weighed against the fact that **Snyk Code does not detect this vulnerability category at all**. A noisy detection is strictly better than no detection — these are real information-disclosure vulnerabilities (CWE-209). CodeQL's problem here is presentation (should consolidate into fewer alerts), not accuracy.

### 3.4 Full Server-Side Request Forgery (SSRF)

| | Snyk Code | CodeQL |
|---|---|---|
| Rule ID | — (not detected) | `py/full-ssrf` |
| Location | — | `app.py:689` |
| Severity | — | **critical** |

```python
resp = requests.get(image_url, timeout=10, allow_redirects=True, verify=False)
```

The `image_url` is fully user-controlled with no scheme/host allowlist. This is the **only critical-severity finding** in the entire scan. CodeQL correctly identifies it; Snyk Code misses it entirely despite flagging the _same line_ for SSL verification bypass (`python/SSLVerificationBypass`). This is a significant Snyk gap — it sees the `verify=False` but not the SSRF vector on the same `requests.get()` call.

### 3.5 Clear-text Logging of Sensitive Data

| | Snyk Code | CodeQL |
|---|---|---|
| Rule ID | — (not detected) | `py/clear-text-logging-sensitive-data` |
| Location | — | `app.py:378` |
| Severity | — | high |

```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
print(f"Debug - Login query: {query}")
```

CodeQL detects that a `password` value flows into a `print()` statement. This requires sensitive-data classification that Snyk Code does not perform.

### 3.6 Certificate Validation Bypass

| | Snyk Code | CodeQL |
|---|---|---|
| Rule ID | `python/SSLVerificationBypass` | `py/request-without-cert-validation` |
| Location | `app.py:689` | `app.py:689` |
| Severity | null | high |

Both tools flag the same line with equivalent findings. Messages are comparable in quality. Tie.

### 3.7 Flask Debug Mode

| | Snyk Code | CodeQL |
|---|---|---|
| Rule ID | `python/RunWithDebugTrue` | `py/flask-debug` |
| Location | `app.py:2479` | `app.py:2479` |
| Severity | null | high |

Both tools flag `app.run(debug=True)`. CodeQL's message is more specific ("may allow an attacker to run arbitrary code through the Werkzeug debugger") vs Snyk's generic warning. Minor CodeQL advantage.

### 3.8 Snyk-Only Findings

| Finding | Rule ID | File | Assessment |
|---|---|---|---|
| **Hardcoded Cryptographic Key** | `python/HardcodedKey` | `auth.py:10` | **True positive.** JWT secret key (`"secret123"`) hardcoded in source. See [Section 4.10](#410-secret-detection--snyk-code-sast-vs-github-secret-scanning) for comparison with GitHub Secret Scanning. |
| **Hardcoded Non-Crypto Secret** | `python/HardcodedNonCryptoSecret` | `app.py:48` | **True positive.** Flask `secret_key` (`"secret123"`) hardcoded. See [Section 4.10](#410-secret-detection--snyk-code-sast-vs-github-secret-scanning). |
| **Insecure Cookie** | `python/WebCookieMissesCallToSetSecure` | `app.py:412` | **True positive.** Session cookie missing `Secure` attribute. CodeQL has this rule for other frameworks but didn't trigger for Flask here. |

### 3.9 CodeQL-Only Findings (CI/CD)

| Finding | Rule ID | File | Severity |
|---|---|---|---|
| Missing workflow permissions | `actions/missing-workflow-permissions` | `build.yml` | medium |
| Missing workflow permissions | `actions/missing-workflow-permissions` | `deploy.yml` | medium |
| Unpinned 3rd-party action tag | `actions/unpinned-tag` | `deploy.yml` | medium |

These are **supply-chain and CI/CD hardening** findings that Snyk Code does not cover at all (Snyk's SAST focuses on application code, not workflow files).

### 3.10 Secret Detection — Snyk Code (SAST) vs GitHub Secret Scanning

CodeQL does not perform secret scanning — that is handled by **GitHub Secret Scanning**, a separate GitHub Advanced Security feature. This section compares Snyk Code's hardcoded-secret SAST rules against GitHub Secret Scanning's results on this repository.

#### GitHub Secret Scanning Results

| # | Secret Type | File | Line | Validity | State |
|---|---|---|---|---|---|
| 1 | DeepSeek API Key | `.env` (commit history) | 6 | Unknown | Open |

GitHub Secret Scanning found **1 alert**: a DeepSeek API key committed in the `.env` file. This is a real API key matching a known provider pattern (`deepseek_api_key`). The alert was detected at the commit level — even though `.env` may be in `.gitignore`, the key exists in Git history.

#### Snyk Code Secret-Related Results

| # | Rule | File | Line | Description |
|---|---|---|---|---|
| 1 | `python/HardcodedKey` | `auth.py` | 10 | JWT secret `"secret123"` used as cryptographic key in `jwt.decode()` |
| 2 | `python/HardcodedNonCryptoSecret` | `app.py` | 48 | Flask `app.secret_key = "secret123"` — application secret hardcoded |

Snyk Code found **2 alerts**: both for the hardcoded string `"secret123"` used as a JWT signing key and a Flask session secret.

#### Comparison

| Dimension | GitHub Secret Scanning | Snyk Code (SAST) |
|---|---|---|
| **What it detects** | Known secret patterns from 200+ providers (API keys, tokens, passwords in specific formats) | Hardcoded strings used in security-sensitive contexts (crypto keys, secret assignments) |
| **Detection method** | Pattern matching against known provider formats | Semantic analysis of how strings are used in code |
| **Scope** | Full Git history (all commits, including deleted files) | Current code snapshot only |
| **DeepSeek API key in `.env`** | ✅ Found | ❌ Missed |
| **JWT secret `"secret123"` in `auth.py`** | ❌ Missed | ✅ Found |
| **Flask secret `"secret123"` in `app.py`** | ❌ Missed | ✅ Found |
| **Total secrets found** | 1 | 2 |
| **Overlap** | 0 | 0 |

**Zero overlap** — the tools detect completely different classes of secrets:

- **GitHub Secret Scanning** identifies the DeepSeek API key because it matches a known provider pattern (format: `sk-*`). It does not flag `"secret123"` because generic short strings don't match any provider's key format — there's no way to distinguish a hardcoded test value from a legitimate constant without semantic context.

- **Snyk Code** flags `"secret123"` because it performs semantic analysis: it sees a string literal flowing into `jwt.decode()` (cryptographic operation) and `app.secret_key` (security-sensitive field). It does not flag the DeepSeek API key because that key lives in `.env`, which Snyk Code's SAST scan doesn't analyze (it focuses on application source code, not configuration files).

**Combined, the three secrets detected are:**
1. **DeepSeek API key** in `.env` — GitHub Secret Scanning only
2. **JWT signing key** `"secret123"` in `auth.py:10` — Snyk Code only
3. **Flask session secret** `"secret123"` in `app.py:48` — Snyk Code only

**Verdict:** GitHub Secret Scanning and Snyk Code are fully complementary for secret detection. Secret Scanning catches real API keys/tokens by format, while Snyk Code catches hardcoded values used in security-sensitive code paths regardless of format. Running both is essential — together they found 3 secrets that neither tool alone would have fully covered.

### 3.11 GraphQL Vulnerability Coverage

The repository's `README.md` documents 6 intentionally implemented GraphQL vulnerabilities (Section 10). This section checks how many were detected by CodeQL and Snyk Code.

#### Implemented Vulnerabilities vs Scanner Results

| # | Documented Vulnerability | CWE | Snyk Code | CodeQL | Notes |
|---|---|---|---|---|---|
| 1 | **Enabled schema introspection** | CWE-200 | ❌ Not detected | ❌ Not detected | Neither tool flags GraphQL introspection being enabled. This is a configuration/design issue — SAST tools focus on code-level flaws, not API design decisions. Requires a dedicated GraphQL security scanner (e.g., InQL, graphql-cop). |
| 2 | **Weak JWT-based authentication** inherited by `/graphql` | CWE-326 | ⚠️ Indirect | ⚠️ Indirect | The hardcoded JWT secret (`"secret123"` in `auth.py:10`) is flagged by Snyk (`python/HardcodedKey`). The `none` algorithm allowance is not flagged by either tool. Neither tool correlates the JWT weakness specifically to the `/graphql` endpoint. |
| 3 | **SQL injection in GraphQL resolver query construction** | CWE-89 | ✅ Partial (3/5) | ✅ Grouped at sink | `transaction_graphql.py` has **5 f-string SQL injection points** (lines 45, 77, 105, 142, 143). **Snyk** flagged 3 — at the `execute_query()` call sites (lines 108, 145, 146) — but missed lines 45 and 77 (`_load_user_actor` and `_load_actor_by_account_number`). **CodeQL** groups these into its `database.py:255` sink alert (7 tracked paths), but does not identify them individually. |
| 4 | **Missing GraphQL depth/complexity controls** | CWE-770 | ❌ Not detected | ❌ Not detected | Neither tool checks for query depth/complexity limits. This is a GraphQL-specific DoS concern that requires specialized analysis. |
| 5 | **Raw GraphQL error disclosure** | CWE-209 | ❌ Not detected | ❌ Not detected | The endpoint at `app.py:250` passes raw `str(error)` to the JSON response. CodeQL has the `py/stack-trace-exposure` rule which catches this pattern elsewhere in `app.py`, but did not flag it inside the GraphQL handler. Snyk does not have an equivalent rule. |
| 6 | **Transaction analytics exposure through admin-scoped queries** | CWE-862 | ❌ Not detected | ❌ Not detected | The authorization logic in `_resolve_scope` allows admins to query any account's data. Neither tool performs authorization-logic analysis — this is a business-logic flaw that requires manual review or DAST. |

#### SQLi in GraphQL Resolvers — Detailed Breakdown

The 5 SQL injection points in `transaction_graphql.py`:

| Line | Function | Vulnerable Code | Snyk | CodeQL |
|---|---|---|---|---|
| 45 | `_load_user_actor` | `f"... WHERE id = {user_id}"` | ❌ Missed | Grouped into `database.py:255` |
| 77 | `_load_actor_by_account_number` | `f"... WHERE account_number = '{account_number}'"` | ❌ Missed | Grouped into `database.py:255` |
| 105→108 | `_load_transactions` | `f" WHERE from_account = '{scoped_account_number}' ..."` → `execute_query(query)` | ✅ Line 108 | Grouped into `database.py:255` |
| 142→145 | `_load_lending_and_bill_metrics` | `f" WHERE user_id = {scoped_user_id}"` → `execute_query(loan_query)` | ✅ Line 145 | Grouped into `database.py:255` |
| 143→146 | `_load_lending_and_bill_metrics` | `f" AND bp.user_id = {scoped_user_id}"` → `execute_query(bill_query)` | ✅ Line 146 | Grouped into `database.py:255` |

Snyk found 3 of 5 injection points. It missed the two where the f-string SQL is constructed and immediately passed to `execute_query()` in a single function (`_load_user_actor` at line 45 and `_load_actor_by_account_number` at line 77). The 3 it found are in functions where the SQL is built across multiple lines before being passed to `execute_query()`.

#### Summary

| Metric | Value |
|---|---|
| Documented GraphQL vulnerabilities | **6** |
| Fully detected by either tool | **1** (SQLi — partial) |
| Partially detected | **2** (SQLi resolvers, JWT weakness) |
| Not detected by either tool | **3** (introspection, depth limits, error disclosure) |
| Not detectable by SAST | **2** (depth/complexity, authorization logic) |
| **SAST detection rate** | **1.5 out of 4 detectable = ~38%** |

**Key takeaway:** SAST tools (both CodeQL and Snyk Code) catch only the SQL injection pattern among the 6 documented GraphQL vulnerabilities — and even then incompletely. Introspection, depth/complexity, error disclosure in GraphQL handlers, and authorization-logic flaws fall outside SAST capabilities. A comprehensive GraphQL security assessment requires complementary tooling: DAST (for introspection/auth testing), dedicated GraphQL scanners (for depth/complexity), and manual code review (for business-logic authorization).

---

## 5. Alert Grouping & Noise Analysis

This section evaluates how well each tool consolidates related findings to minimize alert fatigue.

### 4.1 CodeQL Grouping Assessment

| Aspect | Assessment | Impact |
|---|---|---|
| **Stack trace exposure** (39 alerts) | ⚠️ **Noisy but valuable.** All 39 alerts have identical messages for the same systemic pattern (`return str(e)` in `except` blocks). Better grouping (e.g., 1 alert with "39 instances") would improve UX. But this is a real vulnerability class (CWE-209) that **Snyk missed entirely** — noisy detection beats no detection. | 39 alerts that could be grouped better, but represent genuine findings that only CodeQL catches. |
| **XSS dual-rule overlap** (4 alerts → 2 locations) | ⚠️ **Minor duplication.** `js/xss` and `js/xss-through-dom` fire on the exact same lines (`blog.html:195`, `careers.html:223`). While the rules describe slightly different vulnerability mechanics, from a developer's perspective these are the same issue requiring the same fix. | 4 alerts that could be 2. Minor noise but still unnecessary duplication. |
| **SQL injection** (6 alerts) | ✅ **Excellent grouping.** 2 alerts at `database.py` sinks consolidate 7+3=10 taint paths into just 2 alerts. The 4 `auth.py` alerts are distinct direct `cursor.execute` calls. This is the gold standard for reducing triage burden. | 6 alerts for ~6 distinct fixable issues. Ideal. |
| **Other rules** (7 alerts) | ✅ **Well-grouped.** SSRF, debug mode, cert validation, logging, CI/CD — all one alert per distinct issue. | Clean. |

**CodeQL noise score: 41 unnecessary alerts out of 56 total (73% noise).** If CodeQL grouped the stack-trace findings into one and de-duplicated the XSS rules, the alert count would drop from 56 to ~17 — each representing a genuinely distinct issue. However, its SQL injection grouping is excellent and should be the model for other rules.

### 4.2 Snyk Code Grouping Assessment

| Aspect | Assessment | Impact |
|---|---|---|
| **SQL injection** (25 alerts) | ⚠️ **Over-reported.** The 25 alerts map to only ~6 distinct vulnerabilities. 17 alerts in `app.py` all flow to the same `execute_query()` sink, and 4 flow to `execute_transaction()`. Each alert is a different call site, but a developer fixing the sink function would resolve all of them at once. The varied taint-source messages ("HTTP request body", "HTTP parameter", "database") add useful context, but at the cost of 4× alert inflation vs CodeQL's sink-grouped approach. | 25 alerts for ~6 fixable issues. Creates an inflated impression of vulnerability count. |
| **DOM XSS** (22 alerts) | ✅ **Good granularity.** Unlike SQLi, each XSS alert points to a genuinely different `innerHTML` sink — these are distinct code locations that each need their own fix. All under a single rule ID (`javascript/DOMXSS`) — no rule duplication. | 22 distinct code locations. Appropriate. |
| **Other rules** (5 alerts) | ✅ **Excellent.** Each is a unique finding with a unique message. | No noise. |

**Snyk Code noise score: ~22 inflated alerts out of 52 total (~42% inflation).** The 25 SQLi alerts represent ~6 distinct issues (~19 excess), plus ~3 false positives on parameterized queries. The XSS and other findings are well-calibrated.

### 4.3 Grouping Comparison Summary

| Dimension | CodeQL | Snyk Code | Winner |
|---|---|---|---|
| **Alerts per distinct issue** | ~3.3× (56 alerts / ~17 issues) | ~1.7× (52 alerts / ~30 issues) | **CodeQL** (better for SQLi) |
| **SQL injection grouping** | 6 alerts for ~6 issues (1:1) | 25 alerts for ~6 issues (4:1 inflation) | **CodeQL** |
| **Stack trace detection** | 39 alerts (noisy but detected) | 0 alerts (missed entirely) | **CodeQL** — noisy beats absent |
| **XSS rule deduplication** | 2 rules on same line (2:1) | 1 rule per location (1:1) | **Snyk** |
| **Message diversity** | Identical messages for same rule | Varies by taint source | **Snyk** |
| **Developer triage experience** | Good for SQLi, noisy for stack-traces | Good for XSS, inflated for SQLi | **Mixed** |

**Verdict:** CodeQL is the stronger tool on grouping overall. Its SQL injection sink-level grouping is excellent (6 alerts vs Snyk's 25 for the same issues), and it is the **only tool to detect stack-trace exposure at all** — Snyk has zero coverage of this category. Yes, 39 identical alerts is noisy, but 39 noisy alerts is strictly better than 0 alerts for a real vulnerability class (CWE-209). CodeQL's only grouping weakness is presentation — it should consolidate those 39 into fewer alerts. Snyk's XSS grouping is clean (1 alert per sink), but its SQLi source-level reporting inflates the count 4×. A team using both tools needs to understand that **Snyk's 25 SQLi alerts ≈ CodeQL's 6 SQLi alerts** in terms of actual work required.

---

## 6. False Positive Analysis

### 5.1 Snyk Code False Positives

| Location | Rule | Why it's a false positive |
|---|---|---|
| `app.py:551` | `python/Sqli` | Calls `execute_transaction()` with queries like `"UPDATE users SET balance = balance - %s WHERE id = %s"` — all values passed as `%s` parameters. No user input in the SQL string. |
| `app.py:991` | `python/Sqli` | Same pattern: `"UPDATE loans SET status='approved' WHERE id = %s"` with parameterized values. Taint source is "from a database" — the loan data was already fetched safely. |
| `app.py:2185` | `python/Sqli` | Same pattern: `"UPDATE users SET balance = balance - %s WHERE id = %s"` with proper parameterization. |

**Root cause:** Snyk traces taint from HTTP input through to `cursor.execute()` but fails to recognize that `%s` parameterized queries prevent injection. It treats the `execute_transaction()` call itself as the vulnerability, even when only the parameter tuple (not the query string) contains user data.

**Estimated false positive rate:** ~3/52 = **~6%**

### 5.2 CodeQL Sink-Level Alerts

| Location | Rule | Assessment |
|---|---|---|
| `database.py:255` | `py/sql-injection` | Flags the `cursor.execute(query, params)` sink in `execute_query()`, grouping 7 taint paths. **This is good grouping, not a false positive** — multiple callers pass f-string queries through this function. The alert correctly identifies the convergence point. |
| `database.py:280` | `py/sql-injection` | Same pattern for `execute_transaction()`, grouping 3 taint paths. Also a correct sink-level finding. |

These are **accurate, well-grouped alerts**. By pointing at the sink, CodeQL gives the developer a single place to focus remediation (e.g., add input validation inside the function or fix all callers).

**Estimated CodeQL noise rate:** ~41/56 = **~73%** (39 identical stack-trace + 2 duplicate XSS rules on same lines)

---

## 7. Metadata & Severity Quality

| Dimension | CodeQL | Snyk Code |
|---|---|---|
| **Severity levels** | ✅ `critical`, `high`, `medium` — populated on all 56 alerts | ❌ All 52 alerts show `null` severity |
| **CWE references** | ✅ Standard format: `external/cwe/cwe-089`, `external/cwe/cwe-079`, etc. | ⚠️ Custom tags only: `Sqli`, `DOMXSS`, `Security` — no standard CWE IDs |
| **CVSS scores** | Implied by severity level | Not provided |
| **Taint-flow descriptions** | Generic: "This SQL query depends on a user-provided value" | ✅ Specific: "Unsanitized input from the HTTP request body flows into database.execute_query" |
| **Remediation guidance** | ✅ Full descriptions with "what" and "why" | ⚠️ Short descriptions only |
| **Rule documentation links** | ✅ Links to CodeQL query help pages | ❌ No links in SARIF output |

**Severity is a critical differentiator.** CodeQL's severity ratings enable immediate triage: the 1 critical SSRF alert and 13 high-severity alerts can be prioritized first, while the 42 medium stack-trace alerts can be batched into a separate remediation effort. Snyk's null-severity output means a security team must manually assess all 52 alerts to determine priority — a significant workflow penalty.

**Taint-flow messages are a Snyk strength.** Snyk's messages tell you exactly where the tainted data comes from ("HTTP request body", "HTTP parameter", "database") and where it flows to ("execute_query", "execute_transaction", "innerHTML"). CodeQL's messages are more generic ("depends on a user-provided value"), requiring the developer to inspect the code to understand the dataflow.

---

## 8. File Coverage Comparison

| File | Snyk Alerts | CodeQL Alerts | Notes |
|---|:---:|:---:|---|
| `app.py` | 22 | 42 | Both focus here; CodeQL inflated by 38 stack-trace alerts |
| `auth.py` | 5 | 5 | Equal coverage, 4 overlapping SQLi locations |
| `transaction_graphql.py` | 3 | 0 | **Snyk only** — 3 paths to `execute_query` that CodeQL groups into its `database.py:255` alert |
| `database.py` | 0 | 2 | **CodeQL only** — sink-level alerts grouping 7+3 taint paths from callers |
| `static/dashboard.js` | 10 | 0 | **Snyk only** — CodeQL doesn't analyze standalone JS files |
| `templates/admin.html` | 4 | 0 | **Snyk only** |
| `templates/blog.html` | 1 | 2 | Overlap: same line, CodeQL uses 2 rules |
| `templates/careers.html` | 1 | 2 | Overlap: same line, CodeQL uses 2 rules |
| `templates/forgot_password.html` | 1 | 0 | **Snyk only** |
| `templates/index.html` | 1 | 0 | **Snyk only** |
| `templates/login.html` | 1 | 0 | **Snyk only** |
| `templates/register.html` | 2 | 0 | **Snyk only** |
| `templates/reset_password.html` | 1 | 0 | **Snyk only** |
| `.github/workflows/build.yml` | 0 | 1 | **CodeQL only** — CI/CD scanning |
| `.github/workflows/deploy.yml` | 0 | 2 | **CodeQL only** — CI/CD scanning |

**Key takeaway:** Snyk covers 11 files vs CodeQL's 5. Snyk's JavaScript analysis extends to standalone `.js` files and inline scripts across all HTML templates, while CodeQL's JS coverage is limited to 2 template files. CodeQL's unique value is in `database.py` (sink analysis) and `.github/workflows/` (CI/CD security).

---

## 9. Precision vs Recall Summary

### Precision (signal-to-noise ratio)

| | CodeQL | Snyk Code |
|---|---|---|
| Total alerts | 56 | 52 |
| Distinct actionable issues (estimated) | ~17 | ~30 |
| Noise alerts (duplicates + identical patterns) | ~39 (stack-trace + XSS dup) | ~22 (SQLi path inflation + FPs) |
| **Precision (alerts/issues)** | **~30%** (after grouping penalty) | **~58%** |

Both tools have significant noise, but for different reasons. CodeQL's noise is dominated by the 39 identical stack-trace alerts. Snyk's noise comes from reporting 25 SQLi alerts for ~6 distinct vulnerabilities. If we count by _distinct fixable issues_, CodeQL has ~17 issues in 56 alerts and Snyk has ~30 issues in 52 alerts.

### Recall (completeness)

| | CodeQL | Snyk Code |
|---|---|---|
| SQLi distinct vulnerabilities | ~6 (grouped into 6 alerts) | ~6 (spread across 25 alerts) |
| SQLi taint paths traced | 14 | **21** |
| XSS distinct locations | 2 | **22** |
| Unique high/critical findings only it found | **3** (SSRF, password logging, clear-text logging) | **3** (hardcoded key, hardcoded secret, insecure cookie) |
| Secret detection | N/A (separate tool: GitHub Secret Scanning) | **2** (hardcoded crypto key + app secret) |
| Vulnerability categories covered | **10** (no secret detection) | 7 (includes hardcoded secrets) |
| **Recall for SQLi** | **Equal** (same vulns, fewer paths) | **Equal** (same vulns, more paths) |
| **Recall for XSS** | Low | **High** |
| **Recall across all categories** | **High** | Moderate |

### Combined Scoring

| Dimension | CodeQL | Snyk Code | Winner |
|---|---|---|---|
| SQL Injection (distinct vulns) | ~6 | ~6 | **Tie** — same vulnerabilities |
| SQL Injection (grouping UX) | **6 alerts** | 25 alerts | **CodeQL** |
| SQL Injection (path detail) | 14 paths, generic messages | **21 paths, source-specific messages** | **Snyk** |
| XSS detection | 2 unique locations | **22 locations** | **Snyk** |
| Breadth of categories | **10 categories** | 7 categories | **CodeQL** |
| Critical/high-severity finds | **SSRF (critical), password logging (high)** | Hardcoded key, insecure cookie | **CodeQL** |
| Secret detection (vs GitHub Secret Scanning) | N/A — GitHub Secret Scanning found 1 API key (DeepSeek) in `.env` | **2 hardcoded secrets** in source code (`auth.py`, `app.py`) — zero overlap with Secret Scanning | **Complementary** |
| Alert grouping (SQLi) | **Excellent** (sink-level) | Poor (source-level inflation) | **CodeQL** |
| Alert grouping (stack-trace) | 39 alerts — noisy but detected | **0 alerts — missed entirely** | **CodeQL** — noise > silence |
| Severity classification | **✅ Populated** | ❌ All null | **CodeQL** |
| Taint-flow message quality | Generic | **Specific per-source** | **Snyk** |
| CWE references | **✅ Standard CWEs** | Tags only | **CodeQL** |
| CI/CD security coverage | **✅ 3 findings** | Not covered | **CodeQL** |
| JavaScript file coverage | 2 HTML files | **9 JS/HTML files** | **Snyk** |

---

## 10. Recommendations

### Run Both Tools Together

Neither tool provides complete coverage. The combined view catches:
- **~6 SQLi vulnerabilities** (both tools detect them; CodeQL groups better, Snyk enumerates more paths)
- **22 XSS locations** (driven almost entirely by Snyk)
- **1 critical SSRF + 1 high password-logging** (CodeQL only)
- **3 CI/CD hardening** issues (CodeQL only)
- **3 hardcoded secrets/cookie** issues (Snyk only)

### Triage Strategy

1. **Start with CodeQL critical/high** — the SSRF (`py/full-ssrf`) and password-logging (`py/clear-text-logging-sensitive-data`) findings are highest priority and only CodeQL found them.
2. **Use CodeQL's 6 SQLi alerts as the primary triage view** — they represent the same ~6 distinct vulnerabilities as Snyk's 25 alerts, but with better grouping. Cross-reference Snyk's alerts for call-site detail when fixing.
3. **Use Snyk for XSS** — its 22 DOM XSS findings are genuine and CodeQL catches only 2 of them.
4. **Batch CodeQL's stack-trace alerts** — treat the 39 `py/stack-trace-exposure` findings as a single remediation item (add a global error handler that sanitizes exception messages).
5. **Address Snyk's hardcoded secrets** — rotate the JWT key and application secret.
6. **Harden CI/CD** — add permissions blocks and pin action tags per CodeQL's workflow findings.

### Improving Signal Quality

- **For CodeQL:** Consider adding a `.github/codeql/codeql-config.yml` that adjusts the `py/stack-trace-exposure` query severity or groups findings by pattern, to reduce the 39-alert noise.
- **For Snyk Code:** Investigate Snyk's SARIF configuration to ensure severity levels are populated in the upload. The missing severity data significantly hampers triage in GitHub's Code Scanning UI. Also, consider that Snyk's source-level SQLi reporting inflates alert counts — use CodeQL's grouped view for SQLi triage.
