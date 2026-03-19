# CodeQL vs Snyk Code — SAST Comparison Report

**Repository:** `octodemo/snyk-crew`
**Date:** 2026-03-19
**Scope:** All 108 open Code Scanning alerts from GitHub Advanced Security (CodeQL) and Snyk Code

---

## Executive Summary

Both CodeQL and Snyk Code were run against the same Python/Flask codebase. Together they produced 108 open alerts. **They are strongly complementary — neither tool alone provides adequate coverage.**

**CodeQL** (56 alerts) excels at **breadth and precision**. It covers 10 distinct vulnerability categories, assigns accurate severity levels (1 critical, 13 high, 42 medium), and provides CWE references for every finding. It is the only tool to detect the critical SSRF vulnerability and the clear-text password logging issue. However, it severely under-reports SQL injection (6 vs Snyk's 25) and XSS (4 vs Snyk's 22), and its 39 stack-trace-exposure alerts — all with identical messages — create significant noise that hurts triage efficiency.

**Snyk Code** (52 alerts) excels at **depth in injection-flaw detection**. It finds 4× more SQL injection and 5× more XSS locations than CodeQL. Its taint-flow messages are descriptive and vary by source type. However, it **does not populate severity levels** (all 52 show as `null`), misses several high-impact categories entirely (SSRF, sensitive data logging, CI/CD misconfigurations), and produces false positives on properly parameterized SQL queries.

**On alert grouping and noise:** CodeQL is significantly noisier — 70% of its alerts (39/56) are a single repeated pattern (`py/stack-trace-exposure`) with identical messages. Snyk avoids this problem entirely; its alerts are diverse and each points to a distinct code location with a distinct taint flow. However, CodeQL's dual XSS rules (`js/xss` + `js/xss-through-dom`) on the same line are a minor de-duplication issue, while Snyk consolidates XSS under one rule ID. See the [Alert Grouping & Noise Analysis](#alert-grouping--noise-analysis) section for a detailed breakdown.

**Bottom line:** Run both. Use CodeQL for severity-based triage and broad category coverage. Use Snyk Code for deep injection-flaw detection. Together they catch vulnerabilities that either tool alone would miss.

---

## Table of Contents

1. [Alert Totals](#1-alert-totals)
2. [Finding Categories — Side-by-Side](#2-finding-categories--side-by-side)
3. [Detailed Finding-by-Finding Comparison](#3-detailed-finding-by-finding-comparison)
4. [Alert Grouping & Noise Analysis](#4-alert-grouping--noise-analysis)
5. [False Positive Analysis](#5-false-positive-analysis)
6. [Metadata & Severity Quality](#6-metadata--severity-quality)
7. [File Coverage Comparison](#7-file-coverage-comparison)
8. [Precision vs Recall Summary](#8-precision-vs-recall-summary)
9. [Recommendations](#9-recommendations)

---

## 1. Alert Totals

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

## 2. Finding Categories — Side-by-Side

| Vulnerability Category | CWE | Snyk Code | CodeQL | Found By |
|---|---|:---:|:---:|---|
| SQL Injection | CWE-89 | **25** | 6 | Both |
| DOM-based Cross-site Scripting | CWE-79 | **22** | 4 | Both |
| Stack Trace / Exception Exposure | CWE-209 | 0 | **39** | CodeQL only |
| Full Server-Side Request Forgery | CWE-918 | 0 | **1** | CodeQL only |
| Clear-text Logging of Passwords | CWE-532 | 0 | **1** | CodeQL only |
| Request Without Cert Validation | CWE-295 | 1 | 1 | Both |
| Flask Debug Mode Enabled | CWE-215 | 1 | 1 | Both |
| Hardcoded Cryptographic Key | CWE-321 | **1** | 0 | Snyk only |
| Hardcoded Non-Crypto Secret | CWE-798 | **1** | 0 | Snyk only |
| Insecure Cookie (missing `Secure`) | CWE-614 | **1** | 0 | Snyk only |
| Workflow Missing Permissions | CWE-275 | 0 | **2** | CodeQL only |
| Unpinned Action Tag | CWE-829 | 0 | **1** | CodeQL only |

---

## 3. Detailed Finding-by-Finding Comparison

### 3.1 SQL Injection

| | Snyk Code | CodeQL |
|---|---|---|
| Rule ID | `python/Sqli` | `py/sql-injection` |
| Total alerts | **25** | 6 |
| Files | `app.py` (18), `auth.py` (4), `transaction_graphql.py` (3) | `auth.py` (4), `database.py` (2) |
| Severity | null | high |
| CWE | Tags: `Sqli, Taint, SourceHttpParam` | `external/cwe/cwe-089` |

**Line-level overlap:**

- **4 shared locations** — all in `auth.py` (lines 121, 157, 191, 195). Both tools correctly flag f-string SQL queries like `f"SELECT * FROM users WHERE username='{username}'"`.
- **21 Snyk-only locations** — 18 in `app.py`, 3 in `transaction_graphql.py`. These include:
  - **True positives** (majority): `app.py:487` (`f"SELECT ... WHERE account_number='{account_number}'"`) — classic f-string injection. Similarly lines 596, 1128, 1155, 1254, 1304, 1352, 1590, 1641, 1828, 2076, 2104 all use f-strings or string concatenation to build SQL.
  - **True positive with nuance**: `app.py:325` — uses `%s` for values but dynamically builds column names from user input (`', '.join(fields)` where `fields` comes from `user_data.items()`). This is a real SQL injection via column-name manipulation that CodeQL missed.
  - **False positives**: `app.py:551`, `app.py:991`, `app.py:2185` — all call `execute_transaction()` with properly parameterized queries using `%s` placeholders. User input flows only into parameter tuples, never into the SQL string itself. Snyk flags these because it traces taint to the `cursor.execute()` sink without recognizing that parameterized queries neutralize the injection.
- **2 CodeQL-only locations** — both in `database.py` (lines 255, 280). These flag the generic `cursor.execute(query, params)` functions themselves — the execution sinks. While technically these are the code points where injection occurs, they are **low-signal** because the vulnerability depends entirely on how callers construct the `query` argument. These are sink-level findings, not source-level findings.

**Verdict:** Snyk has far superior recall (25 vs 6), catching 21 real injection points that CodeQL misses entirely across `app.py`. CodeQL's dataflow analysis is too conservative here — it successfully traces taint through `auth.py` but fails to follow it through the larger `app.py` call chains. However, Snyk's ~3 false positives on parameterized queries show it doesn't fully resolve safe parameterization patterns.

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

**This is CodeQL's biggest noise contributor** — 39 alerts of the same pattern constitute 70% of all CodeQL findings and 36% of all alerts across both tools. See [Section 4](#4-alert-grouping--noise-analysis) for detailed noise analysis.

Snyk Code does not have an equivalent rule and ignores this category entirely.

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
| **Hardcoded Cryptographic Key** | `python/HardcodedKey` | `auth.py:10` | **High-quality true positive.** JWT secret key hardcoded in source — critical for production. CodeQL has no equivalent rule for Python. |
| **Hardcoded Non-Crypto Secret** | `python/HardcodedNonCryptoSecret` | `app.py:48` | **True positive.** Application secret hardcoded. |
| **Insecure Cookie** | `python/WebCookieMissesCallToSetSecure` | `app.py:412` | **True positive.** Session cookie missing `Secure` attribute. CodeQL has this rule for other frameworks but didn't trigger for Flask here. |

### 3.9 CodeQL-Only Findings (CI/CD)

| Finding | Rule ID | File | Severity |
|---|---|---|---|
| Missing workflow permissions | `actions/missing-workflow-permissions` | `build.yml` | medium |
| Missing workflow permissions | `actions/missing-workflow-permissions` | `deploy.yml` | medium |
| Unpinned 3rd-party action tag | `actions/unpinned-tag` | `deploy.yml` | medium |

These are **supply-chain and CI/CD hardening** findings that Snyk Code does not cover at all (Snyk's SAST focuses on application code, not workflow files).

---

## 4. Alert Grouping & Noise Analysis

This section evaluates how well each tool consolidates related findings to minimize alert fatigue.

### 4.1 CodeQL Grouping Assessment

| Aspect | Assessment | Impact |
|---|---|---|
| **Stack trace exposure** (39 alerts) | ❌ **Very noisy.** All 39 alerts have the identical message, identical rule, identical severity. They represent a single systemic pattern (`return str(e)` in `except` blocks) but are reported as 39 separate alerts. A single alert with "39 instances" would be far more effective. | 39 alerts that could be 1. This makes the alert dashboard appear dominated by medium-severity noise, burying the 1 critical and 13 high findings. |
| **XSS dual-rule overlap** (4 alerts → 2 locations) | ⚠️ **Minor duplication.** `js/xss` and `js/xss-through-dom` fire on the exact same lines (`blog.html:195`, `careers.html:223`). While the rules describe slightly different vulnerability mechanics, from a developer's perspective these are the same issue requiring the same fix. | 4 alerts that could be 2. Minor noise but still unnecessary duplication. |
| **SQL injection** (6 alerts) | ✅ **Well-grouped.** Each alert is a distinct code location. No duplication. | Clean. |
| **Other rules** (7 alerts) | ✅ **Well-grouped.** SSRF, debug mode, cert validation, logging, CI/CD — all one alert per distinct issue. | Clean. |

**CodeQL noise score: 41 unnecessary alerts out of 56 total (73% noise).** If CodeQL grouped the stack-trace findings into one and de-duplicated the XSS rules, the alert count would drop from 56 to ~17 — each representing a genuinely distinct issue.

### 4.2 Snyk Code Grouping Assessment

| Aspect | Assessment | Impact |
|---|---|---|
| **SQL injection** (25 alerts) | ✅ **Good granularity.** Each alert points to a different code location. The taint-flow messages vary meaningfully: "Unsanitized input from the HTTP request body", "from an HTTP parameter", "from a database" — helping developers understand the specific data flow. | 25 distinct code locations, each with a unique taint path. Appropriate. |
| **DOM XSS** (22 alerts) | ✅ **Good granularity.** Each alert points to a different `innerHTML` sink. The source description varies ("from the document location" vs "from data from a remote resource"), providing useful triage context. All under a single rule ID (`javascript/DOMXSS`) — no rule duplication. | 22 distinct code locations. Clean. |
| **Other rules** (5 alerts) | ✅ **Excellent.** Each is a unique finding with a unique message. | No noise. |

**Snyk Code noise score: ~3 false positives out of 52 total (6% noise).** Snyk's only noise comes from the ~3 false positive SQLi alerts on parameterized queries, not from poor grouping. Every alert ID maps to a distinct code location.

### 4.3 Grouping Comparison Summary

| Dimension | CodeQL | Snyk Code | Winner |
|---|---|---|---|
| **Alerts per distinct issue** | ~3.3× (56 alerts / ~17 issues) | ~1.1× (52 alerts / ~49 issues) | **Snyk** |
| **Worst grouping offender** | 39 identical stack-trace alerts | 3 false-positive SQLi alerts | **Snyk** (by far) |
| **Rule deduplication** | 2 XSS rules on same line | 1 rule per vulnerability class | **Snyk** |
| **Message diversity** | Identical messages for same rule | Varies by taint source | **Snyk** |
| **Developer triage experience** | Dashboard dominated by medium noise | Each alert is distinct and actionable | **Snyk** |

**Verdict:** Snyk Code is significantly better at avoiding noise. Every Snyk alert represents a distinct code location with a meaningful, varied message. CodeQL's lack of grouping for `py/stack-trace-exposure` creates a wall of identical alerts that degrades triage quality substantially — a security team seeing 56 CodeQL alerts may not realize that 39 of them are the same pattern and only ~17 are distinct.

---

## 5. False Positive Analysis

### 5.1 Snyk Code False Positives

| Location | Rule | Why it's a false positive |
|---|---|---|
| `app.py:551` | `python/Sqli` | Calls `execute_transaction()` with queries like `"UPDATE users SET balance = balance - %s WHERE id = %s"` — all values passed as `%s` parameters. No user input in the SQL string. |
| `app.py:991` | `python/Sqli` | Same pattern: `"UPDATE loans SET status='approved' WHERE id = %s"` with parameterized values. Taint source is "from a database" — the loan data was already fetched safely. |
| `app.py:2185` | `python/Sqli` | Same pattern: `"UPDATE users SET balance = balance - %s WHERE id = %s"` with proper parameterization. |

**Root cause:** Snyk traces taint from HTTP input through to `cursor.execute()` but fails to recognize that `%s` parameterized queries prevent injection. It treats the `execute_transaction()` call itself as the vulnerability, even when only the parameter tuple (not the query string) contains user data.

**Estimated false positive rate:** ~3/52 = **~6%**

### 5.2 CodeQL False Positives

| Location | Rule | Why it's low-signal |
|---|---|---|
| `database.py:255` | `py/sql-injection` | Flags the generic `cursor.execute(query, params)` helper function — the sink, not the source. Whether this is exploitable depends entirely on how callers construct `query`. |
| `database.py:280` | `py/sql-injection` | Same — flags `cursor.execute(query, params)` inside `execute_transaction()`. The function itself is safe when called with parameterized queries. |

These aren't strictly false positives — they're **low-signal sink-level findings** that shift the burden to the developer to trace all callers.

**Estimated noise rate:** ~41/56 = **~73%** (39 identical stack-trace + 2 duplicate XSS + 2 low-signal sinks)

---

## 6. Metadata & Severity Quality

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

## 7. File Coverage Comparison

| File | Snyk Alerts | CodeQL Alerts | Notes |
|---|:---:|:---:|---|
| `app.py` | 22 | 42 | Both focus here; CodeQL inflated by 38 stack-trace alerts |
| `auth.py` | 5 | 5 | Equal coverage, 4 overlapping SQLi locations |
| `transaction_graphql.py` | 3 | 0 | **Snyk only** — CodeQL missed 3 SQLi in GraphQL resolvers |
| `database.py` | 0 | 2 | **CodeQL only** — sink-level SQLi findings |
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

## 8. Precision vs Recall Summary

### Precision (signal-to-noise ratio)

| | CodeQL | Snyk Code |
|---|---|---|
| Total alerts | 56 | 52 |
| Distinct actionable issues (estimated) | ~17 | ~49 |
| Noise alerts (duplicates + identical patterns) | ~39 | ~3 |
| **Precision** | **~30%** (after grouping penalty) | **~94%** |

If we set aside the grouping issue and count by _distinct rule categories_, CodeQL has ~89% precision (only the database.py sink findings are truly low-signal). The problem is the presentation, not the analysis.

### Recall (completeness)

| | CodeQL | Snyk Code |
|---|---|---|
| SQLi locations found | 6 | **25** |
| XSS locations found | 2 (unique) | **22** |
| Unique high/critical findings only it found | **3** (SSRF, password logging, clear-text logging) | **3** (hardcoded key, hardcoded secret, insecure cookie) |
| Vulnerability categories covered | **10** | 7 |
| **Recall for injection flaws** | Low | **High** |
| **Recall across all categories** | **High** | Moderate |

### Combined Scoring

| Dimension | CodeQL | Snyk Code | Winner |
|---|---|---|---|
| SQL Injection detection | 6 locations | **25 locations** | **Snyk** |
| XSS detection | 2 unique locations | **22 locations** | **Snyk** |
| Breadth of categories | **10 categories** | 7 categories | **CodeQL** |
| Critical/high-severity finds | **SSRF (critical), password logging (high)** | Hardcoded key, insecure cookie | **CodeQL** |
| Precision (fewer false positives) | 89% (per-rule) / 30% (per-alert) | **94%** | **Snyk** |
| Alert grouping quality | 73% noise | **6% noise** | **Snyk** |
| Severity classification | **✅ Populated** | ❌ All null | **CodeQL** |
| Taint-flow message quality | Generic | **Specific per-source** | **Snyk** |
| CWE references | **✅ Standard CWEs** | Tags only | **CodeQL** |
| CI/CD security coverage | **✅ 3 findings** | Not covered | **CodeQL** |
| JavaScript file coverage | 2 HTML files | **9 JS/HTML files** | **Snyk** |

---

## 9. Recommendations

### Run Both Tools Together

Neither tool provides complete coverage. The combined view catches:
- **25 SQLi + 22 XSS** locations (driven by Snyk)
- **1 critical SSRF + 1 high password-logging** (driven by CodeQL)
- **3 CI/CD hardening** issues (CodeQL only)
- **3 hardcoded secrets/cookie** issues (Snyk only)

### Triage Strategy

1. **Start with CodeQL critical/high** — the SSRF (`py/full-ssrf`) and password-logging (`py/clear-text-logging-sensitive-data`) findings are highest priority and only CodeQL found them.
2. **Review Snyk SQLi and XSS** — these have the highest volume of true positives. Dismiss alerts on lines using `%s` parameterized queries (likely false positives).
3. **Batch CodeQL's stack-trace alerts** — treat the 39 `py/stack-trace-exposure` findings as a single remediation item (add a global error handler that sanitizes exception messages).
4. **Address Snyk's hardcoded secrets** — rotate the JWT key and application secret.
5. **Harden CI/CD** — add permissions blocks and pin action tags per CodeQL's workflow findings.

### Improving Signal Quality

- **For CodeQL:** Consider adding a `.github/codeql/codeql-config.yml` that adjusts the `py/stack-trace-exposure` query severity or groups findings by pattern, to reduce the 39-alert noise.
- **For Snyk Code:** Investigate Snyk's SARIF configuration to ensure severity levels are populated in the upload. The missing severity data significantly hampers triage in GitHub's Code Scanning UI.
