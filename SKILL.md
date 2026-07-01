---
name: vulnerability-exploit-developer
description: >-
  Audit source code for security vulnerabilities and develop working
  proof-of-concept exploits for each confirmed finding. Trigger when the user
  asks to "find vulnerabilities", "audit/review this code for security",
  "pentest this app", "write/develop an exploit or PoC", "is this code
  exploitable", or hands over a file/repo/endpoint and asks what's wrong with it
  security-wise. Covers web apps and APIs (SQLi, command/template injection,
  authn/authz, SSRF, path traversal, insecure deserialization, XXE, SSTI,
  secrets, unsafe debug/RCE, crypto misuse). Produces: a ranked findings report
  AND runnable exploits validated against a LOCAL replica.
---

# Vulnerability & Exploit Developer

A repeatable workflow to (1) find **all** vulnerabilities in the code in scope and
(2) develop a **working, documented exploit** for each confirmed one. It codifies
the analyze → weaponize → prove → remediate loop.

## Safety & scope rail (read first — non-negotiable)

- **Only run exploits against a local replica or an explicitly authorized target.**
  Never fire a live-written exploit at production or third-party infrastructure
  from this skill. When in doubt, spin up the code locally and attack *that*.
- If the target is not obviously local/authorized, **ask for authorization scope**
  before sending any exploit traffic; static analysis + a *non-firing* PoC is the
  safe default until scope is confirmed.
- Keep everything in a scratch/sandbox dir. Don't exfiltrate real data; use
  planted/synthetic secrets in replicas.

## Workflow

### 1. Recon & map the attack surface
- Identify language/framework, entry points (routes, handlers, CLI args, message
  consumers), and every place **untrusted input** enters (query/body/headers/
  path/params/env/files/DB).
- Note the trust boundaries and the privileges each component runs with
  (DB user grants, filesystem, network egress, `debug=True`, etc.).
- Build a quick table: `input → sink → context`.

### 2. Analyze for each vulnerability class
Walk this checklist against every input→sink path. For each, the tell-tale sink
and the exploitation primitive:

| Class | Look for (sink) | Exploit primitive |
|---|---|---|
| **SQL injection** (CWE-89) | string-built SQL (f-strings, `%`, `+`, `.format`) into `execute` | UNION/error/boolean/time; if output reflects → in-band `UNION`+`group_concat`; else blind binary-search oracle |
| **Command injection** (CWE-78) | `os.system`, `subprocess(..., shell=True)`, backticks with user data | `;`, `|`, `$( )`, `&&`; blind → time/DNS/OOB |
| **Server-Side Template Injection** | user input into template string (Jinja2 `render_template_string`, etc.) | `{{7*7}}` probe → sandbox escape → RCE |
| **Path traversal / LFI** (CWE-22) | `open`, `send_file`, file paths built from input | `../`, absolute paths, null/encoding tricks |
| **SSRF** (CWE-918) | server-side fetch of a user-supplied URL | internal IPs, `169.254.169.254`, `file://`, redirect bypass |
| **AuthN / AuthZ** | missing ownership checks (IDOR), weak session/JWT, recovery flows | swap IDs; `alg=none`/key confusion; recovery-channel abuse |
| **Insecure deserialization** | `pickle.loads`, `yaml.load`, native deserializers on input | gadget chain → RCE |
| **XXE** (CWE-611) | XML parser with external entities enabled | `SYSTEM` entity file read / SSRF |
| **Debug / dev-server exposure** (CWE-489 → CWE-94) | Flask `debug=True`, Werkzeug interactive debugger, dev server bound to `0.0.0.0`, stack-trace pages | debugger-console PIN → RCE; source & stack disclosure |
| **Secrets & error disclosure** (CWE-209 / CWE-798) | hardcoded keys/creds; verbose errors returned to the client (`str(e)`, raw tracebacks) | error-based oracle; credential reuse |
| **Crypto / randomness** | `md5`/`sha1` for auth, static IV, `random` for tokens | forgery / prediction |
| **Race / logic** | check-then-act on money/state, missing idempotency | TOCTOU, double-spend, negative amounts |

Prioritise by **impact × reachability**. Reflected output, error echoing, and
over-privileged DB/service accounts are force multipliers — flag them.

### 3. Confirm (no false positives)
- Trace the tainted data end-to-end; confirm no sanitizer/parameterization on the
  path. Distinguish the vulnerable sink from safe siblings (e.g., a parameterized
  `?` query next to an f-string query — only the latter is exploitable).

### 4. Build the exploit against a local replica
- Reconstruct a minimal runnable target: copy the vulnerable code verbatim; only
  change externalities (DB path, ports) via env vars — never the vulnerable logic.
- Seed a realistic dataset (multiple tables/objects; a planted synthetic
  secret/flag) so the exploit must **generalize**, not hardcode a location.
- Write the exploit as a **standalone, well-documented script**. Requirements:
  - Module docstring: the vuln, the strategy, why it's fast, and any fallback.
  - **Confirm** step (sentinel) before extraction.
  - **Enumerate then cover everything** (full schema/surface), not a guessed spot.
  - **Performance (scaled to the target)**: minimize request count first (aggregate via `group_concat`/batching); reuse the connection (`Session`). Add concurrency *only* when request volume actually warrants it — don't over-engineer a small target.
  - **Robustness**: automatic fallback channel (e.g., in-band → boolean-blind).
  - Clear success output and telemetry (time, request count).
- **Validate**: run it; confirm it extracts the planted secret. Then **move the
  secret** and re-run unchanged to prove generality. Measure wall-clock time.

### 5. Report & remediate
For each finding produce:
- **Title / CWE / severity**, exact `file:line`, and the tainted path.
- **PoC**: the runnable exploit + observed output (redacted as needed).
- **Impact**: what an attacker gains (data, RCE, funds, lateral movement).
- **Fix**: the concrete, minimal remediation (parameterize, least-privilege,
  disable debug, stop echoing errors, add authz check, etc.) plus defense-in-depth.

## Worked example — *one* illustration of the method (do not pattern-match)

> This walks the reasoning loop end-to-end on a single app. The **method transfers;
> the specific payloads do not.** On a different codebase, re-derive from the actual
> sink — don't reach for `sqlite_master` / `group_concat` / a `CW{` regex by reflex
> just because they appear here.

A Flask app exposes `GET /api/user?username=` that builds SQL with an f-string on
SQLite and **reflects** the selected columns; it also returns `str(e)` on error and
runs with `debug=True`. Walking the checklist yields **three** findings, not one —
the SQL injection (critical), the error disclosure, and the debug/dev-server
exposure — plus a safe parameterized sibling `/api/profile` that models the fix.
(Reporting all three, not just the flashiest, is the point of step 2.)

For the SQLi, the *reasoning* (not a recipe) is: **reflection + a single-row read →
in-band `UNION` is viable**, and an aggregate function (here SQLite's `group_concat`)
collapses a whole-table scan into one reflected row. Because the target string's
location is unknown, **enumerate the schema first, then scan every column** instead
of guessing. Keep an automatic blind fallback (a 200-vs-404 boolean oracle with a
per-character binary search) for when reflection is unavailable. Fixes: parameterized
queries, a least-privilege DB account, stop echoing errors, and `debug=False` behind
a production WSGI server.

## Output format
1. **Summary table** of findings, ranked by severity.
2. Per-finding detail (CWE, location, PoC, impact, fix) as above.
3. Runnable exploit file(s) saved to the workspace, each self-documented.
4. A short **defensive** section (systemic fixes + detection ideas).
