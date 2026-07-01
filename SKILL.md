---
name: vulnerability-exploit-developer
description: >-
  Audit code and find ANY security vulnerability in it, known class or novel,
  including business-logic and chained flaws, then prove each one with a working
  proof-of-concept. Works by understanding the application, mapping where
  untrusted data meets power, and running time-boxed spikes to confirm or kill
  hypotheses. Scores findings with CVSS and validates exploits against a LOCAL
  replica. Trigger when the user asks to "find vulnerabilities", "audit/review
  this code for security", "pentest this app", "write/develop an exploit or PoC",
  "is this code exploitable", or hands over a file/repo/endpoint and asks what's
  wrong with it security-wise.
---

# Vulnerability & Exploit Developer

Find any vulnerability in the code in scope, whether or not it has a textbook name, prove each one
with a working exploit, and say exactly how to fix it. This is discovery-driven, not
checklist-driven. You reason from the code, form hypotheses, and run spikes to confirm them. The loop
is understand, map, hypothesize and spike, confirm, score, weaponize, remediate. Every claim ties to
a `file:line`, a payload, or a score, never a vague "might be insecure".

## Safety & scope rail (read first, non-negotiable)
- Only run spikes or exploits against a local replica or an explicitly authorized target. Never fire
  a live payload at production or third-party infrastructure. When unsure, stand the code up locally
  and attack that.
- If scope is not clearly authorized, ask before sending any traffic. Static analysis plus a
  non-firing PoC is the safe default until it is.
- Work in a scratch or sandbox dir, and use planted or synthetic secrets, never real data.

## 0. Understand the application first
You cannot rate, or even find, what you do not understand. Build a short model before touching
anything.
- **Purpose & users.** What it does, who calls it, which roles exist.
- **Data & money.** What it holds (secrets, keys, PII, cardholder data, health data) or moves (funds).
  This sets the stakes.
- **Trust boundaries.** Where untrusted input crosses in, and the privilege each component runs with
  (DB grants, filesystem, network egress, `debug`).
- **Deployment.** Internet-facing or internal, what auth sits in front, single- vs multi-tenant.

Context is what makes a later severity honest. A bug in a payments path is not a bug in a demo.

## 1. Map where untrusted data meets power
Forget bug names for a moment and map the terrain.
- Follow every untrusted input (query, body, headers, path, cookies, env, files, upstream data) to
  the point where it does something powerful. That could be a query, a shell, a template, a file
  path, a URL fetch, a deserializer, an auth or session or recovery decision, a money or state
  change, or the response itself.
- Mark every trust boundary and every assumption the code makes ("this is always an int", "only an
  admin reaches here", "this token must be valid", "the amount is positive"). Vulnerabilities live
  exactly where an assumption is wrong or a boundary goes unchecked.
- Note the privilege each component holds and what a break there would yield.

The output is a map of *where untrusted data meets power*, not a list of CVE names.

## 2. Hypothesize & spike (the core loop)
Work by hypothesis, and prove or kill each one fast.
- State a concrete hypothesis for a sink or assumption, for example "this input reaches the query
  unescaped", "changing this id returns another tenant's record", "this reset accepts a guessable
  token", "two concurrent requests double-spend".
- Run a spike, a small, time-boxed, throwaway probe (one request, one payload, one local test) that
  confirms or kills the hypothesis in minutes. Keep what fires, and drop the rest without ceremony.
- Follow surprises. An odd error, a timing difference, a reflected value or an unexpected status
  often exposes a bug no checklist would have named. Chase them, because that is where the
  interesting findings and the chains live.
- Iterate until the surface from step 1 is covered. Spikes are how you catch business-logic flaws,
  multi-step chains and novel issues, not just the familiar classes.

> Memory-joggers, and non-exhaustive. Treat these as a starting prompt, never the finish line.
> Injection of every kind (SQL, command, template), broken authz and IDOR, auth and recovery abuse,
> SSRF, path traversal, insecure deserialization, XXE, exposed debug or dev servers, secret and error
> leakage, weak crypto or randomness, race conditions and logic flaws. If something does not fit a
> name, it is still a finding, so write it up anyway.

## 3. Fan out specialist agents (in parallel)
For anything larger than a single file, do not do one generalist pass. Launch parallel specialists
split by area of the app, each carrying the step-0 context and each told to report any weakness in
its area, named class or not.
- request handling and data access
- authentication, session, recovery and access control
- secrets, crypto and configuration
- external interactions (outbound fetch, file handling, XML, serialization)
- business logic and money movement
- dependencies, build and CI

Then a synthesis pass. Dedupe, discard false positives, and chain findings. A leak plus a weak reset
plus an unscoped API key is one critical path, not three mediums. Parallel specialists are faster and
avoid a single reviewer's tunnel vision, so keep each scope tight to keep the output concrete.

## 4. Confirm (no false positives)
Trace the tainted data end-to-end and confirm there is no sanitizer, parameterization or authz on the
path. Distinguish the vulnerable spot from safe siblings. If you cannot actually reach it, say so and
downgrade it.

## 5. Score with CVSS
Score every confirmed finding with CVSS v4.0 (fall back to 3.1 only if tooling requires it). Publish
the vector, base score and severity band, then recompute with Environmental metrics using the step-0
context and prioritise on that, not the base. Where findings chain, score the chain, since it usually
outranks any single link.

## 6. Weaponize against a local replica
A confirmed spike graduates into a real, documented exploit.
- Rebuild a minimal runnable target. Copy the vulnerable code verbatim, and change only externalities
  (paths, ports) via env vars, never the vulnerable logic. Seed a realistic dataset with a planted
  synthetic secret so the exploit must generalize, not hardcode a location.
- Write it as a standalone, documented script. Include a docstring (vuln, strategy, any fallback), a
  confirm or sentinel step, then enumerate and cover the whole surface. Scale performance to the
  target, minimising round-trips first by batching or aggregating where the sink allows, and adding
  concurrency only when volume warrants it. Add an automatic fallback channel where one exists, plus
  clear success output and telemetry.
- Validate. Run it, confirm it works, then move the secret and re-run unchanged to prove generality.

## 7. Report & remediate
Per finding.
- **Title, CWE, CVSS v4.0** (vector, score, severity), exact `file:line`, tainted path.
- **PoC.** The runnable exploit plus observed output.
- **Impact.** In the app's own terms (data, RCE, funds, lateral movement).
- **Fix.** The concrete, minimal remediation plus one defense-in-depth layer.

## Output format
1. Context summary (one paragraph) plus which specialist agents ran.
2. Findings table, ranked by CVSS environmental severity (finding, CWE, CVSS v4.0, `file:line`).
3. Per-finding detail as above.
4. Runnable exploit file(s), each self-documented.
5. A short defensive section (systemic fixes plus detection ideas).
