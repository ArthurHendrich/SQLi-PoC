# SQLi-PoC — `CW{...}` flag extractor

A self-contained, **sqlmap-free** SQL-injection exploit that extracts a `CW{...}` flag from a SQLite-backed API in **under 15 seconds, in a single run** — with a reproducible Docker target and a reusable vulnerability-audit skill.

> **Authorized / educational use only.** Everything here runs against the bundled local target. Do not point the exploit at systems you are not authorized to test.

---

## The vulnerability

The target builds SQL by string interpolation (`/api/user`):

```python
query = f"SELECT username, email FROM users WHERE username = '{username}'"
cursor.execute(query)
```

`username` lands in string context with no escaping — textbook **string-context SQL injection (CWE-89)** on SQLite. The response reflects the selected columns and the app returns raw exceptions to the client, so extraction can be fully in-band. The sibling `/api/profile` is parameterized and safe — it models the fix.

## Quick start (Docker)

```bash
docker compose up -d --build                       # serve the vulnerable app on :4001
python3 sqli_exploit.py http://127.0.0.1:4001      # primary in-band path
python3 sqli_exploit.py http://127.0.0.1:4001 --blind   # force the boolean-blind fallback
docker compose down                                 # tear down
```

Measured against the bundled target:

| Mode | Result | Time | Requests |
|---|---|---|---|
| Primary — `UNION` + `group_concat` | flag extracted | ~0.03 s | 8 |
| Boolean-blind fallback (`--blind`) | flag extracted | ~3 s | ~5,388 |

Both are well under the 15 s budget, run once, and do not hardcode the flag's location.

## How it works

**Primary (in-band).** Because the endpoint reflects `username`/`email`, a two-column `UNION SELECT` returns arbitrary computed values in the JSON. One request enumerates every `(table, column)` via `sqlite_master` joined with `pragma_table_info()`; `group_concat()` collapses whole-table scans into single responses; batched column probes (`… LIKE '%CW{%'`) run concurrently; a client-side regex `CW\{[^}]*\}` pulls the flag — including from table/column names and `CREATE` SQL.

**Fallback (boolean-blind).** If reflection is ever unavailable, the script switches to a `200`-vs-`404` truth oracle, reconstructs the schema, locates the flag column with `LIKE`, and recovers the string with a per-character binary search (positions fetched concurrently).

## Without Docker

```bash
cd test_harness
python3 make_db.py                                  # build challenge.db with a planted flag
CHALLENGE_DB="$PWD/challenge.db" python3 vuln_app.py # run the vulnerable app on :4001
# in another shell, from the repo root:
python3 sqli_exploit.py http://127.0.0.1:4001
```

## Layout

```
sqli_exploit.py          # the exploit (in-band primary + blind fallback)
test_harness/
  vuln_app.py            # the vulnerable Flask app (DB path via env; logic unchanged)
  make_db.py             # builds a 7-table DB and hides the flag in a non-obvious column
Dockerfile               # bakes a fresh flagged DB + serves the app
docker-compose.yml       # docker compose up -d --build
requirements.txt
SKILL.md                 # reusable: audit code for vulns + develop PoC exploits
```

## Remediation

Use bound parameters (as `/api/profile` already does), and harden:

```python
cursor.execute("SELECT username, email FROM users WHERE username = ?", (username,))
```

- don't return raw database exception messages to clients;
- run Flask with `debug=False` behind a production WSGI server;
- least-privilege database account (avoid one account reaching every app's tables);
- alert on SQL errors, unusual quote/comment patterns and high-rate enumeration.

## `SKILL.md`

A reusable workflow that audits a codebase for vulnerabilities (SQLi, command/template injection, auth, SSRF, deserialization, debug/RCE, secrets, …) and develops a working PoC exploit for each confirmed finding against a **local replica** — the analyze → weaponize → prove → remediate loop this exploit demonstrates.

## License

[MIT](./LICENSE) © 2026 Arthur Hendrich
