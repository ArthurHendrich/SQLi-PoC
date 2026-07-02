# SQLi-PoC

A self-contained, **sqlmap-free** SQL-injection exploit that pulls a `CW{...}` flag from a SQLite-backed API in **under 15 seconds, in a single run**. It ships with a reproducible Docker target, a local test harness, and a reusable vulnerability-audit skill.

> **Authorized and educational use only.** Everything here runs against the bundled local target. Do not point the exploit at systems you are not authorized to test.

---

## Test it from GitHub

Prerequisites: `git`, plus either **Docker** or **Python 3** (Flask and requests).

```bash
git clone https://github.com/ArthurHendrich/SQLi-PoC.git
cd SQLi-PoC
```

### Option A, with Docker (recommended)

```bash
docker compose up -d --build          # serves the vulnerable app on :4001 with a fresh, flag-planted DB
pip install requests                  # the exploit's only dependency

python3 sqli_exploit.py http://127.0.0.1:4001          # in-band path
python3 sqli_exploit.py http://127.0.0.1:4001 --blind  # boolean-blind fallback

docker compose down                   # stop and remove
```

Quick sanity check while it's up:

```bash
curl "http://127.0.0.1:4001/api/user?username=alice"    # {"email":"alice@corp.io","username":"alice"}
curl "http://127.0.0.1:4001/api/user?username=nobody"   # 404
```

### Option B, without Docker

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install flask requests
cd test_harness
python3 make_db.py                                      # builds challenge.db with a planted flag
CHALLENGE_DB="$PWD/challenge.db" python3 vuln_app.py     # serves on :4001, leave it running
# in a second terminal, from the repo root:
python3 sqli_exploit.py http://127.0.0.1:4001
python3 sqli_exploit.py http://127.0.0.1:4001 --blind
```

### What to expect

Both modes print `[+] FLAG: CW{...}` with a time and request count, well under the 15-second budget.

| Mode | Time | Requests |
|---|---|---|
| Primary, `UNION` + `group_concat` | ~0.03 s | 8 |
| Boolean-blind fallback (`--blind`) | ~3 s | ~5,388 |

The bundled flag is the one planted by `make_db.py` (`CW{un10n_gr0up_c0nc4t_sql1_pwn3d_in_und3r_15s}`), since the real challenge database is not public. Nothing is hardcoded: the script enumerates the schema at runtime, so if you move the flag to another table or column it still finds it.

### Trying the skill

`SKILL.md` is an Agent Skill (Markdown), not a runnable script. Load it into an AI coding agent (Claude Code, Codex or similar), point the agent at `test_harness/vuln_app.py`, and ask it to find vulnerabilities and build an exploit. The trigger phrases live in the `description` at the top of the file.

---

## The vulnerability

The target builds SQL by string interpolation (`/api/user`):

```python
query = f"SELECT username, email FROM users WHERE username = '{username}'"
cursor.execute(query)
```

`username` lands in string context with no escaping, so it's textbook **string-context SQL injection (CWE-89)** on SQLite. The response reflects the selected columns and the app returns raw exceptions to the client, so extraction can be fully in-band. The sibling `/api/profile` is parameterized and safe, and it models the fix.

## How it works

**Primary (in-band).** Because the endpoint reflects `username` and `email`, a two-column `UNION SELECT` returns arbitrary computed values in the JSON. One request enumerates every `(table, column)` via `sqlite_master` joined with `pragma_table_info()`, `group_concat()` collapses whole-table scans into single responses, batched column probes (`… LIKE '%CW{%'`) run concurrently, and a client-side regex `CW\{[^}]*\}` pulls the flag, including from table and column names and the `CREATE` SQL.

**Fallback (boolean-blind).** If the reflected output ever goes away, the script switches to a `200`-vs-`404` truth oracle, reconstructs the schema, locates the flag column with `LIKE`, and recovers the string with a per-character binary search (positions fetched concurrently).

## Layout

```
sqli_exploit.py          # the exploit (in-band primary + blind fallback)
test_harness/
  vuln_app.py            # the vulnerable Flask app (DB path via env; logic unchanged)
  make_db.py             # builds a 7-table DB and hides the flag in a non-obvious column
Dockerfile               # bakes a fresh flag-planted DB + serves the app
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
- give the app a least-privilege database account (avoid one account reaching every app's tables);
- alert on SQL errors, unusual quote or comment patterns and high-rate enumeration.

## `SKILL.md`

A reusable, discovery-driven workflow that audits a codebase for any class of vulnerability (injection, broken authorization, SSRF, deserialization, exposed debug servers, secrets and more) and develops a working PoC exploit for each confirmed finding against a **local replica**. It runs the same understand, map, spike, confirm, score, weaponize and remediate loop this exploit demonstrates.

## License

[MIT](./LICENSE) © 2026 Arthur Hendrich
