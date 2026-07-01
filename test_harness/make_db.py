#!/usr/bin/env python3
"""Build a realistic 'multi-application' challenge.db with a hidden CW{...} flag.

The challenge states the injectable app is "connected to the db of multiple
applications" and that "we don't know exactly where the flag is". So we create
several tables belonging to different notional apps and bury the flag in a
non-obvious text column, forcing the exploit to enumerate the FULL schema and
scan every column rather than target a known location.
"""
import sqlite3, os, hashlib, random, string

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "challenge.db")
if os.path.exists(DB):
    os.remove(DB)

random.seed(1337)
conn = sqlite3.connect(DB)
c = conn.cursor()

# --- App A: identity (this is the table the vulnerable endpoint reads) --------
c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password_hash TEXT)")
for i, (u, e) in enumerate([("alice", "alice@corp.io"), ("bob", "bob@corp.io"),
                            ("carol", "carol@corp.io"), ("dave", "dave@corp.io")], 1):
    c.execute("INSERT INTO users VALUES (?,?,?,?)", (i, u, e, hashlib.sha256(u.encode()).hexdigest()))

# --- App B: auth sessions -----------------------------------------------------
c.execute("CREATE TABLE auth_sessions (id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT, expires_at TEXT)")
for i in range(1, 6):
    c.execute("INSERT INTO auth_sessions VALUES (?,?,?,?)",
              (i, random.randint(1, 4), ''.join(random.choices(string.hexdigits.lower(), k=40)), "2026-01-01T00:00:00Z"))

# --- App C: billing -----------------------------------------------------------
c.execute("CREATE TABLE billing_invoices (id INTEGER PRIMARY KEY, merchant_id INTEGER, amount_cents INTEGER, currency TEXT, status TEXT)")
for i in range(1, 8):
    c.execute("INSERT INTO billing_invoices VALUES (?,?,?,?,?)",
              (i, random.randint(100, 200), random.randint(500, 900000), "BRL", random.choice(["paid", "open", "void"])))

# --- App D: merchant payouts --------------------------------------------------
c.execute("CREATE TABLE merchant_payouts (id INTEGER PRIMARY KEY, merchant_id INTEGER, bank_account TEXT, amount_cents INTEGER, status TEXT)")
for i in range(1, 6):
    c.execute("INSERT INTO merchant_payouts VALUES (?,?,?,?,?)",
              (i, random.randint(100, 200), f"BR{random.randint(10**11, 10**12)}", random.randint(1000, 5000000), "settled"))

# --- App E: internal secrets vault  <<< FLAG HIDDEN HERE >>> ------------------
c.execute("CREATE TABLE internal_vault (id INTEGER PRIMARY KEY, name TEXT, secret_value TEXT, created_at TEXT)")
vault = [
    ("smtp_password", "S3nd!ngM41l#2026", "2025-11-02"),
    ("jwt_signing_key", ''.join(random.choices(string.ascii_letters + string.digits, k=48)), "2025-12-15"),
    ("backup_notes", "CW{un10n_gr0up_c0nc4t_sql1_pwn3d_in_und3r_15s}", "2026-02-20"),  # <-- the flag
    ("stripe_restricted", "rk_live_" + ''.join(random.choices(string.ascii_letters + string.digits, k=24)), "2026-03-01"),
]
for i, (n, v, ts) in enumerate(vault, 1):
    c.execute("INSERT INTO internal_vault VALUES (?,?,?,?)", (i, n, v, ts))

# --- App F: key/value config --------------------------------------------------
c.execute("CREATE TABLE app_config (key TEXT PRIMARY KEY, value TEXT)")
for k, v in [("maintenance", "false"), ("max_payout", "5000000"), ("region", "sa-east-1"), ("feature.pix", "true")]:
    c.execute("INSERT INTO app_config VALUES (?,?)", (k, v))

# --- App G: audit log ---------------------------------------------------------
c.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, actor TEXT, action TEXT, detail TEXT, ts TEXT)")
for i in range(1, 10):
    c.execute("INSERT INTO audit_log VALUES (?,?,?,?,?)",
              (i, random.choice(["alice", "bob", "system"]), random.choice(["login", "payout.approve", "key.rotate"]), "ok", "2026-06-30T12:00:00Z"))

conn.commit()
conn.close()
print("built", DB, "with tables: users, auth_sessions, billing_invoices, merchant_payouts, internal_vault, app_config, audit_log")
print("flag hidden in internal_vault.secret_value (row name='backup_notes')")
