# Reproducible target for the CloudWalk SQLi challenge (task 3).
#
# Builds the *unmodified* vulnerable Flask app plus a fresh, multi-table
# challenge.db with a planted CW{...} flag, so the exploit and the SKILL.md
# can be tested end-to-end against a realistic, disposable target.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The vulnerable app + DB builder come straight from the test harness.
# (vuln_app.py's SQL is byte-for-byte the challenge; only the DB *path* is an
#  env var so we don't need a chdir.)
COPY test_harness/make_db.py test_harness/vuln_app.py ./

# Bake a fresh challenge.db into the image at build time. The flag is planted
# in a non-obvious column so the exploit must enumerate the whole schema.
RUN python make_db.py

ENV CHALLENGE_DB=/app/challenge.db
EXPOSE 4001

# Faithful to the challenge: Flask dev server, debug=True, listening on 0.0.0.0:4001.
CMD ["python", "vuln_app.py"]
