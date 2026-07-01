"""TEST HARNESS copy of the challenge's vulnerable app.

Logic is byte-for-byte the provided challenge; the ONLY change is that the
sqlite file path is read from the CHALLENGE_DB env var (default 'challenge.db')
so the test harness can point it at an absolute path without a chdir. The
injectable query and response behaviour are identical to the original.
"""
from flask import Flask, request, jsonify, send_file
import sqlite3
import os

app = Flask(__name__)

DB_PATH = os.environ.get("CHALLENGE_DB", "challenge.db")  # only harness change


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route('/api/user', methods=['GET'])
def get_user():
    username = request.args.get('username', '')

    conn = get_db()
    cursor = conn.cursor()

    query = f"SELECT username, email FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        if result:
            return jsonify({"username": result[0], "email": result[1]})
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@app.route('/api/profile', methods=['GET'])
def get_profile():
    user_id = request.args.get('id')
    if not user_id:
        return jsonify({"error": "Missing id parameter"}), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({"username": result[0], "email": result[1]})
    return jsonify({"error": "Profile not found"}), 404


if __name__ == '__main__':
    app.run(debug=True, port=4001, host='0.0.0.0')
