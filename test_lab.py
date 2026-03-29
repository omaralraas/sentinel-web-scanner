"""
Sentinel Test Lab — Intentionally Vulnerable Flask Application
===============================================================
A minimal web server designed to be scanned by the Sentinel Web
Scanner.  It contains **two deliberate vulnerabilities**:

1. **Missing Security Headers** — No HSTS, CSP, or X-Frame-Options
   are set, so the header_analyzer module should flag them.

2. **IDOR on /api/v1/users/<id>** — Returns different user records
   for integer IDs without any authentication, so the api_fuzzer
   module should detect this as an Insecure Direct Object Reference.

Usage:
    pip install flask
    python test_lab.py
    # → Runs on http://127.0.0.1:5000
"""

from __future__ import annotations

from flask import Flask, jsonify, Response

app = Flask(__name__)

# ── Fake user database (simulates an unprotected data store) ────────────────
USERS_DB: dict[int, dict[str, str | int]] = {
    1: {"id": 1, "username": "admin",     "email": "admin@sentinel.local",    "role": "administrator"},
    2: {"id": 2, "username": "jdoe",      "email": "jdoe@sentinel.local",     "role": "user"},
    3: {"id": 3, "username": "alice",     "email": "alice@sentinel.local",    "role": "user"},
    4: {"id": 4, "username": "bob",       "email": "bob@sentinel.local",      "role": "moderator"},
    5: {"id": 5, "username": "charlie",   "email": "charlie@sentinel.local",  "role": "user"},
}


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index() -> str:
    """Landing page — intentionally serves NO security headers."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Sentinel Test Lab</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex; align-items: center; justify-content: center;
            height: 100vh; margin: 0;
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            color: #e0e0e0;
        }
        .card {
            text-align: center; padding: 3rem 4rem;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            backdrop-filter: blur(12px);
        }
        h1 { margin-bottom: 0.25rem; color: #ff6b6b; }
        code { color: #feca57; }
    </style>
</head>
<body>
    <div class="card">
        <h1>⚠ Sentinel Test Lab</h1>
        <p>This server is <strong>intentionally vulnerable</strong>.</p>
        <p>Try: <code>GET /api/v1/users/1</code></p>
    </div>
</body>
</html>"""
    # ⚠ Deliberate: We do NOT set any security headers on this response.
    return html


@app.route("/api/v1/users")
def list_users() -> Response:
    """Return a list of all usernames (no auth required)."""
    users = [{"id": uid, "username": u["username"]} for uid, u in USERS_DB.items()]
    return jsonify(users)


@app.route("/api/v1/users/<int:user_id>")
def get_user(user_id: int) -> tuple[Response, int]:
    """Return full user details by ID — **no authentication**.

    This is an intentional IDOR vulnerability: any integer ID
    returns that user's record, including email and role.
    """
    user = USERS_DB.get(user_id)
    if user is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user), 200


@app.route("/api/health")
def health() -> Response:
    """Simple health-check endpoint."""
    return jsonify({"status": "ok", "service": "test-lab"})


# ── Entry-point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  [TEST LAB] Sentinel Test Lab running on http://127.0.0.1:5000")
    print("  [WARNING]  This server is INTENTIONALLY VULNERABLE — do not expose to the internet.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
