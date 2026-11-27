"""ClientNotes (REMEDIATED VERSION). Each fix references the flaw it closes."""
import json, os, secrets, sqlite3
from urllib.parse import urlparse
from flask import Flask, request, session, abort
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# A02/A05 fix: secret comes from the environment (a vault in production), random fallback for local runs
app.secret_key = os.environ.get("CLIENTNOTES_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=True)

ALLOWED_PREVIEW_HOSTS = {"example.com"}   # A10 fix: allow-list
ALLOWED_PING = {"127.0.0.1", "localhost"}                   # A03 fix: allow-list, no shell


def db():
    return sqlite3.connect("file:clientnotes_fixed?mode=memory&cache=shared", uri=True)

_keep = db()
_keep.executescript("""
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, pw TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, owner_id INTEGER, nickname TEXT, balance REAL);
DELETE FROM users; DELETE FROM accounts;
""")
for i, (u, p, r) in enumerate([("alice", "alice123", "client"), ("bob", "bob123", "client"), ("admin", "S3cure!", "admin")], 1):
    _keep.execute("INSERT INTO users VALUES (?,?,?,?)", (i, u, generate_password_hash(p), r))  # A02 fix: salted hash
_keep.executemany("INSERT INTO accounts VALUES (?,?,?,?)", [(1, 1, "Alice chequing", 2500.0), (2, 2, "Bob savings", 91000.0)])
_keep.commit()


@app.after_request
def security_headers(resp):  # A05 fix: secure headers
    resp.headers.update({
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    })
    return resp


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    # A03 fix: parameterized query
    row = db().execute("SELECT id, username, pw FROM users WHERE username = ?", (u,)).fetchone()
    if not row or not check_password_hash(row[2], p):
        return "Invalid login", 401
    session.clear(); session["uid"] = row[0]
    return f"Welcome {escape(row[1])}"


@app.route("/search")
def search():
    # A03 fix: output encoding, no template rendering of user input
    return f"<h1>Results for {escape(request.args.get('q', ''))}</h1>"


@app.route("/account/<int:acct_id>")
def account(acct_id):
    if "uid" not in session:
        abort(401)
    # A01 fix: object-level authorization (the account must belong to the signed-in user)
    row = db().execute("SELECT nickname, balance FROM accounts WHERE id = ? AND owner_id = ?",
                       (acct_id, session["uid"])).fetchone()
    return {"nickname": row[0], "balance": row[1]} if row else abort(404)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if host not in ALLOWED_PING:
        abort(400)
    return f"pinging {host}"


@app.route("/preview")
def preview():
    u = urlparse(request.args.get("url", ""))
    if u.scheme != "https" or u.hostname not in ALLOWED_PREVIEW_HOSTS:
        abort(400)
    return f"preview allowed for {escape(u.hostname)}"


@app.route("/prefs")
def prefs():
    # A08 fix: JSON with schema check instead of pickle
    try:
        data = json.loads(request.cookies.get("prefs") or '{"theme": "light"}')
        theme = data.get("theme") if data.get("theme") in ("light", "dark") else "light"
    except (ValueError, AttributeError):
        theme = "light"
    return {"prefs": {"theme": theme}}


@app.route("/internal/health")
def internal():
    if request.remote_addr != "127.0.0.1" or request.headers.get("X-Forwarded-For"):
        abort(403)
    return "ok"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
