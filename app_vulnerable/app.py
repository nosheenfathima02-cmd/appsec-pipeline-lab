"""ClientNotes (VULNERABLE TRAINING VERSION).

!! Intentionally insecure. For local security-testing practice only. Never deploy. !!
Each flaw is labelled with its OWASP Top 10 (2021) category so the scanners' results can be checked.
"""
import hashlib, pickle, base64, sqlite3, subprocess
import urllib.request
from flask import Flask, request, render_template_string, session, abort

app = Flask(__name__)
app.secret_key = "dev-secret-123"            # A02/A05: hard-coded secret

def db():
    con = sqlite3.connect("file:clientnotes?mode=memory&cache=shared", uri=True)
    return con

_keep = db()  # keep the shared in-memory DB alive
_keep.executescript("""
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, pw TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, owner_id INTEGER, nickname TEXT, balance REAL);
DELETE FROM users; DELETE FROM accounts;
""")
for i, (u, p, r) in enumerate([("alice", "alice123", "client"), ("bob", "bob123", "client"), ("admin", "S3cure!", "admin")], 1):
    _keep.execute("INSERT INTO users VALUES (?,?,?,?)", (i, u, hashlib.md5(p.encode()).hexdigest(), r))  # A02: MD5
_keep.executemany("INSERT INTO accounts VALUES (?,?,?,?)", [(1, 1, "Alice chequing", 2500.0), (2, 2, "Bob savings", 91000.0)])
_keep.commit()


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    pw = hashlib.md5(p.encode()).hexdigest()
    # A03: SQL injection (string-built query)
    row = db().execute(f"SELECT id, username FROM users WHERE username = '{u}' AND pw = '{pw}'").fetchone()
    if not row:
        return "Invalid login", 401
    session["uid"] = row[0]
    return f"Welcome {row[1]}"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # A03: reflected cross-site scripting (user input rendered as template/HTML)
    return render_template_string("<h1>Results for " + q + "</h1>")


@app.route("/account/<int:acct_id>")
def account(acct_id):
    if "uid" not in session:
        abort(401)
    # A01: broken access control (IDOR) - no check that the account belongs to the user
    row = db().execute("SELECT nickname, balance FROM accounts WHERE id = ?", (acct_id,)).fetchone()
    return {"nickname": row[0], "balance": row[1]} if row else abort(404)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # A03: OS command injection
    out = subprocess.run(f"echo pinging {host}", shell=True, capture_output=True, text=True)
    return out.stdout


@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    # A10: server-side request forgery (fetches any URL, including internal services)
    return urllib.request.urlopen(url, timeout=3).read()[:200]


@app.route("/prefs")
def prefs():
    raw = request.cookies.get("prefs")
    # A08: insecure deserialization of untrusted data
    data = pickle.loads(base64.b64decode(raw)) if raw else {"theme": "light"}
    return {"prefs": str(data)}


@app.route("/internal/health")
def internal():
    return "INTERNAL-ONLY: db=ok"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)  # A05: debug mode on
