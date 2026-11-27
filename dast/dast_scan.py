"""Lightweight DAST: starts the target app and probes it over real HTTP with safe payloads.

Usage: python dast/dast_scan.py app_vulnerable 5001 reports/dast_vulnerable.json
Only ever point this at your own local test apps.
"""
import base64, json, pickle, subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

REQUIRED_HEADERS = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]


class Target:
    def __init__(self, port):
        self.base = f"http://127.0.0.1:{port}"
        self.cookie = None

    def req(self, path, data=None, headers=None):
        h = dict(headers or {})
        if self.cookie:
            h["Cookie"] = "; ".join(c for c in (h.get("Cookie"), self.cookie) if c)
        body = urllib.parse.urlencode(data).encode() if data else None
        r = urllib.request.Request(self.base + path, data=body, headers=h)
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, resp.headers, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode(errors="replace")

    def login(self, user, pw):
        status, headers, body = self.req("/login", {"username": user, "password": pw})
        sc = headers.get("Set-Cookie")
        if sc:
            self.cookie = sc.split(";")[0]
        return status, headers, body


def finding(fid, title, owasp, cwe, severity, endpoint, evidence):
    return dict(id=fid, tool="dast", title=title, owasp=owasp, cwe=cwe, severity=severity,
                location=endpoint, evidence=evidence[:160], confirmed=True)


def scan(port):
    t, out = Target(port), []

    s, h, _ = t.req("/search?q=hello")
    missing = [x for x in REQUIRED_HEADERS if x not in h]
    if missing:
        out.append(finding("DAST-HDR", "Missing security headers", "A05 Security Misconfiguration", "CWE-693",
                           "Medium", "all responses", "missing: " + ", ".join(missing)))

    s, h, b = t.login("admin' --", "anything")
    if s == 200 and "admin" in b:
        out.append(finding("DAST-SQLI", "SQL injection: login bypass", "A03 Injection", "CWE-89", "Critical",
                           "POST /login", "username=admin' -- returned: " + b))

    s, h, b = t.req("/search?q=" + urllib.parse.quote("{{7*7}}"))
    if "49" in b:
        out.append(finding("DAST-SSTI", "Server-side template injection", "A03 Injection", "CWE-1336", "Critical",
                           "GET /search", "q={{7*7}} rendered as 49"))
    s, h, b = t.req("/search?q=" + urllib.parse.quote("<script>alert(1)</script>"))
    if "<script>alert(1)</script>" in b:
        out.append(finding("DAST-XSS", "Reflected cross-site scripting", "A03 Injection", "CWE-79", "High",
                           "GET /search", "payload reflected without encoding"))

    t.cookie = None
    t.login("alice", "alice123")
    s, h, b = t.req("/account/2")          # account 2 belongs to bob
    if s == 200 and "Bob" in b:
        out.append(finding("DAST-IDOR", "Broken object-level authorization (IDOR)", "A01 Broken Access Control",
                           "CWE-639", "High", "GET /account/{id}", "alice read bob's account: " + b))
    t.cookie = None
    s, h, b = t.login("alice", "alice123")
    sc = h.get("Set-Cookie", "")
    if sc and "httponly" not in sc.lower():
        out.append(finding("DAST-COOKIE", "Session cookie missing HttpOnly/Secure/SameSite", "A05 Security Misconfiguration",
                           "CWE-1004", "Low", "POST /login", sc))

    s, h, b = t.req("/ping?host=" + urllib.parse.quote("127.0.0.1; echo DAST_MARKER_$((6*7))"))
    if "DAST_MARKER_42" in b:
        out.append(finding("DAST-CMDI", "OS command injection", "A03 Injection", "CWE-78", "Critical",
                           "GET /ping", "shell evaluated injected command (DAST_MARKER_42)"))

    s, h, b = t.req("/preview?url=" + urllib.parse.quote(f"http://127.0.0.1:{port}/internal/health"))
    if "INTERNAL-ONLY" in b:
        out.append(finding("DAST-SSRF", "Server-side request forgery to internal endpoint", "A10 SSRF", "CWE-918",
                           "High", "GET /preview", "fetched /internal/health: " + b))

    harmless = base64.b64encode(pickle.dumps({"theme": "DAST_PICKLE_MARKER"})).decode()
    s, h, b = t.req("/prefs", headers={"Cookie": "prefs=" + harmless})
    if "DAST_PICKLE_MARKER" in b:
        out.append(finding("DAST-DESER", "Untrusted pickle data deserialized", "A08 Software and Data Integrity Failures",
                           "CWE-502", "High", "GET /prefs", "server unpickled attacker-supplied cookie"))

    s, h, b = t.req("/prefs", headers={"Cookie": "prefs=not-base64!!"})
    if "Werkzeug Debugger" in b or "Traceback" in b:
        out.append(finding("DAST-DEBUG", "Debug mode exposes stack traces / interactive debugger", "A05 Security Misconfiguration",
                           "CWE-489", "High", "GET /prefs (error)", "stack trace returned to client"))
    return out


def main(app_dir, port, out_path):
    proc = subprocess.Popen([sys.executable, "app.py"], cwd=app_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/search", timeout=1); break
            except Exception:
                time.sleep(0.2)
        results = scan(port)
    finally:
        proc.terminate(); proc.wait()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(results, indent=2))
    print(f"DAST {app_dir}: {len(results)} confirmed findings")
    for f in results:
        print(f"  [{f['severity']:<8}] {f['title']}  ({f['location']})")
    return results


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]), sys.argv[3])
