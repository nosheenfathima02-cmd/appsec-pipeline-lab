# Secure Coding Quick Guide for Developers

A one-page training handout built from the real findings in this lab. Each item shows the vulnerable pattern, the fix, and the tool that catches it.

| # | Vulnerability (OWASP 2021) | Vulnerable pattern | Secure fix | Caught by |
|---|---|---|---|---|
| 1 | SQL injection (A03, CWE-89) | `f"... WHERE username = '{u}'"` | Parameterized query: `execute("... WHERE username = ?", (u,))` | Bandit B608, Semgrep, DAST |
| 2 | Cross-site scripting / template injection (A03, CWE-79/1336) | `render_template_string("<h1>" + q + "</h1>")` | Never render user input as a template; encode output with `escape()` | Semgrep, DAST |
| 3 | OS command injection (A03, CWE-78) | `subprocess.run(f"... {host}", shell=True)` | No shell; validate against an allow-list | Bandit B602, Semgrep, DAST |
| 4 | Broken access control / IDOR (A01, CWE-639) | `SELECT ... WHERE id = ?` | Check ownership: `WHERE id = ? AND owner_id = ?` | **DAST only** (SAST cannot see business logic) |
| 5 | SSRF (A10, CWE-918) | `urlopen(user_url)` | HTTPS only plus a host allow-list | Bandit B310, Semgrep, DAST |
| 6 | Insecure deserialization (A08, CWE-502) | `pickle.loads(cookie)` | JSON plus schema/allow-list validation | Bandit B301/B403, DAST |
| 7 | Weak password hashing (A02, CWE-327) | `hashlib.md5(pw)` | Salted, slow hash (`generate_password_hash`, bcrypt, Argon2) | Bandit B324, Semgrep |
| 8 | Hard-coded secret (A07, CWE-259) | `secret_key = "dev-secret-123"` | Load from a vault or the environment; rotate | Bandit B105 |
| 9 | Debug mode in production (A05, CWE-489) | `app.run(debug=True)` | `debug=False`; generic error pages | Bandit B201, Semgrep, DAST |
| 10 | Missing security headers (A05) | none set | CSP, HSTS, X-Frame-Options, X-Content-Type-Options | DAST |
| 11 | Vulnerable dependencies (A06) | `flask==2.0.1`, `werkzeug==2.0.1`, ... | Upgrade to patched versions; run SCA on every build | pip-audit (SCA) |
| 12 | Container runs as root (A04/A05, CWE-250) | no `USER` in the Dockerfile; `python:latest` | Pinned slim base image, non-root user, no secrets in the image | Semgrep Dockerfile rules, Trivy |

## Three lessons

1. **Use more than one kind of testing.** SAST found 22 code issues, but only DAST proved the IDOR. SAST also raised 6 false positives on safe code that DAST showed were not exploitable.
2. **Prioritize by risk, not by count.** 68 of 99 findings were dependency CVEs that one upgrade of 7 packages fixes. The 14 P1 issues are confirmed-exploitable injection and access-control flaws.
3. **Shift left.** All of these checks run automatically in CI on every push (`.github/workflows/appsec.yml`), so issues are caught before release.
