"""Security regression tests: every flaw is exploitable in the vulnerable app and blocked in the fixed app."""
import base64, importlib.util, json, pickle, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "triage"))
import triage  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / name / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    return mod.app.test_client()


class Remediation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln, cls.fixed = load("app_vulnerable"), load("app_fixed")

    def test_sql_injection(self):
        payload = {"username": "admin' --", "password": "x"}
        self.assertEqual(self.vuln.post("/login", data=payload).status_code, 200)
        self.assertEqual(self.fixed.post("/login", data=payload).status_code, 401)

    def test_xss_and_template_injection(self):
        self.assertIn(b"<script>", self.vuln.get("/search?q=<script>x</script>").data)
        self.assertNotIn(b"<script>", self.fixed.get("/search?q=<script>x</script>").data)
        self.assertIn(b"49", self.vuln.get("/search?q={{7*7}}").data)
        self.assertNotIn(b"49", self.fixed.get("/search?q={{7*7}}").data)

    def test_idor(self):
        for client, expected in ((self.vuln, 200), (self.fixed, 404)):
            with client.session_transaction() as s:
                s["uid"] = 1  # alice
            self.assertEqual(client.get("/account/2").status_code, expected)  # bob's account

    def test_command_injection(self):
        self.assertIn(b"PWNED", self.vuln.get("/ping?host=x;echo PWNED").data)
        self.assertEqual(self.fixed.get("/ping?host=x;echo PWNED").status_code, 400)

    def test_ssrf_blocked(self):
        self.assertEqual(self.fixed.get("/preview?url=http://127.0.0.1/internal/health").status_code, 400)

    def test_deserialization(self):
        cookie = base64.b64encode(pickle.dumps({"theme": "MARK"})).decode()
        self.vuln.set_cookie("prefs", cookie)
        self.assertIn(b"MARK", self.vuln.get("/prefs").data)
        self.fixed.set_cookie("prefs", cookie)
        self.assertEqual(self.fixed.get("/prefs").json, {"prefs": {"theme": "light"}})

    def test_security_headers(self):
        h = self.fixed.get("/search").headers
        for name in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"):
            self.assertIn(name, h)


class Triage(unittest.TestCase):
    def test_dast_confirmation_raises_priority(self):
        dast = [dict(id="D1", title="SQLi", severity="Critical", cwe="CWE-89", location="/login", evidence="e")]
        bandit = {"results": [
            dict(test_id="B608", issue_text="sql", issue_severity="MEDIUM", issue_cwe={"id": 89}, filename="app.py", line_number=3),
            dict(test_id="B324", issue_text="md5", issue_severity="MEDIUM", issue_cwe={"id": 327}, filename="app.py", line_number=4)]}
        fake = {"bandit_t.json": bandit, "dast_t.json": dast}
        orig, triage.load = triage.load, lambda name: fake.get(name)
        try:
            items = {i["rule"]: i for i in triage.normalize("t", [])}
        finally:
            triage.load = orig
        self.assertTrue(items["D1"]["priority"].startswith("P1"))
        self.assertTrue(items["B608"]["confirmed_by_dast"])           # same CWE confirmed at runtime
        self.assertTrue(items["B608"]["priority"].startswith("P2"))   # Medium 5 + 2.5
        self.assertFalse(items["B324"]["confirmed_by_dast"])
        self.assertTrue(items["B324"]["priority"].startswith("P3"))
        self.assertEqual(items["B324"]["owasp"], "A02 Cryptographic Failures")

    def test_report_numbers_are_consistent(self):
        p = ROOT / "reports" / "triage_vulnerable.json"
        if not p.exists():
            self.skipTest("run ./run_all.sh first")
        d = json.loads(p.read_text())
        s = d["summary"]
        self.assertEqual(s["raw_findings"], len(d["findings"]))
        self.assertEqual(sum(s["by_priority"].values()), s["open"])
        f = json.loads((ROOT / "reports" / "triage_fixed.json").read_text())["summary"]
        self.assertEqual(f["open"], 0)


if __name__ == "__main__":
    unittest.main()
