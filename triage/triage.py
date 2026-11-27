"""Risk-based vulnerability triage: normalize SAST, SCA and DAST results into one prioritized list.

Usage: python triage/triage.py vulnerable   (reads reports/*_vulnerable.json)
Exit code 1 if any P1 issue is open, so CI can block the release.
"""
import json, re, sys
from pathlib import Path

R = Path(__file__).resolve().parent.parent / "reports"
SEV_SCORE = {"Critical": 10, "High": 7.5, "Medium": 5, "Low": 2.5}
# Scanner CWEs that are imprecise in context: B310 is urlopen of user input (SSRF); tainted-sql-string is SQL injection
RULE_CWE_ALIAS = {"B310": "918", "tainted-sql-string": "89"}
DIRECT_DEPS = {"flask", "werkzeug", "jinja2"}   # imported by the app, so vulnerabilities are reachable

CWE_OWASP = {
    "89": "A03 Injection", "78": "A03 Injection", "79": "A03 Injection", "1336": "A03 Injection", "94": "A03 Injection",
    "639": "A01 Broken Access Control", "22": "A01 Broken Access Control",
    "327": "A02 Cryptographic Failures", "328": "A02 Cryptographic Failures", "798": "A07 Identification and Authentication Failures",
    "259": "A07 Identification and Authentication Failures",
    "502": "A08 Software and Data Integrity Failures", "918": "A10 SSRF",
    "489": "A05 Security Misconfiguration", "94/489": "A05 Security Misconfiguration", "693": "A05 Security Misconfiguration",
    "250": "A05 Security Misconfiguration", "1104": "A06 Vulnerable and Outdated Components",
}


def cwe_num(text):
    nums = re.findall(r"CWE-(\d+)", str(text))
    return next((n for n in nums if n in CWE_OWASP), nums[0] if nums else "")


def load(name):
    p = R / name
    return json.loads(p.read_text()) if p.exists() else None


def normalize(variant, suppressions):
    items = []
    for r in (load(f"bandit_{variant}.json") or {}).get("results", []):
        sev = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}[r["issue_severity"]]
        c = str(r.get("issue_cwe", {}).get("id", ""))
        items.append(dict(tool="bandit (SAST)", rule=r["test_id"], title=r["issue_text"], severity=sev, cwe=c,
                          file=r["filename"], line=r["line_number"], location=f"{Path(r['filename']).name}:{r['line_number']}"))
    for r in (load(f"semgrep_{variant}.json") or {}).get("results", []):
        sev = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}.get(r["extra"].get("severity"), "Medium")
        meta = r["extra"].get("metadata", {})
        c = cwe_num(meta.get("cwe"))
        ow = [o for o in (meta.get("owasp") if isinstance(meta.get("owasp"), list) else [meta.get("owasp", "")]) if ":2021" in o]
        hint = ow[0].replace(":2021 -", "") if ow else None
        items.append(dict(tool="semgrep (SAST)", owasp_hint=hint, rule=r["check_id"].split(".")[-1], title=r["extra"]["message"].split(".")[0],
                          severity=sev, cwe=c, file=r["path"], line=r["start"]["line"], location=f"{Path(r['path']).name}:{r['start']['line']}"))
    for d in (load(f"sca_{variant}.json") or {}).get("dependencies", []):
        for v in d.get("vulns", []):
            reachable = d["name"].lower() in DIRECT_DEPS
            items.append(dict(tool="pip-audit (SCA)", rule=v["id"], title=f"{d['name']} {d['version']} vulnerable, fixed in {', '.join(v.get('fix_versions', [])) or 'n/a'}",
                              severity="High" if reachable else "Medium", cwe="1104", file="requirements.txt", line=0,
                              location=f"{d['name']}=={d['version']}", package=d["name"], fix=bool(v.get("fix_versions"))))
    for f in load(f"dast_{variant}.json") or []:
        items.append(dict(tool="dast", rule=f["id"], title=f["title"], severity=f["severity"], cwe=cwe_num(f["cwe"]),
                          file="", line=0, location=f["location"], evidence=f["evidence"]))

    for i in items:
        i["cwe"] = RULE_CWE_ALIAS.get(i["rule"], i["cwe"])
        if i["rule"] in RULE_CWE_ALIAS:
            i.pop("owasp_hint", None)
    dast_cwes = {i["cwe"] for i in items if i["tool"] == "dast"}
    for i in items:
        i["owasp"] = (i.pop("owasp_hint", None) or CWE_OWASP.get(i["cwe"], "Other")).replace(
            "Server-Side Request Forgery (SSRF)", "SSRF").strip()
        sup = next((s for s in suppressions if s["tool"] in i["tool"] and i["file"].endswith(s["file"].split("/")[-1])
                    and s["line"] == i["line"] and variant in s["file"]), None)
        i["status"] = sup["status"] if sup else "open"
        i["reason"] = sup["reason"] if sup else ""
        # Risk = severity, +2.5 when exploitation is confirmed at runtime by DAST
        confirmed = i["tool"] == "dast" or i["cwe"] in dast_cwes
        i["confirmed_by_dast"] = confirmed
        i["risk"] = SEV_SCORE[i["severity"]] + (2.5 if confirmed else 0)
        i["priority"] = "P1 (fix in 7 days)" if i["risk"] >= 10 else "P2 (fix in 30 days)" if i["risk"] >= 7.5 else "P3 (fix in 90 days)"
    return items


def summarize(items):
    open_ = [i for i in items if i["status"] == "open"]
    # one SCA issue per package (upgrade fixes all of its CVEs together)
    pkgs = {i["package"] for i in open_ if i.get("package")}
    by_p = {}
    for i in open_:
        by_p[i["priority"][:2]] = by_p.get(i["priority"][:2], 0) + 1
    by_owasp = {}
    for i in open_:
        by_owasp[i["owasp"]] = by_owasp.get(i["owasp"], 0) + 1
    code_weaknesses = {i["cwe"] for i in open_ if not i.get("package")}
    return dict(raw_findings=len(items), open=len(open_), unique_issues=len(code_weaknesses) + len(pkgs), false_positives=len(items) - len(open_),
                vulnerable_packages=len(pkgs), by_priority=by_p, by_owasp=dict(sorted(by_owasp.items())),
                by_tool={t: sum(1 for i in items if i["tool"] == t) for t in sorted({i["tool"] for i in items})})


def main(variant):
    sup = json.loads((R.parent / "triage" / "suppressions.json").read_text())
    items = sorted(normalize(variant, sup), key=lambda i: (-i["risk"], i["tool"]))
    s = summarize(items)
    (R / f"triage_{variant}.json").write_text(json.dumps({"summary": s, "findings": items}, indent=2))
    print(f"[{variant}] raw={s['raw_findings']} unique={s['unique_issues']} open={s['open']} false_positives={s['false_positives']} "
          f"priority={s['by_priority']} tools={s['by_tool']}")
    return 1 if s["by_priority"].get("P1") else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "vulnerable"))
