"""Build reports/appsec_report.html: before (vulnerable) vs after (remediated)."""
import html, json
from pathlib import Path

R = Path(__file__).resolve().parent.parent / "reports"
OWASP_ORDER = ["A01 Broken Access Control", "A02 Cryptographic Failures", "A03 Injection", "A04 Insecure Design",
               "A05 Security Misconfiguration", "A06 Vulnerable and Outdated Components",
               "A07 Identification and Authentication Failures", "A08 Software and Data Integrity Failures",
               "A09 Security Logging and Monitoring Failures", "A10 SSRF"]


def e(x):
    return html.escape(str(x))


def main():
    v = json.loads((R / "triage_vulnerable.json").read_text())
    f = json.loads((R / "triage_fixed.json").read_text())
    sv, sf = v["summary"], f["summary"]

    tiles = "".join(f"<div class='tile'><b>{n}</b><span>{e(l)}</span></div>" for n, l in [
        (sv["raw_findings"], "raw findings from 4 tools"), (sv["unique_issues"], "unique issues after de-duplication"),
        (sv["by_priority"].get("P1", 0), "P1 findings (fix in 7 days)"),
        (sum(1 for i in v["findings"] if i["confirmed_by_dast"] and i["tool"] != "dast"), "SAST findings confirmed by DAST"),
        (sf["open"], "open after remediation"), (sf["false_positives"], "false positives documented")])

    mx = max(sv["by_owasp"].values())
    bars = ""
    for cat in OWASP_ORDER:
        n = sv["by_owasp"].get(cat, 0)
        bars += (f"<div class='row'><span class='cat'>{e(cat)}</span><span class='track'>"
                 f"<span class='fill' style='width:{100*n/mx if n else 0:.1f}%'></span></span><span class='n'>{n}</span>"
                 f"<span class='n after'>{sf['by_owasp'].get(cat, 0)}</span></div>")

    seen, rows = set(), ""
    for i in v["findings"]:
        key = (i["cwe"], i["tool"]) if not i.get("package") else (i["package"],)
        if key in seen or i["status"] != "open":
            continue
        seen.add(key)
        if len(seen) > 22:
            break
        pr = i["priority"][:2]
        rows += (f"<tr><td><span class='p {pr}'>{pr}</span></td><td>{e(i['title'])}</td><td>{e(i['tool'])}</td>"
                 f"<td>{e(i['owasp'])}</td><td>CWE-{e(i['cwe'])}</td><td class='mono'>{e(i['location'])}</td>"
                 f"<td>{'yes' if i['confirmed_by_dast'] else ''}</td></tr>")

    fps = "".join(f"<tr><td class='mono'>{e(i['location'])}</td><td>{e(i['rule'])}</td><td>{e(i['reason'])}</td></tr>"
                  for i in f["findings"] if i["status"] == "false_positive")

    page = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>AppSec Pipeline Report</title><style>
body{{margin:0;font:14px/1.45 system-ui,Segoe UI,Arial,sans-serif;background:#f5f6f8;color:#1c2330}}
header{{background:#7a0c25;color:#fff;padding:20px 28px}} header h1{{margin:0;font-size:21px}} header p{{margin:4px 0 0;opacity:.85}}
main{{max-width:1150px;margin:auto;padding:18px}} section{{background:#fff;border:1px solid #dfe3e8;border-radius:10px;padding:16px 20px;margin:14px 0}}
h2{{font-size:16px;margin:2px 0 12px}} .tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}}
.tile{{background:#fff;border:1px solid #dfe3e8;border-radius:10px;padding:14px}} .tile b{{display:block;font-size:30px;color:#7a0c25}} .tile span{{color:#5d6878;font-size:13px}}
.row{{display:grid;grid-template-columns:290px 1fr 40px 40px;align-items:center;gap:10px;margin:5px 0}} .cat{{font-size:13px}}
.track{{background:#eef0f3;border-radius:4px;height:16px;overflow:hidden}} .fill{{display:block;height:100%;background:#b4233f}}
.n{{text-align:right;font-weight:600}} .after{{color:#15803d}} .legend{{color:#5d6878;font-size:12px;text-align:right}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #e6e9ed;vertical-align:top}}
td:nth-child(5){{white-space:nowrap}} .mono{{font-family:ui-monospace,monospace;font-size:12px}} .p{{border-radius:4px;padding:1px 6px;font-weight:700;color:#fff}} .P1{{background:#b91c1c}} .P2{{background:#c2410c}} .P3{{background:#64748b}}
@media(max-width:700px){{.row{{grid-template-columns:1fr 50px 30px 30px}} .track{{display:none}}}}
</style></head><body>
<header><h1>AppSec Pipeline Report · ClientNotes</h1><p>SAST (Bandit, Semgrep) · SCA (pip-audit) · DAST (custom HTTP scanner) · risk-based triage · before vs after remediation</p></header>
<main><div class='tiles'>{tiles}</div>
<section><h2>Findings by OWASP Top 10 (2021)</h2><div class='legend'>before &nbsp;·&nbsp; <span class='after'>after</span></div>{bars}</section>
<section><h2>Prioritized remediation queue (top issues, de-duplicated)</h2>
<table><tr><th>Priority</th><th>Finding</th><th>Tool</th><th>OWASP</th><th>CWE</th><th>Location</th><th>Confirmed by DAST</th></tr>{rows}</table></section>
<section><h2>SAST false positives reviewed on the remediated app</h2>
<table><tr><th>Location</th><th>Rule</th><th>Reason (verified)</th></tr>{fps}</table></section>
</main></body></html>"""
    (R / "appsec_report.html").write_text(page)
    print("wrote", R / "appsec_report.html")


if __name__ == "__main__":
    main()
