#!/usr/bin/env bash
# Runs the full AppSec pipeline locally: SAST -> SCA -> DAST -> risk-based triage -> HTML report
set -u
mkdir -p reports
for v in vulnerable fixed; do
  port=$([ "$v" = vulnerable ] && echo 5001 || echo 5002)
  bandit -q -f json -o reports/bandit_$v.json app_$v/app.py || true
  semgrep scan --quiet --metrics=off --config p/python --config p/flask --config p/owasp-top-ten --config p/dockerfile \
    --json -o reports/semgrep_$v.json app_$v >/dev/null || true
  pip-audit -r app_$v/requirements.txt -f json -o reports/sca_$v.json >/dev/null 2>&1 || true
  python dast/dast_scan.py app_$v $port reports/dast_$v.json
  python triage/triage.py $v || true
done
python triage/report.py
