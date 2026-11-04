import json
import time
import urllib.request

data = json.dumps({
    "dockerfile_content": "FROM python:3.9\nUSER root\nENV AWS_KEY=AKIAIOSFODNN7EXAMPLE\nEXPOSE 22"
}).encode("utf-8")

req = urllib.request.Request(
    "http://localhost/api/v1/scans/docker",
    data=data,
    headers={"Content-Type": "application/json"}
)

with urllib.request.urlopen(req) as resp:
    scan_id = json.loads(resp.read().decode())["scan_id"]
    print(f"[*] Submitted Scan ID: {scan_id}")

time.sleep(2)

res_req = urllib.request.Request(f"http://localhost/api/v1/scans/{scan_id}/results")
with urllib.request.urlopen(res_req) as res_resp:
    res = json.loads(res_resp.read().decode())
    print(f"[+] Status    : {res['status']}")
    print(f"[+] Risk Score: {res['risk_score']}/100 (Grade: {res['security_grade']})")
    print(f"[+] Findings  : {len(res['findings'])}")
    for f in res["findings"]:
        print(f"    - [{f['severity']}] {f['title']} ({f['file_path']})")

# Test HTML report export
html_req = urllib.request.Request(f"http://localhost/api/v1/scans/{scan_id}/report/html")
with urllib.request.urlopen(html_req) as html_resp:
    print(f"[+] HTML Report Status: {html_resp.status} (Length: {len(html_resp.read())} bytes)")

# Test JSON report export
json_req = urllib.request.Request(f"http://localhost/api/v1/scans/{scan_id}/report/json")
with urllib.request.urlopen(json_req) as json_resp:
    print(f"[+] JSON Report Status: {json_resp.status} (Length: {len(json_resp.read())} bytes)")

# Test SARIF report export
sarif_req = urllib.request.Request(f"http://localhost/api/v1/scans/{scan_id}/report/sarif")
with urllib.request.urlopen(sarif_req) as sarif_resp:
    print(f"[+] SARIF Report Status: {sarif_resp.status} (Length: {len(sarif_resp.read())} bytes)")

# Test PDF report export
pdf_req = urllib.request.Request(f"http://localhost/api/v1/scans/{scan_id}/report/pdf")
with urllib.request.urlopen(pdf_req) as pdf_resp:
    print(f"[+] PDF Report Status: {pdf_resp.status} (Length: {len(pdf_resp.read())} bytes)")
