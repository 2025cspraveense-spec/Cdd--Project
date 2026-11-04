#!/usr/bin/env python3
"""
Test all navigation links, endpoints, and actions exposed by the Unified Gateway.
"""

import sys
import json
import urllib.request
from urllib.error import HTTPError, URLError

ENDPOINTS = [
    ("Scanner Portal UI (/)", "http://localhost/", [200]),
    ("Secured App (/app/)", "http://localhost/app/", [200]),
    ("HashiCorp Vault (/vault/)", "http://localhost/vault/", [200, 301, 307]),
    ("Nginx Gateway Health (/nginx-health)", "http://localhost/nginx-health", [200]),
    ("Scanner Health API (/api/v1/health)", "http://localhost/api/v1/health", [200]),
    ("Dashboard Metrics API (/api/v1/dashboard/metrics)", "http://localhost/api/v1/dashboard/metrics", [200]),
    ("Secured App Health (/app/health)", "http://localhost/app/health", [200]),
    ("Secured App Secrets Status (/app/api/secrets/status)", "http://localhost/app/api/secrets/status", [200]),
    ("Secured App Rotation (/app/api/secrets/rotation-status)", "http://localhost/app/api/secrets/rotation-status", [200]),
    ("Secured App Rotation Alias (/app/api/secrets/rotation)", "http://localhost/app/api/secrets/rotation", [200]),
]

def check_endpoints():
    print("=" * 70)
    print("[*] TESTING ALL GATEWAY NAVBAR LINKS AND BACKEND ENDPOINTS")
    print("=" * 70)
    all_ok = True
    for name, url, expected_codes in ENDPOINTS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SLG-Navbar-Tester/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.status
                is_ok = code in expected_codes
                status_str = "[PASS]" if is_ok else "[FAIL]"
                print(f"{status_str} | {name.ljust(45)} | HTTP {code}")
                if not is_ok:
                    all_ok = False
        except HTTPError as e:
            is_ok = e.code in expected_codes
            status_str = "[PASS]" if is_ok else "[FAIL]"
            print(f"{status_str} | {name.ljust(45)} | HTTP {e.code}")
            if not is_ok:
                all_ok = False
        except URLError as e:
            print(f"[FAIL] | {name.ljust(45)} | Connection error: {e.reason}")
            all_ok = False
        except Exception as e:
            print(f"[FAIL] | {name.ljust(45)} | Error: {e}")
            all_ok = False

    print("=" * 70)
    if all_ok:
        print("[SUCCESS] ALL NAVBAR LINKS AND ENDPOINTS ARE FULLY OPERATIONAL!")
    else:
        print("[WARNING] SOME ENDPOINTS REPORTED ERRORS.")
    print("=" * 70)
    return all_ok

if __name__ == "__main__":
    check_endpoints()
