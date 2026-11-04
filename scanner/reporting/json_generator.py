"""
JSON and SARIF v2.1.0 Security Report Exporter
Generates machine-readable security reports compatible with GitHub Advanced Security
and CI/CD pipelines.
"""

import json
from typing import Any, Dict, List


class JSONReportGenerator:
    """Exports scan results to JSON and standard OASIS SARIF v2.1.0."""

    @classmethod
    def generate_json(cls, scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Returns standard normalized JSON report structure."""
        report = {
            "version": "2.0.0",
            "scanner": "Secret Leak Guard — Universal Source Code Security Scanner",
            "scan_id": scan_data.get("scan_id"),
            "project_name": scan_data.get("project_name"),
            "source_type": scan_data.get("source_type"),
            "source_target": scan_data.get("source_target"),
            "created_at": scan_data.get("created_at"),
            "completed_at": scan_data.get("completed_at"),
            "duration_seconds": scan_data.get("duration_seconds"),
            "status": scan_data.get("status"),
            "risk_score": scan_data.get("risk_score"),
            "security_grade": scan_data.get("security_grade"),
            "summary": scan_data.get("summary", {}),
            "engines_executed": scan_data.get("engines_executed", []),
            "findings_count": len(findings),
            "findings": findings,
        }
        return report

    @classmethod
    def generate_sarif(cls, scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generates standard OASIS SARIF (Static Analysis Results Interchange Format) v2.1.0
        for integration with GitHub Code Scanning alerts.
        """
        sarif_results = []
        rules = []
        seen_rules = set()

        for idx, f in enumerate(findings):
            rule_id = f.get("cwe") or f.get("title", f"RULE_{idx}")
            rule_id_clean = rule_id.split(":")[0].strip() if ":" in rule_id else rule_id

            if rule_id_clean not in seen_rules:
                seen_rules.add(rule_id_clean)
                rules.append({
                    "id": rule_id_clean,
                    "name": f.get("title", "Security Finding"),
                    "shortDescription": {"text": f.get("title", "")},
                    "fullDescription": {"text": f.get("description", "")},
                    "help": {"text": f.get("recommended_remediation", "Remediate finding.")},
                    "properties": {
                        "tags": ["security", f.get("category", "vulnerability").lower()],
                        "precision": "high",
                    },
                })

            level = "warning"
            sev = f.get("severity", "MEDIUM")
            if sev in ["CRITICAL", "HIGH"]:
                level = "error"
            elif sev == "LOW":
                level = "note"

            sarif_results.append({
                "ruleId": rule_id_clean,
                "level": level,
                "message": {"text": f"{f.get('title')}: {f.get('description')}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file_path", "unknown")},
                        "region": {
                            "startLine": f.get("line_number") or 1,
                            "startColumn": f.get("column_number") or 1,
                        },
                    }
                }],
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Secret Leak Guard",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/2025cspraveense-spec/Cdd--Project",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }],
        }
        return sarif_doc
