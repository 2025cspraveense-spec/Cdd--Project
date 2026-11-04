"""
Report and Findings Endpoints
Serves paginated findings, PDF audit downloads, SARIF exports, and HTML reports.
"""

from flask import Blueprint, request, jsonify, Response, send_file
import io

from scanner.db import db
from scanner.reporting import PDFReportGenerator, JSONReportGenerator, HTMLReportGenerator

report_bp = Blueprint("report_bp", __name__)


@report_bp.route("/scans/<scan_id>/results", methods=["GET"])
def get_scan_results(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found."}), 404

    severity = request.args.get("severity")
    category = request.args.get("category")
    engine = request.args.get("engine")
    search = request.args.get("search")
    limit = int(request.args.get("limit", 100))
    skip = int(request.args.get("skip", 0))

    findings = db.get_findings(
        scan_id=scan_id,
        severity=severity,
        category=category,
        engine=engine,
        search=search,
        limit=limit,
        skip=skip,
    )
    total_matching = db.count_findings(scan_id=scan_id, severity=severity)

    return jsonify({
        "scan_id": scan_id,
        "project_name": scan.get("project_name"),
        "status": scan.get("status"),
        "risk_score": scan.get("risk_score"),
        "security_grade": scan.get("security_grade"),
        "summary": scan.get("summary", {}),
        "total_findings": total_matching,
        "limit": limit,
        "skip": skip,
        "findings": findings,
    }), 200


@report_bp.route("/scans/<scan_id>/report/pdf", methods=["GET"])
def download_pdf_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found."}), 404

    findings = db.get_findings(scan_id=scan_id, limit=500)
    pdf_bytes = PDFReportGenerator.generate(scan, findings)

    filename = f"security_report_{scan.get('project_name', 'project')}_{scan_id}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@report_bp.route("/scans/<scan_id>/report/json", methods=["GET"])
def download_json_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found."}), 404

    findings = db.get_findings(scan_id=scan_id, limit=1000)
    report = JSONReportGenerator.generate_json(scan, findings)
    return jsonify(report), 200


@report_bp.route("/scans/<scan_id>/report/sarif", methods=["GET"])
def download_sarif_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found."}), 404

    findings = db.get_findings(scan_id=scan_id, limit=1000)
    sarif = JSONReportGenerator.generate_sarif(scan, findings)
    return jsonify(sarif), 200


@report_bp.route("/scans/<scan_id>/report/html", methods=["GET"])
def view_html_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found."}), 404

    findings = db.get_findings(scan_id=scan_id, limit=1000)
    html_content = HTMLReportGenerator.generate(scan, findings)
    return Response(html_content, mimetype="text/html"), 200
