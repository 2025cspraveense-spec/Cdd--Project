"""
Scan Management API Endpoints
Handles project uploads, local folder references, GitHub repository clones,
Dockerfile ingestion, and status queries.
"""

from pathlib import Path
import tempfile
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

from scanner.config import ScannerConfig
from scanner.db import db
from scanner.ingestion import UploadManager, RepositoryManager
from scanner.models import ScanRecord, ScanStatus, SourceType
from scanner.orchestrator import orchestrator
from scanner.api.auth import jwt_required

scan_bp = Blueprint("scan_bp", __name__)


@scan_bp.route("/scans", methods=["GET"])
def list_scans():
    limit = int(request.args.get("limit", 50))
    skip = int(request.args.get("skip", 0))
    scans = db.list_scans(limit=limit, skip=skip)
    return jsonify({"total": len(scans), "scans": scans}), 200


@scan_bp.route("/scans/<scan_id>/status", methods=["GET"])
def get_scan_status(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan with ID '{scan_id}' not found."}), 404
    return jsonify({
        "scan_id": scan.get("scan_id"),
        "status": scan.get("status"),
        "progress_percentage": scan.get("progress_percentage", 0),
        "current_engine": scan.get("current_engine", ""),
        "duration_seconds": scan.get("duration_seconds", 0),
        "risk_score": scan.get("risk_score", 0),
        "security_grade": scan.get("security_grade", "A"),
        "summary": scan.get("summary", {}),
        "error_message": scan.get("error_message"),
    }), 200


@scan_bp.route("/scans/upload", methods=["POST"])
def scan_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request. Please upload a ZIP archive or code file."}), 400

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return jsonify({"error": "No file selected for upload."}), 400

    filename = secure_filename(uploaded_file.filename)
    project_name = request.form.get("project_name") or Path(filename).stem
    scan_history = request.form.get("scan_history", "false").lower() == "true"

    scan_rec = ScanRecord(
        project_name=project_name,
        source_type=SourceType.ZIP_UPLOAD if filename.lower().endswith((".zip", ".tar", ".gz", ".tgz")) else SourceType.SINGLE_FILE,
        source_target=filename,
    )

    try:
        temp_dir = Path(tempfile.mkdtemp(prefix="upload_"))
        temp_file_path = temp_dir / filename
        uploaded_file.save(str(temp_file_path))

        if filename.lower().endswith(".zip"):
            source_path = UploadManager.process_zip_upload(temp_file_path, scan_rec.scan_id)
        elif filename.lower().endswith((".tar", ".gz", ".tgz")):
            source_path = UploadManager.process_zip_upload(temp_file_path, scan_rec.scan_id)
        else:
            with open(temp_file_path, "rb") as f:
                content = f.read()
            source_path = UploadManager.process_single_file(filename, content, scan_rec.scan_id)

        temp_file_path.unlink(missing_ok=True)
        temp_dir.rmdir()

        orchestrator.run_scan_async(scan_rec, source_path, scan_history=scan_history)

        return jsonify({
            "message": "Scan job queued successfully.",
            "scan_id": scan_rec.scan_id,
            "project_name": project_name,
            "status": ScanStatus.QUEUED.value,
        }), 202

    except Exception as e:
        return jsonify({"error": f"Upload processing failed: {str(e)}"}), 400


@scan_bp.route("/scans/local", methods=["POST"])
def scan_local_folder():
    data = request.get_json(force=True, silent=True) or {}
    folder_path = data.get("path")
    if not folder_path:
        return jsonify({"error": "Missing 'path' parameter in request body."}), 400

    project_name = data.get("project_name") or Path(folder_path).name
    scan_history = bool(data.get("scan_history", False))

    scan_rec = ScanRecord(
        project_name=project_name,
        source_type=SourceType.LOCAL_FOLDER,
        source_target=str(folder_path),
    )

    try:
        source_path = UploadManager.process_local_folder(folder_path, scan_rec.scan_id)
        orchestrator.run_scan_async(scan_rec, source_path, scan_history=scan_history)

        return jsonify({
            "message": "Local folder scan queued successfully.",
            "scan_id": scan_rec.scan_id,
            "project_name": project_name,
            "status": ScanStatus.QUEUED.value,
        }), 202
    except Exception as e:
        return jsonify({"error": f"Failed to ingest local folder: {str(e)}"}), 400


@scan_bp.route("/scans/github", methods=["POST"])
def scan_github_repository():
    data = request.get_json(force=True, silent=True) or {}
    repo_url = data.get("repo_url")
    if not repo_url:
        return jsonify({"error": "Missing 'repo_url' parameter in request body."}), 400

    branch = data.get("branch")
    project_name = data.get("project_name") or Path(repo_url.rstrip("/")).stem
    scan_history = bool(data.get("scan_history", False))

    scan_rec = ScanRecord(
        project_name=project_name,
        source_type=SourceType.GITHUB_REPO,
        source_target=repo_url,
    )

    try:
        source_path = RepositoryManager.clone_repository(
            repo_url, scan_rec.scan_id, branch=branch, fetch_history=scan_history
        )
        orchestrator.run_scan_async(scan_rec, source_path, scan_history=scan_history)

        return jsonify({
            "message": "GitHub repository clone and scan queued successfully.",
            "scan_id": scan_rec.scan_id,
            "project_name": project_name,
            "status": ScanStatus.QUEUED.value,
        }), 202
    except Exception as e:
        return jsonify({"error": f"Repository ingestion failed: {str(e)}"}), 400


@scan_bp.route("/scans/docker", methods=["POST"])
def scan_dockerfile_content():
    data = request.get_json(force=True, silent=True) or {}
    content = data.get("dockerfile_content") or data.get("compose_content")
    if not content:
        return jsonify({"error": "Missing 'dockerfile_content' in request body."}), 400

    project_name = data.get("project_name", "Docker-Security-Audit")
    filename = "Dockerfile" if "dockerfile_content" in data else "docker-compose.yml"

    scan_rec = ScanRecord(
        project_name=project_name,
        source_type=SourceType.DOCKERFILE,
        source_target=filename,
    )

    try:
        source_path = UploadManager.process_single_file(filename, content.encode("utf-8"), scan_rec.scan_id)
        orchestrator.run_scan_async(scan_rec, source_path, scan_history=False)

        return jsonify({
            "message": "Dockerfile security scan queued successfully.",
            "scan_id": scan_rec.scan_id,
            "project_name": project_name,
            "status": ScanStatus.QUEUED.value,
        }), 202
    except Exception as e:
        return jsonify({"error": f"Failed to ingest Docker configuration: {str(e)}"}), 400


@scan_bp.route("/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    success = db.delete_scan(scan_id)
    return jsonify({"message": f"Scan '{scan_id}' and findings deleted.", "success": success}), 200
