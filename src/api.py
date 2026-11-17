"""Flask API for starting and checking VAPT scans."""
from __future__ import annotations

import hmac
import logging
import threading
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request

from .config import settings
from .scanner import ScanError, run_scan, validate_target

logging.basicConfig(
    level=getattr(logging, __import__("os").getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("vapt")

_scan_lock = threading.Lock()
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def create_app(mode: str) -> Flask:
    if mode not in {"blackbox", "graybox"}:
        raise ValueError("mode must be 'blackbox' or 'graybox'")
    app = Flask(__name__)
    app.config["SCAN_MODE"] = mode
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "scanner": mode})

    def authorized() -> bool:
        expected = settings.api_token
        supplied = request.headers.get("Authorization", "")
        if supplied.startswith("Bearer "):
            supplied = supplied[7:].strip()
        else:
            supplied = ""
        return bool(expected) and hmac.compare_digest(supplied, expected)

    @app.before_request
    def protect_api():
        if request.endpoint in {"health", "static"}:
            return None
        if not authorized():
            return jsonify({"error": "Unauthorized"}), 401
        return None

    @app.post("/scan")
    def start_scan():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a JSON object."}), 400
        target = payload.get("url")
        auth = payload.get("auth") if mode == "graybox" else None
        if mode == "blackbox" and "auth" in payload:
            return jsonify({"error": "This endpoint accepts black-box scans only."}), 400
        if mode == "graybox" and not isinstance(auth, dict):
            return jsonify({"error": "Gray-box scan requires an auth object."}), 400
        try:
            target = validate_target(target)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        if not _scan_lock.acquire(blocking=False):
            return jsonify({"error": "Another scan is already running. Try again later."}), 409

        job_id = str(uuid.uuid4())
        with _jobs_lock:
            _jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "mode": mode,
                "target": target,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

        def worker():
            with _jobs_lock:
                _jobs[job_id]["status"] = "running"
                _jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
            try:
                result = run_scan(target, auth=auth if mode == "graybox" else None)
                with _jobs_lock:
                    _jobs[job_id]["status"] = "completed"
                    _jobs[job_id]["result"] = result
            except Exception as exc:
                log.exception("Scan job %s failed.", job_id)
                with _jobs_lock:
                    _jobs[job_id]["status"] = "failed"
                    _jobs[job_id]["error"] = str(exc)
            finally:
                with _jobs_lock:
                    _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
                _scan_lock.release()

        threading.Thread(target=worker, name=f"vapt-{job_id[:8]}", daemon=True).start()
        return jsonify({
            "status": "scan_started",
            "job_id": job_id,
            "target": target,
            "scan_type": "gray-box" if mode == "graybox" else "black-box",
        }), 202

    @app.get("/scan/<job_id>")
    def scan_status(job_id: str):
        with _jobs_lock:
            job = _jobs.get(job_id)
            if not job:
                return jsonify({"error": "Job not found."}), 404
            # Return a shallow copy so callers cannot mutate the shared state.
            return jsonify(dict(job))

    return app
