from __future__ import annotations

import json
import os
import threading
from collections import OrderedDict
from io import BytesIO
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from web_scanner import ScanError, demo_assessment, discover_hosts, scan_target, validate_network

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)
DEMO_ONLY = os.environ.get("DEMO_ONLY", "0").lower() in {"1", "true", "yes"}
SCAN_LOCK = threading.Lock()
REPORT_CACHE: OrderedDict[str, bytes] = OrderedDict()
REPORT_CACHE_LOCK = threading.Lock()
MAX_CACHED_REPORTS = 25

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    )
    return response


@app.get("/")
def index():
    return render_template("index.html", demo_only=DEMO_ONLY)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "demo_only": DEMO_ONLY})


@app.post("/api/demo")
def api_demo():
    result = demo_assessment()
    report_id = _save_report(result)
    result["report_id"] = report_id
    return jsonify(result)


@app.post("/api/discover")
def api_discover():
    payload = request.get_json(silent=True) or {}
    if DEMO_ONLY:
        return jsonify({"error": "This public instance is demo-only; live network discovery is disabled."}), 403
    if not payload.get("authorized"):
        return jsonify({"error": "Confirm that you own or are authorized to assess this lab network."}), 400
    try:
        network = validate_network(str(payload.get("network", "")))
        if not SCAN_LOCK.acquire(blocking=False):
            return jsonify({"error": "Another scan is running. Try again after it finishes."}), 429
        try:
            result = discover_hosts(network)
        finally:
            SCAN_LOCK.release()
        return jsonify(result)
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    if DEMO_ONLY:
        return jsonify({"error": "This public instance is demo-only; live network scanning is disabled."}), 403
    if not payload.get("authorized"):
        return jsonify({"error": "Confirm that you own or are authorized to assess this target."}), 400
    try:
        if not SCAN_LOCK.acquire(blocking=False):
            return jsonify({"error": "Another scan is running. Try again after it finishes."}), 429
        try:
            result = scan_target(str(payload.get("target", "")), include_cve=bool(payload.get("include_cve", True)))
        finally:
            SCAN_LOCK.release()
        report_id = _save_report(result)
        result["report_id"] = report_id
        return jsonify(result)
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/report/<report_id>")
def download_report(report_id: str):
    if not report_id.isdigit() or len(report_id) > 20:
        return jsonify({"error": "Invalid report identifier."}), 400

    # Public demo reports are kept in a small bounded memory cache. This avoids
    # unbounded writes to an ephemeral public-host filesystem.
    if DEMO_ONLY:
        with REPORT_CACHE_LOCK:
            report_bytes = REPORT_CACHE.get(report_id)
        if report_bytes is None:
            return jsonify({"error": "Report not found or the demo instance restarted."}), 404
        return send_file(
            BytesIO(report_bytes),
            as_attachment=True,
            download_name=f"network_security_report_{report_id}.json",
            mimetype="application/json",
        )

    path = REPORT_DIR / f"report_{report_id}.json"
    if not path.exists() or path.resolve().parent != REPORT_DIR.resolve():
        return jsonify({"error": "Report not found."}), 404
    return send_file(path, as_attachment=True, download_name=f"network_security_report_{report_id}.json", mimetype="application/json")


def _save_report(result: dict) -> str:
    report_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
    report_bytes = json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")
    if DEMO_ONLY:
        with REPORT_CACHE_LOCK:
            REPORT_CACHE[report_id] = report_bytes
            REPORT_CACHE.move_to_end(report_id)
            while len(REPORT_CACHE) > MAX_CACHED_REPORTS:
                REPORT_CACHE.popitem(last=False)
    else:
        path = REPORT_DIR / f"report_{report_id}.json"
        path.write_bytes(report_bytes)
    return report_id


if __name__ == "__main__":
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print("Network Penetration Testing Tool — Web Dashboard")
    print(f"Open: http://{host}:{port}")
    if DEMO_ONLY:
        print("DEMO_ONLY is enabled: live scanning is disabled.")
    app.run(host=host, port=port, debug=False)
