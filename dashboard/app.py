import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, render_template, request
import threading
import webbrowser

from database.mongo_handler import MongoHandler
from enforcer.rollback import RollbackEngine
from utils.logger import dashboard_logger
from config.settings import DASHBOARD_HOST, DASHBOARD_PORT

app = Flask(__name__)


@app.route("/")
def index():
    db = MongoHandler()
    threats = db.get_all(limit=500)
    stats = db.stats()
    return render_template("index.html", threats=threats, stats=stats)


@app.route("/api/threats")
def api_threats():
    db = MongoHandler()
    limit = min(int(request.args.get("limit", 200)), 1000)
    threats = db.get_all(limit=limit)
    return jsonify({"count": len(threats), "data": threats})


@app.route("/api/stats")
def api_stats():
    db = MongoHandler()
    return jsonify(db.stats())


@app.route("/api/blocked")
def api_blocked():
    db = MongoHandler()
    blocked = [t for t in db.get_all(limit=1000) if t.get("is_blocked")]
    return jsonify({"count": len(blocked), "data": blocked})


@app.route("/api/rollback", methods=["POST"])
def api_rollback():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()

    if not ip:
        return jsonify({"success": False, "error": "Missing 'ip' field."}), 400

    engine = RollbackEngine()
    success = engine.unblock_ip(ip)

    if success:
        dashboard_logger.info(f"[Dashboard] Rollback initiated for {ip} via API.")
        return jsonify({"success": True, "message": f"{ip} unblocked successfully."})
    else:
        return jsonify({"success": False, "error": f"Rollback failed for {ip}."}), 500


def _open_browser():
    webbrowser.open_new(f"http://localhost:{DASHBOARD_PORT}")


if __name__ == "__main__":
    dashboard_logger.info(
        f"Starting TIP Dashboard at http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"
    )
    threading.Timer(1.2, _open_browser).start()
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)