from collections import defaultdict
request_counts = defaultdict(list)
from flask import Flask, request, jsonify
from flask_cors import CORS
import time

app = Flask(__name__)
CORS(app)

# In-memory storage (temporary)
traffic_logs = []

def get_client_ip():
    """Get real client IP (handles proxies)"""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr

@app.route("/", methods=["GET", "POST"])
def log_request():
    ip = get_client_ip()
    timestamp = time.time()
    method = request.method
    user_agent = request.headers.get("User-Agent", "unknown")
    request_size = len(request.data)

    log = {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "user_agent": user_agent,
        "request_size": request_size
    }

    traffic_logs.append(log)

    print("📥 Request Logged:", log)

    return jsonify({
        "message": "Request logged successfully",
        "data": log
    })

@app.route("/logs", methods=["GET"])
def get_logs():
    return jsonify(traffic_logs)

if __name__ == "__main__":
    app.run(debug=True)
