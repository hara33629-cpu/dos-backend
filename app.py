from collections import defaultdict
request_counts = defaultdict(list)
from flask import Flask, request, jsonify
from flask_cors import CORS
import time

app = Flask(__name__)
CORS(app)

# In-memory storage (temporary)
traffic_logs = []

def extract_features(ip, request_size, user_agent):
    current_time = time.time()

    # Store request timestamps per IP
    request_counts[ip].append(current_time)

    # Keep only last 60 seconds data
    request_counts[ip] = [
        t for t in request_counts[ip] if current_time - t <= 60
    ]

    request_count = len(request_counts[ip])

    # Features
    high_request_rate = request_count > 20
    repeated_access = request_count > 5
    small_payload = request_size < 50
    large_payload = request_size > 5000
    unusual_user_agent = (
        "bot" in user_agent.lower() or
        "crawl" in user_agent.lower() or
        "spider" in user_agent.lower()
    )

    return {
        "request_count": request_count,
        "high_request_rate": high_request_rate,
        "repeated_access": repeated_access,
        "small_payload": small_payload,
        "large_payload": large_payload,
        "unusual_user_agent": unusual_user_agent
    }

def detect_attack(features):
    # 🚨 Strong attack pattern
    if features["high_request_rate"] and features["small_payload"]:
        return "BLOCK"

    # ⚠️ Suspicious behavior
    if features["repeated_access"] or features["unusual_user_agent"]:
        return "SUSPICIOUS"

    # ✅ Normal traffic
    return "ALLOW"

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
    decision = detect_attack(features)

    log = {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "user_agent": user_agent,
        "request_size": request_size
    }

    # ✅ Extract features here
    features = extract_features(ip, request_size, user_agent)

    traffic_logs.append(log)

    print("📥 Request Logged:", log)
    print("⚙️ Features:", features)

    return jsonify({
        "message": "Request logged successfully",
        "data": log,
        "features": features
        "decision": decision
    })

@app.route("/logs", methods=["GET"])
def get_logs():
    return jsonify(traffic_logs)

if __name__ == "__main__":
    app.run(debug=True)
