from collections import defaultdict
request_counts = defaultdict(list)

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import sqlite3

app = Flask(__name__)
CORS(app)

# In-memory storage (optional)
traffic_logs = []


# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(ip, request_size, user_agent):
    current_time = time.time()

    request_counts[ip].append(current_time)

    # Keep last 60 sec
    request_counts[ip] = [
        t for t in request_counts[ip] if current_time - t <= 60
    ]

    request_count = len(request_counts[ip])

    return {
        "request_count": request_count,
        "high_request_rate": request_count > 20,
        "repeated_access": request_count > 5,
        "small_payload": request_size < 50,
        "large_payload": request_size > 5000,
        "unusual_user_agent": (
            "bot" in user_agent.lower()
            or "crawl" in user_agent.lower()
            or "spider" in user_agent.lower()
        )
    }


# =========================
# DETECTION LOGIC
# =========================
def detect_attack(features):
    if features["high_request_rate"] and features["small_payload"]:
        return "BLOCK"

    if features["repeated_access"] or features["unusual_user_agent"]:
        return "SUSPICIOUS"

    return "ALLOW"


# =========================
# GET CLIENT IP
# =========================
def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr


# =========================
# DATABASE INIT
# =========================
def init_db():
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        timestamp REAL,
        method TEXT,
        user_agent TEXT,
        request_size INTEGER,
        request_count INTEGER,
        high_request_rate BOOLEAN,
        repeated_access BOOLEAN,
        small_payload BOOLEAN,
        large_payload BOOLEAN,
        unusual_user_agent BOOLEAN,
        decision TEXT
    )
    """)

    conn.commit()
    conn.close()


# =========================
# SAVE TO DATABASE
# =========================
def save_to_db(log, features, decision):
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO traffic_logs (
        ip, timestamp, method, user_agent, request_size,
        request_count, high_request_rate, repeated_access,
        small_payload, large_payload, unusual_user_agent, decision
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log["ip"],
        log["timestamp"],
        log["method"],
        log["user_agent"],
        log["request_size"],
        features["request_count"],
        features["high_request_rate"],
        features["repeated_access"],
        features["small_payload"],
        features["large_payload"],
        features["unusual_user_agent"],
        decision
    ))

    conn.commit()
    conn.close()


# =========================
# MAIN ROUTE
# =========================
@app.route("/", methods=["GET", "POST"])
def log_request():
    ip = get_client_ip()
    timestamp = time.time()
    method = request.method
    user_agent = request.headers.get("User-Agent", "unknown")
    request_size = len(request.data)

    features = extract_features(ip, request_size, user_agent)
    decision = detect_attack(features)

    log = {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "user_agent": user_agent,
        "request_size": request_size
    }

    traffic_logs.append(log)

    # ✅ SAVE TO DB
    save_to_db(log, features, decision)

    print("📥 Request Logged:", log)
    print("⚙️ Features:", features)
    print("🚦 Decision:", decision)

    return jsonify({
        "message": "Request logged successfully",
        "data": log,
        "features": features,
        "decision": decision
    })


# =========================
# FETCH LOGS FROM DATABASE
# =========================
@app.route("/logs", methods=["GET"])
def get_logs():
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM traffic_logs")
    rows = cursor.fetchall()

    conn.close()

    return jsonify(rows)


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    init_db()   # ✅ create DB
    app.run(debug=True)
