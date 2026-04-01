from collections import defaultdict
request_counts = defaultdict(list)

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import sqlite3

# ✅ Import ML modules
from utils.feature_extractor import extract_features
from utils.predictor import predict_trust_score

app = Flask(__name__)
CORS(app)

# In-memory storage (optional)
traffic_logs = []


# =========================
# BEHAVIOR FEATURE EXTRACTION (RENAMED)
# =========================
def extract_behavior_features(ip, request_size, user_agent):
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
# RULE-BASED DETECTION (BACKUP)
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
# DATABASE INIT FUNCTION
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


# Initialize DB
init_db()


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
# MAIN ROUTE (UPDATED WITH DNN)
# =========================
@app.route("/", methods=["GET", "POST"])
def log_request():
    ip = get_client_ip()
    timestamp = time.time()
    method = request.method
    user_agent = request.headers.get("User-Agent", "unknown")
    request_size = len(request.data)

    # ✅ Step 1: Extract behavior features
    features_dict = extract_behavior_features(ip, request_size, user_agent)

    # ✅ Step 2: Convert features → ML input
    features_list = [
        request_size,
        int(features_dict["high_request_rate"]),
        int(features_dict["repeated_access"]),
        int(features_dict["small_payload"]),
        int(features_dict["large_payload"]),
        int(features_dict["unusual_user_agent"])
    ]

    # ✅ Step 3: DNN Prediction
    trust_score = predict_trust_score(features_list)

    # ✅ Step 4: Rule-based backup
    rule_decision = detect_attack(features_dict)

    # ✅ Step 5: Final Decision (Hybrid)
    if rule_decision == "BLOCK":
        decision = "BLOCK"
    else:
        if trust_score > 0.8:
            decision = "ALLOW"
        elif trust_score > 0.5:
            decision = "SUSPICIOUS"
        else:
            decision = "BLOCK"

    # Log data
    log = {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "user_agent": user_agent,
        "request_size": request_size
    }

    traffic_logs.append(log)

    # ✅ Save to DB
    save_to_db(log, features_dict, decision)

    print("📥 Request Logged:", log)
    print("⚙️ Features:", features_dict)
    print("🧠 Trust Score:", trust_score)
    print("🚦 Decision:", decision)

    return jsonify({
        "message": "Request logged successfully",
        "data": log,
        "features": features_dict,
        "trust_score": trust_score,
        "decision": decision
    })


# =========================
# FETCH LOGS
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
    init_db()
    app.run(debug=True)
