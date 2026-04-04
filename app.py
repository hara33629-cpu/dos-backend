from collections import defaultdict
request_counts = defaultdict(list)

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import psycopg2
import os

# ✅ Import ML modules
from utils.feature_extractor import extract_features
from utils.predictor import predict_trust_score

app = Flask(__name__)
CORS(app)

# In-memory storage (optional)
traffic_logs = []

# =========================
# DATABASE CONFIG
# =========================
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id SERIAL PRIMARY KEY,
        ip TEXT,
        timestamp DOUBLE PRECISION,
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
    cursor.close()
    conn.close()


# =========================
# BEHAVIOR FEATURE EXTRACTION
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
# RULE-BASED DETECTION
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
# SAVE TO DATABASE (FIXED)
# =========================
def save_to_db(log, features, decision):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO traffic_logs (
            ip, timestamp, method, user_agent, request_size,
            request_count, high_request_rate, repeated_access,
            small_payload, large_payload, unusual_user_agent, decision
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
        cursor.close()
        conn.close()

    except Exception as e:
        print("❌ DB Error:", e)


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

    # Feature extraction
    features_dict = extract_behavior_features(ip, request_size, user_agent)

    # Convert features → ML input
    features_list = [
        request_size,
        int(features_dict["high_request_rate"]),
        int(features_dict["repeated_access"]),
        int(features_dict["small_payload"]),
        int(features_dict["large_payload"]),
        int(features_dict["unusual_user_agent"])
    ]

    # ML Prediction
    trust_score = predict_trust_score(features_list)

    # Rule-based fallback
    rule_decision = detect_attack(features_dict)

    # Final decision
    if rule_decision == "BLOCK":
        decision = "BLOCK"
    else:
        if trust_score > 0.8:
            decision = "ALLOW"
        elif trust_score > 0.5:
            decision = "SUSPICIOUS"
        else:
            decision = "BLOCK"

    log = {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "user_agent": user_agent,
        "request_size": request_size
    }

    traffic_logs.append(log)

    # Save to DB
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
# FETCH LOGS (FIXED)
# =========================
@app.route("/logs", methods=["GET"])
def get_logs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC")
        rows = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify(rows)

    except Exception as e:
        return jsonify({"error": str(e)})


# =========================
# RUN APP (RENDER FIX)
# =========================
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
