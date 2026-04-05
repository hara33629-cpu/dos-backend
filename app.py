from collections import defaultdict
request_counts = defaultdict(list)
rate_limit_store = defaultdict(list)

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import psycopg2
import os

from utils.predictor import predict_trust_score

# =========================
# DATABASE CONFIG
# =========================
DATABASE_URL = os.getenv("DATABASE_URL") or "postgresql://dos_db_user:HenUNMcO7hT1YTIys5pQftIwBDDg1yzz@dpg-d78it8hr0fns73e0mjmg-a/dos_db"

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # traffic logs
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
            threat_score FLOAT,
            decision TEXT
        )
        """)

        # blocked IPs
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            blocked_at TIMESTAMP,
            reason TEXT
        )
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Database initialized")

    except Exception as e:
        print("❌ DB Init Error:", e)


# =========================
# APP INIT
# =========================
app = Flask(__name__)
CORS(app)

@app.before_request
def initialize_database():
    if not hasattr(app, "db_initialized"):
        init_db()
        app.db_initialized = True


# =========================
# IP BLACKLIST
# =========================
blocked_ips_cache = set()

def load_blocked_ips():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT ip FROM blocked_ips")
        rows = cursor.fetchall()

        for row in rows:
            blocked_ips_cache.add(row[0])

        cursor.close()
        conn.close()
    except:
        pass


def is_ip_blocked(ip):
    return ip in blocked_ips_cache


def block_ip(ip, reason="Auto blocked"):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO blocked_ips (ip, blocked_at, reason)
        VALUES (%s, NOW(), %s)
        ON CONFLICT (ip) DO NOTHING
        """, (ip, reason))

        conn.commit()
        cursor.close()
        conn.close()

        blocked_ips_cache.add(ip)
        print(f"🚫 IP BLOCKED: {ip}")

    except Exception as e:
        print("❌ Block IP Error:", e)


# =========================
# RATE LIMITER
# =========================
def is_rate_limited(ip):
    now = time.time()

    rate_limit_store[ip] = [
        t for t in rate_limit_store[ip] if now - t <= 5
    ]

    rate_limit_store[ip].append(now)

    return len(rate_limit_store[ip]) > 20


# =========================
# FEATURE EXTRACTION
# =========================
def extract_behavior_features(ip, request_size, user_agent):
    current_time = time.time()

    request_counts[ip].append(current_time)

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
# THREAT SCORE (NEW 🔥)
# =========================
def calculate_threat_score(trust_score, features):
    rule_score = 0

    if features["high_request_rate"]:
        rule_score += 0.4
    if features["repeated_access"]:
        rule_score += 0.2
    if features["unusual_user_agent"]:
        rule_score += 0.2
    if features["small_payload"]:
        rule_score += 0.1
    if features["large_payload"]:
        rule_score += 0.1

    # Combine ML + rules
    threat_score = (1 - trust_score) * 0.6 + rule_score * 0.4

    return min(threat_score, 1.0)


# =========================
# GET CLIENT IP
# =========================
def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr


# =========================
# SAVE TO DB
# =========================
def save_to_db(log, features, threat_score, decision):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO traffic_logs (
            ip, timestamp, method, user_agent, request_size,
            request_count, high_request_rate, repeated_access,
            small_payload, large_payload, unusual_user_agent,
            threat_score, decision
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            threat_score,
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

    # 🚫 Step 1: Check blacklist
    if is_ip_blocked(ip):
        return jsonify({"decision": "BLOCKED (BLACKLIST)"}), 403

    timestamp = time.time()
    method = request.method
    user_agent = request.headers.get("User-Agent", "unknown")
    request_size = len(request.data)

    # 🚫 Step 2: Rate limit check
    if is_rate_limited(ip):
        block_ip(ip, "Rate limit exceeded")
        return jsonify({"decision": "BLOCKED (RATE LIMIT)"}), 429

    # Features
    features = extract_behavior_features(ip, request_size, user_agent)

    features_list = [
        request_size,
        int(features["high_request_rate"]),
        int(features["repeated_access"]),
        int(features["small_payload"]),
        int(features["large_payload"]),
        int(features["unusual_user_agent"])
    ]

    # ML
    trust_score = float(predict_trust_score(features_list))

    # 🔥 Threat score
    threat_score = float(calculate_threat_score(trust_score, features))

    # Decision
    if threat_score > 0.7:
        decision = "BLOCK"
        block_ip(ip, "High threat score")
    elif threat_score > 0.4:
        decision = "SUSPICIOUS"
    else:
        decision = "ALLOW"

    log = {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "user_agent": user_agent,
        "request_size": request_size
    }

    save_to_db(log, features, threat_score, decision)

    print("🧠 Threat Score:", threat_score)
    print("🚦 Decision:", decision)

    return jsonify({
        "decision": decision,
        "trust_score": trust_score,
        "threat_score": threat_score,
        "features": features
    })


# =========================
# LOAD BLOCKED IPS ON START
# =========================
load_blocked_ips()


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
