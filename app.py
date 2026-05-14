from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import psycopg2
import os
import smtplib
from email.mime.text import MIMEText

from utils.send_email_alert import send_email_alert
from utils.predictor import predict_trust_score

# =========================
# IN-MEMORY STORES
# =========================
request_counts = defaultdict(list)
rate_limit_store = defaultdict(list)
blocked_ips_cache = set()
alerted_ips = set()  # ✅ prevent multiple emails per IP

# =========================
# DATABASE CONFIG
# =========================
DATABASE_URL =" postgresql://dosdb_user:1qyPhQywwqztaa2PexPRkHUQ7AURXNQE@dpg-d83067tckfvc7389r750-a.oregon-postgres.render.com/dosdb"

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    try:
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
            threat_score FLOAT,
            decision TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            blocked_at TIMESTAMP,
            reason TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            ip TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        load_blocked_ips()
        app.db_initialized = True

# =========================
# ALERT SYSTEM
# =========================
def create_alert(ip, message):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (ip, message) VALUES (%s, %s)",
            (ip, message)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print("❌ Alert Error:", e)

# =========================
# IP BLACKLIST
# =========================
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
    except Exception as e:
        print("❌ Load Blocked IPs Error:", e)

# =========================
# 🔥 FRONTEND ACTION HANDLER
# =========================
def handle_frontend_action(data):
    action = data.get("action")
    item = data.get("item", {})

    if action == "ADD":
        return jsonify({"message": "Item added", "item": item})

    elif action == "DELETE":
        return jsonify({"message": "Item deleted", "id": item.get("id")})

    elif action == "UPDATE":
        return jsonify({"message": "Item updated", "item": item})

    return jsonify({"error": "Invalid action"}), 400

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
        create_alert(ip, reason)

        if ip not in alerted_ips:
            send_email_alert(ip, "BLOCK", 1.0, {
                "request_count": 0,
                "high_request_rate": True,
                "repeated_access": True,
                "small_payload": False,
                "large_payload": False,
                "unusual_user_agent": False
            })
            alerted_ips.add(ip)

        print(f"🚫 IP BLOCKED: {ip}")

    except Exception as e:
        print("❌ Block IP Error:", e)

# =========================
# RATE LIMITER
# =========================
def is_rate_limited(ip):
    now = time.time()
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t <= 5]
    rate_limit_store[ip].append(now)
    return len(rate_limit_store[ip]) > 2

# =========================
# FEATURE EXTRACTION
# =========================
def extract_behavior_features(ip, request_size, user_agent):
    current_time = time.time()
    request_counts[ip].append(current_time)
    request_counts[ip] = [t for t in request_counts[ip] if current_time - t <= 60]
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
# THREAT SCORE
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
    threat_score = (1 - trust_score) * 0.6 + rule_score * 0.4
    return min(threat_score, 1.0)

# =========================
# GET CLIENT IP
# =========================
def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr

def save_to_db(log, features, threat_score, decision,
               visited_logs="NORMAL_REQUEST", visited_url=""):
    decision = normalize_decision(decision)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO traffic_logs (
                ip, timestamp, method, user_agent, request_size,
                request_count, high_request_rate, repeated_access,
                small_payload, large_payload, unusual_user_agent,
                threat_score, decision, visited_logs, visited_url
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            decision,
            visited_logs,
            visited_url
        ))

        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        print("❌ DB Error:", e)
def normalize_decision(decision):
    if "BLOCK" in decision:
        return "BLOCK"
    elif decision == "SUSPICIOUS":
        return "SUSPICIOUS"
    else:
        return "ALLOW"

def map_traffic_log_row(row):
    return {
        "id": row[0],
        "ip": row[1],
        "timestamp": row[2],
        "method": row[3],
        "user_agent": row[4],
        "request_size": row[5],
        "request_count": row[6],
        "high_request_rate": row[7],
        "repeated_access": row[8],
        "small_payload": row[9],
        "large_payload": row[10],
        "unusual_user_agent": row[11],
        "threat_score": row[12],
        "decision": row[13],
        "visited_logs": row[14],
        "visited_url": row[15]
    }

# =========================
# MAIN LOGGING ENDPOINT
# =========================
@app.route("/", methods=["GET", "POST"])
def log_request():
    ip = get_client_ip()

    data = request.get_json(silent=True)
    visited_logs = "NORMAL_REQUEST"
    visited_url = request.url

    if data and "action" in data:
        visited_logs = data.get("action")
        item = data.get("item", {})
        visited_url = item.get("page", request.url)

    timestamp = time.time()
    method = request.method
    user_agent = request.headers.get("User-Agent", "unknown")
    request_size = len(request.data)

    features = {
        "request_count": 0,
        "high_request_rate": False,
        "repeated_access": False,
        "small_payload": False,
        "large_payload": False,
        "unusual_user_agent": False
    }

    trust_score = 0.0
    threat_score = 0.0
    decision = "ALLOW"

    if is_ip_blocked(ip):
        decision = "BLOCKED (BLACKLIST)"

    elif is_rate_limited(ip):
        decision = "BLOCK"
        block_ip(ip, "Rate limit exceeded")

    else:
        features = extract_behavior_features(ip, request_size, user_agent)

        features_list = [
            request_size,
            int(features["high_request_rate"]),
            int(features["repeated_access"]),
            int(features["small_payload"]),
            int(features["large_payload"]),
            int(features["unusual_user_agent"])
        ]

        trust_score = float(predict_trust_score(features_list))
        threat_score = float(calculate_threat_score(trust_score, features))

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

    save_to_db(log, features, threat_score, decision, visited_logs, visited_url)

    return jsonify({
        "decision": normalize_decision(decision),
        "trust_score": trust_score,
        "threat_score": threat_score,
        "features": features,
        "visited_logs": visited_logs,
        "visited_url": visited_url
    })
# =========================
# FIXED /alerts ENDPOINT
# =========================
@app.route("/alerts", methods=["GET"])
def get_alerts():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch all alerts
        cursor.execute("SELECT id, ip, message, created_at FROM alerts ORDER BY created_at DESC")
        rows = cursor.fetchall()

        # Count alert types
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN message LIKE 'Rate limit%' THEN 'RATE_LIMIT'
                    WHEN message LIKE 'High threat score%' THEN 'HIGH_THREAT'
                    ELSE 'OTHER'
                END AS alert_type,
                COUNT(*) 
            FROM alerts 
            GROUP BY alert_type
        """)
        type_counts = {r[0]: r[1] for r in cursor.fetchall()}

        cursor.close()
        conn.close()

        result = [{"id": r[0], "ip": r[1], "message": r[2], "created_at": str(r[3])} for r in rows]

        return jsonify({
            "count": len(result),
            "alerts": result,
            "type_counts": type_counts  # new summary by alert type
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logs")
def get_logs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        result = [map_traffic_log_row(r) for r in rows]
        return jsonify({"count": len(result), "logs": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# FIXED /stats ENDPOINT
# =========================
@app.route("/stats")
def get_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM traffic_logs")
        total = cursor.fetchone()[0]

        # Count all blocked types
        cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE decision LIKE 'BLOCK%'")
        blocked = cursor.fetchone()[0]

        # Count suspicious
        cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE decision='SUSPICIOUS'")
        suspicious = cursor.fetchone()[0]

        # Count allowed
        cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE decision='ALLOW'")
        allowed = cursor.fetchone()[0]

        # Unique IPs
        cursor.execute("SELECT COUNT(DISTINCT ip) FROM traffic_logs")
        unique_ips = cursor.fetchone()[0]

        cursor.close()
        conn.close()

        return jsonify({
            "total_requests": total,
            "blocked_requests": blocked,
            "suspicious_requests": suspicious,
            "allowed_requests": allowed,
            "unique_ips": unique_ips
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# FIXED /blocked_requests
# =========================
@app.route("/blocked_requests", methods=["GET"])
def get_blocked_requests():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # fetch all types starting with BLOCK
        cursor.execute("SELECT * FROM traffic_logs WHERE decision LIKE 'BLOCK%' ORDER BY id DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        result = [map_traffic_log_row(r) for r in rows]
        return jsonify({"count": len(result), "blocked_requests": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# FIXED /allowed_requests
# =========================
@app.route("/allowed_requests", methods=["GET"])
def get_allowed_requests():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM traffic_logs WHERE decision='ALLOW' ORDER BY id DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        result = [map_traffic_log_row(r) for r in rows]
        return jsonify({"count": len(result), "allowed_requests": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# FIXED /suspicious_requests
# =========================
@app.route("/suspicious_requests", methods=["GET"])
def get_suspicious_requests():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM traffic_logs WHERE decision='SUSPICIOUS' ORDER BY id DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        result = [map_traffic_log_row(r) for r in rows]
        return jsonify({"count": len(result), "suspicious_requests": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# MODIFY REQUEST DECISION
# =========================
@app.route("/modify_request/<int:request_id>", methods=["PUT"])
def modify_request(request_id):
    try:
        data = request.get_json()
        new_decision = data.get("decision", "ALLOW")
        new_decision = normalize_decision(new_decision)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update the decision in database
        cursor.execute(
            "UPDATE traffic_logs SET decision = %s WHERE id = %s",
            (new_decision, request_id)
        )
        conn.commit()
        
        # Fetch updated record
        cursor.execute("SELECT * FROM traffic_logs WHERE id = %s", (request_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row:
            return jsonify({
                "status": "success",
                "message": f"Request {request_id} updated to {new_decision}",
                "data": map_traffic_log_row(row)
            }), 200
        else:
            return jsonify({"error": "Record not found"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# DELETE REQUEST
# =========================
@app.route("/delete_request/<int:request_id>", methods=["DELETE"])
def delete_request(request_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete the record from database
        cursor.execute("DELETE FROM traffic_logs WHERE id = %s", (request_id,))
        conn.commit()
        
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows > 0:
            return jsonify({
                "status": "success",
                "message": f"Request {request_id} deleted successfully"
            }), 200
        else:
            return jsonify({"error": "Record not found"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return "OK", 200


# ✅ FIXED: separate route (no indentation)
@app.route("/test_email")
def test_email():
    send_email_alert(
        "1.2.3.4",
        "BLOCK",
        0.95,
        {
            "request_count": 10,
            "high_request_rate": True,
            "repeated_access": True,
            "small_payload": False,
            "large_payload": False,
            "unusual_user_agent": True
        }
    )
    return "Email test triggered"


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    init_db()
    load_blocked_ips()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
