from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import psycopg2
import os
import smtplib
from email.mime.text import MIMEText

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
DATABASE_URL = os.getenv("DATABASE_URL")

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
# EMAIL ALERT
# =========================
def send_email_alert(ip, reason):
    try:
        sender = os.getenv("EMAIL_USER")
        password = os.getenv("EMAIL_PASS")

        if not sender or not password:
            print("⚠️ Email credentials missing")
            return

        subject = "🚨 DOS ATTACK DETECTED & BLOCKED"

        html_body = f"""
        <html>
        <body style="font-family: Arial; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 10px;">
                
                <h2 style="color: red;">🚨 DOS Attack Alert</h2>
                
                <p><strong>Status:</strong> IP Blocked</p>
                
                <table style="width: 100%;">
                    <tr><td><strong>IP Address:</strong></td><td>{ip}</td></tr>
                    <tr><td><strong>Reason:</strong></td><td>{reason}</td></tr>
                    <tr><td><strong>Time:</strong></td><td>{time.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                </table>

                <hr>

                <p style="color: gray;">
                    This IP has been automatically blocked by your DOS Detection System.
                </p>

                <p style="font-size: 12px; color: gray;">
                    Project: DOS Mitigation System
                </p>

            </div>
        </body>
        </html>
        """

        msg = MIMEText(html_body, "html")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = sender

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, sender, msg.as_string())
        server.quit()

        print("📧 Email alert sent!")

    except Exception as e:
        print("❌ Email Error:", e)


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

        # ✅ send email only once
        if ip not in alerted_ips:
            send_email_alert(ip, reason)
            alerted_ips.add(ip)

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

    if is_ip_blocked(ip):
        return jsonify({"decision": "BLOCKED (BLACKLIST)"}), 403

    timestamp = time.time()
    method = request.method
    user_agent = request.headers.get("User-Agent", "unknown")
    request_size = len(request.data)

    if is_rate_limited(ip):
        block_ip(ip, "Rate limit exceeded")
        return jsonify({"decision": "BLOCKED (RATE LIMIT)"}), 429

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

    save_to_db(log, features, threat_score, decision)

    return jsonify({
        "decision": decision,
        "trust_score": trust_score,
        "threat_score": threat_score,
        "features": features
    })


# =========================
# ADMIN APIs
# =========================
@app.route("/stats")
def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM traffic_logs")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE decision='BLOCK'")
    blocked = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT ip) FROM traffic_logs")
    unique_ips = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    return jsonify({
        "total_requests": total,
        "blocked_requests": blocked,
        "unique_ips": unique_ips
    })


@app.route("/blocked", methods=["GET"])
def get_blocked_ips():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT ip, blocked_at, reason
            FROM blocked_ips
            ORDER BY blocked_at DESC
        """)
        rows = cursor.fetchall()

        cursor.close()
        conn.close()

        result = []
        for row in rows:
            result.append({
                "ip": row[0],
                "blocked_at": str(row[1]),
                "reason": row[2]
            })

        return jsonify({
            "count": len(result),
            "blocked_ips": result
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/alerts", methods=["GET"])
def get_alerts():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, ip, message, created_at
            FROM alerts
            ORDER BY created_at DESC
        """)
        rows = cursor.fetchall()

        cursor.close()
        conn.close()

        result = []
        for row in rows:
            result.append({
                "id": row[0],
                "ip": row[1],
                "message": row[2],
                "created_at": str(row[3])
            })

        return jsonify({
            "count": len(result),
            "alerts": result
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logs")
def get_logs():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC")
    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return jsonify(rows)


@app.route("/health")
def health():
    return "OK", 200


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    init_db()
    load_blocked_ips()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
