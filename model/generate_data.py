import sqlite3
import random
import time

# =========================
# CONNECT DB
# =========================
conn = sqlite3.connect("traffic.db")
cursor = conn.cursor()

# =========================
# CREATE TABLE IF NOT EXISTS
# =========================
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

# =========================
# HELPERS
# =========================
def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def normal_user_agent():
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

def bot_user_agent():
    return random.choice([
        "Googlebot",
        "Bingbot",
        "Crawler",
        "SpiderBot"
    ])

# =========================
# GENERATE DATA
# =========================
data = []

for _ in range(500):
    # NORMAL USERS
    request_size = random.randint(200, 2000)
    request_count = random.randint(1, 5)

    data.append((
        random_ip(),
        time.time(),
        "GET",
        normal_user_agent(),
        request_size,
        request_count,
        False,
        False,
        False,
        False,
        False,
        "ALLOW"
    ))

for _ in range(300):
    # SUSPICIOUS USERS
    request_size = random.randint(50, 500)
    request_count = random.randint(5, 15)

    data.append((
        random_ip(),
        time.time(),
        "GET",
        normal_user_agent(),
        request_size,
        request_count,
        False,
        True,
        True,
        False,
        False,
        "SUSPICIOUS"
    ))

for _ in range(300):
    # ATTACK USERS
    request_size = random.randint(1, 50)
    request_count = random.randint(20, 100)

    data.append((
        random_ip(),
        time.time(),
        "GET",
        bot_user_agent(),
        request_size,
        request_count,
        True,
        True,
        True,
        False,
        True,
        "BLOCK"
    ))

# =========================
# INSERT INTO DB
# =========================
cursor.executemany("""
INSERT INTO traffic_logs (
    ip, timestamp, method, user_agent, request_size,
    request_count, high_request_rate, repeated_access,
    small_payload, large_payload, unusual_user_agent, decision
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", data)

conn.commit()
conn.close()

print("✅ Fake dataset generated successfully!")
