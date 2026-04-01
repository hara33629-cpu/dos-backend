import sqlite3
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# =========================
# LOAD DATA FROM DB
# =========================
conn = sqlite3.connect("traffic.db")
cursor = conn.cursor()

cursor.execute("""
SELECT 
    request_size,
    high_request_rate,
    repeated_access,
    small_payload,
    large_payload,
    unusual_user_agent,
    decision
FROM traffic_logs
""")

rows = cursor.fetchall()
conn.close()

# =========================
# PREPARE DATA
# =========================
X = []
y = []

label_map = {
    "ALLOW": 1,
    "SUSPICIOUS": 0.5,
    "BLOCK": 0
}

for row in rows:
    request_size, high_rate, repeated, small, large, unusual, decision = row

    features = [
        request_size,
        int(high_rate),
        int(repeated),
        int(small),
        int(large),
        int(unusual)
    ]

    X.append(features)
    y.append(label_map.get(decision, 0.5))

X = np.array(X)
y = np.array(y)

# =========================
# TRAIN / TEST SPLIT
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# =========================
# TRAIN MODEL
# =========================
model = RandomForestClassifier(n_estimators=100)

model.fit(X_train, y_train)

# =========================
# EVALUATE
# =========================
y_pred = model.predict(X_test)

print("\n📊 Model Evaluation:\n")
print(classification_report(y_test, y_pred))

# =========================
# SAVE MODEL
# =========================
joblib.dump(model, "model/model.pkl")

print("\n✅ Model saved as model/model.pkl")
