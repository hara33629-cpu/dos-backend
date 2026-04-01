import joblib
import numpy as np

model = joblib.load("model/dnn_model.pkl")
scaler = joblib.load("model/scaler.pkl")

def predict_trust_score(features):
    features = np.array([features])
    features = scaler.transform(features)

    prob = model.predict_proba(features)[0][1]
    return prob
