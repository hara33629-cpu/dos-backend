# train_model.py

from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from data_loader import load_data  # optional if you separate

X, y = load_data()

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=300)
model.fit(X_scaled, y)

joblib.dump(model, "model/dnn_model.pkl")
joblib.dump(scaler, "model/scaler.pkl")

print("✅ Model trained and saved")
