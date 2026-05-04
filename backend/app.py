# from flask import Flask, request, jsonify

# app = Flask(__name__)

# @app.route('/')
# def home():
#     return "PhishVoider backend running"

# @app.route('/predict', methods=['POST'])
# def predict():
#     data = request.get_json()
#     url = data.get('url')
    
#     # For now, just return a dummy response
#     response = {
#         "url": url,
#         "prediction": "safe",
#         "confidence": 1.0
#     }
#     return jsonify(response)

# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, request, jsonify
import joblib
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Allow requests from Chrome extension

# --- Load ML Model & Vectorizer ---
try:
    model = joblib.load("../backend/phishing_model.pkl")
    vectorizer = joblib.load("../backend/vectorizer.pkl")
    print("Model & vectorizer loaded successfully.")
except Exception as e:
    print("Error loading model/vectorizer:", e)

# --- Test Route ---
@app.route('/')
def home():
    return "PhishVoider backend running"

# --- Prediction Route ---
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' field"}), 400

    url = data['url'].lower()  # normalize URL

    try:
        # Transform URL with vectorizer
        X = vectorizer.transform([url])

        # Make prediction
        prediction_raw = model.predict(X)[0]
        prediction = int(prediction_raw)

        confidence = max(model.predict_proba(X)[0])

        return jsonify({
            "url": url,
            "prediction": prediction,
            "confidence": float(confidence),
            "label": "safe" if prediction == 0 else "phishing"
        })

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True)
