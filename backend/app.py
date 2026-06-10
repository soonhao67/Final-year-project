from flask import Flask, request, jsonify, render_template, send_from_directory, Response
from flask_cors import CORS

import joblib
import os
import logging
import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
import numpy as np
from scipy.sparse import hstack, csr_matrix

from page_features import score_page_features

# -----------------------------
# Flask App Setup
# -----------------------------
app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------------
# SQLite Database Setup
# -----------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishvoider.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            label TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            phishing_probability REAL NOT NULL,
            safe_probability REAL NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    logging.info("Database initialized.")

def log_scan(url, domain, label, risk_level, phishing_prob, safe_prob):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_history (timestamp, url, domain, label, risk_level, phishing_probability, safe_probability)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url, domain, label, risk_level,
            round(phishing_prob, 4),
            round(safe_prob, 4)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Failed to log scan: {e}")

init_db()

# -----------------------------
# Load ML Model & Vectorizer
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model_path = os.path.join(
    BASE_DIR,
    "phishing_model.pkl"
)

vectorizer_path = os.path.join(
    BASE_DIR,
    "vectorizer.pkl"
)

try:

    model = joblib.load(model_path)

    vectorizer = joblib.load(vectorizer_path)

    logging.info(
        "Model & vectorizer loaded successfully."
    )

except Exception as e:

    raise RuntimeError(
        f"Failed to load model/vectorizer: {e}"
    )

# -----------------------------
# URL Validation Regex
# -----------------------------
URL_PATTERN = re.compile(
    r'^(http|https)://'
)

# -----------------------------
# Trusted Domains
# -----------------------------
TRUSTED_DOMAINS = {

    # Search / Tech
    "google.com",
    "microsoft.com",
    "apple.com",
    "openai.com",

    # Social Media
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "threads.net",
    "reddit.com",
    "linkedin.com",

    # Video / Streaming
    "youtube.com",
    "netflix.com",
    "spotify.com",
    "twitch.tv",

    # Developer Platforms
    "github.com",
    "stackoverflow.com",

    # Education
    "mmu.edu.my",
    "coursera.org",
    "udemy.com",

    # Cloud / Enterprise
    "aws.amazon.com",
    "awsacademy.com",

    # Shopping
    "amazon.com",
    "shopee.com",
    "lazada.com",

    # Banking / Finance
    "paypal.com",

    # Entertainment
    "imdb.com",
    "plex.tv"
}

# -----------------------------
# Load Global Top 10k Domains
# -----------------------------
TOP_DOMAINS = set()
top10k_path = os.path.join(BASE_DIR, "top10k.txt")
try:
    if os.path.exists(top10k_path):
        with open(top10k_path, "r") as f:
            for line in f:
                TOP_DOMAINS.add(line.strip().lower())
        logging.info(f"Loaded {len(TOP_DOMAINS)} global trusted domains.")
except Exception as e:
    logging.warning(f"Could not load top10k.txt: {e}")

def check_is_trusted(domain):
    # Check exact match
    if domain in TRUSTED_DOMAINS or domain in TOP_DOMAINS:
        return True
    
    # Check .edu and .gov suffixes
    if domain.endswith('.edu') or domain.endswith('.gov') or domain.endswith('.edu.my') or domain.endswith('.gov.my'):
        return True
        
    # Check root domains (e.g., mail.google.com -> google.com)
    parts = domain.split('.')
    if len(parts) >= 2:
        root = f"{parts[-2]}.{parts[-1]}"
        if root in TRUSTED_DOMAINS or root in TOP_DOMAINS:
            return True
            
    if len(parts) >= 3:
        sub_root = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        if sub_root in TRUSTED_DOMAINS or sub_root in TOP_DOMAINS:
            return True
            
    return False

# -----------------------------
# Extract Features
# -----------------------------
def calculate_entropy(text):
    if not text:
        return 0
    import math
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(url):
    features = []
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('/'))
    features.append(sum(c.isdigit() for c in url))
    features.append(1 if 'https' in url else 0)
    features.append(1 if '@' in url else 0)
    features.append(url.count('='))
    features.append(url.count('?'))
    import re
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    features.append(1 if ip_pattern.search(url) else 0)
    suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'signin', 'confirm', 'password', 'wallet']
    keyword_count = sum(keyword in url.lower() for keyword in suspicious_keywords)
    features.append(keyword_count)
    
    # Advanced features
    features.append(calculate_entropy(url))
    
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    parts = domain.split('.')
    subdomain_count = max(0, len(parts) - 2)
    features.append(subdomain_count)
    
    suspicious_tlds = ['.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.io']
    has_suspicious_tld = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
    features.append(has_suspicious_tld)
    
    return features

# -----------------------------
# Extract Domain
# -----------------------------
def extract_domain(url):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # Remove www.
    if domain.startswith("www."):
        domain = domain[4:]

    return domain

# -----------------------------
# Risk Level Generator
# -----------------------------
def get_risk_level(probability):

    if probability >= 0.90:
        return "HIGH"

    elif probability >= 0.70:
        return "MEDIUM"

    elif probability >= 0.50:
        return "LOW"

    else:
        return "SAFE"

# -----------------------------
# Risk Factor Analysis
# -----------------------------
def analyze_risk_factors(url):
    factors = []

    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.search(url):
        factors.append("IP address detected instead of domain name")

    suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'signin', 'confirm', 'password', 'wallet']
    found_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
    if found_keywords:
        factors.append(f"URL contains suspicious keywords ({', '.join(found_keywords)})")

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    suspicious_tlds = ['.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.io']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        factors.append("Suspicious top-level domain detected")

    if len(url) > 100:
        factors.append(f"Unusually long URL ({len(url)} characters)")

    if '@' in url:
        factors.append("URL contains @ symbol (may hide true destination)")

    parts = domain.split('.')
    subdomain_count = max(0, len(parts) - 2)
    if subdomain_count > 2:
        factors.append(f"Many subdomains ({subdomain_count} levels deep)")

    entropy = calculate_entropy(url)
    if entropy > 4.5:
        factors.append(f"High URL entropy ({entropy:.1f}) — appears randomly generated")

    if not url.startswith('https'):
        factors.append("URL uses HTTP instead of HTTPS")

    special_chars = sum(1 for c in url if c in ['-', '.', '/', '=', '?', '%', '&', '_'])
    if special_chars > 10:
        factors.append(f"Many special characters ({special_chars} instances)")

    return factors

# -----------------------------
# Home Route
# -----------------------------
@app.route('/')
def home():

    return "PhishVoider backend running"

# -----------------------------
# Prediction Route
# -----------------------------
@app.route('/predict', methods=['POST'])
def predict():

    data = request.get_json()

    # -----------------------------
    # Validate Request
    # -----------------------------
    if not data or 'url' not in data:

        return jsonify({
            "error": "Missing 'url' field"
        }), 400

    if not isinstance(data['url'], str):

        return jsonify({
            "error": "URL must be a string"
        }), 400

    url = data['url'].strip().lower()

    # -----------------------------
    # Validate URL Format
    # -----------------------------
    if not URL_PATTERN.match(url):

        return jsonify({
            "error": "Invalid URL format"
        }), 400

    # -----------------------------
    # Extract Domain
    # -----------------------------
    domain = extract_domain(url)

    logging.info(f"Received URL: {url}")

    # -----------------------------
    # Trusted Domain Check
    # -----------------------------
    if check_is_trusted(domain):

        # Log trusted domain scan
        log_scan(
            url=url,
            domain=domain,
            label="safe",
            risk_level="SAFE",
            phishing_prob=0.0001,
            safe_prob=0.9999
        )

        return jsonify({

            "url": url,

            "domain": domain,

            "prediction": 0,

            "label": "safe",

            "safe_probability": 0.9999,

            "phishing_probability": 0.0001,

            "risk_level": "SAFE",

            "risk_factors": [],

            "reason":
                "Trusted legitimate domain"

        })

    # -----------------------------
    # ML Prediction
    # -----------------------------
    try:

        # Vectorize URL
        tfidf_features = vectorizer.transform([url])
        
        # Extract handcrafted features
        manual_features = np.array([extract_features(url)])
        manual_features_sparse = csr_matrix(manual_features)
        
        # Combine features
        X = hstack([tfidf_features, manual_features_sparse])

        # Get probabilities
        probabilities = model.predict_proba(X)[0]

        safe_prob = float(probabilities[0])

        phishing_prob = float(probabilities[1])

        # -----------------------------
        # Threshold Tuning
        # -----------------------------
        threshold = 0.50

        prediction = (
            1
            if phishing_prob >= threshold
            else 0
        )

        # -----------------------------
        # Risk Level
        # -----------------------------
        risk_level = get_risk_level(
            phishing_prob
        )

        # -----------------------------
        # Final Result
        # -----------------------------
        result = {

            "url": url,

            "domain": domain,

            "prediction": prediction,

            "label":
                "phishing"
                if prediction == 1
                else "safe",

            "safe_probability":
                round(safe_prob, 4),

            "phishing_probability":
                round(phishing_prob, 4),

            "risk_level":
                risk_level,

            "risk_factors":
                analyze_risk_factors(url),

            "reason":
                "Machine learning URL analysis"
        }

        log_scan(
            url=url,
            domain=domain,
            label=result["label"],
            risk_level=risk_level,
            phishing_prob=phishing_prob,
            safe_prob=safe_prob
        )

        return jsonify(result)

    except Exception as e:

        logging.error(
            f"Prediction failed: {e}"
        )

        return jsonify({
            "error":
                f"Prediction failed: {str(e)}"
        }), 500

# -----------------------------
# Page Content Analysis Route
# -----------------------------
@app.route('/analyze-page', methods=['POST'])
def analyze_page():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request body"}), 400

        # data comes directly from content script with forms/brands/iframes/scripts keys
        result = score_page_features(data)
        result["url"] = data.get("url", "")

        logging.info(
            f"Page analysis: score={result['page_risk_score']}, "
            f"level={result['page_risk_level']}, "
            f"factors={len(result['page_risk_factors'])}"
        )

        return jsonify(result)

    except Exception as e:
        logging.error(f"Page analysis failed: {e}")
        return jsonify({"error": f"Page analysis failed: {str(e)}"}), 500

# -----------------------------
# History Route
# -----------------------------
@app.route('/history', methods=['GET'])
def history():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM scan_history
            ORDER BY id DESC
            LIMIT 50
        ''')
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({"history": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# Export CSV Route
# -----------------------------
@app.route('/export/csv', methods=['GET'])
def export_csv():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, url, domain, label, risk_level, phishing_probability, safe_probability
            FROM scan_history
            ORDER BY id DESC
        ''')
        rows = cursor.fetchall()
        conn.close()

        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Timestamp", "URL", "Domain", "Label", "Risk Level", "Phishing Probability", "Safe Probability"])
        for row in rows:
            writer.writerow(row)

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=phishvoider_scan_history.csv"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# Stats Route
# -----------------------------
@app.route('/stats', methods=['GET'])
def stats():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE label = 'phishing'")
        total_phishing = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE label = 'safe'")
        total_safe = cursor.fetchone()[0]
        conn.close()
        return jsonify({
            "total_scans": total,
            "total_phishing": total_phishing,
            "total_safe": total_safe
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# Dashboard Route
# -----------------------------
@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

# -----------------------------
# Evaluation Graphs
# -----------------------------
EVAL_DIR = os.path.join(BASE_DIR, "evaluation")

@app.route('/evaluation/<filename>')
def evaluation_graph(filename):
    return send_from_directory(EVAL_DIR, filename)

# -----------------------------
# Run Flask App
# -----------------------------
if __name__ == "__main__":

    app.run(debug=True)