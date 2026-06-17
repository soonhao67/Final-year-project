# PhishVoider

> **AI-Powered Anti-Phishing Browser Extension** — A hybrid machine learning and rule-based system for real-time phishing URL detection, deployed as a Chrome MV3 extension with a Flask API backend.

<p align="center">
  <img src="/backend/screenshot/1.jpg" width="320" style="vertical-align: middle" alt="Extension popup showing scan result">
  <img src="/backend/screenshot/2.jpg" width="280" style="vertical-align: middle" alt="Phishing warning interstitial page">
  <br>
  <em>Left: Extension popup with URL analysis result · Right: Warning page on phishing detection</em>
</p>

---

## Architecture

```
User Browser (Chrome MV3 Extension)
        │
        │  HTTP POST /predict
        │  HTTP POST /analyze-page
        ▼
Flask Backend (localhost:5000)
        │
        ├── phishing_model.pkl   (trained Random Forest)
        ├── vectorizer.pkl       (fitted TF-IDF vectorizer)
        └── phishvoider.db       (scan history SQLite)
```

---

## Quick Start

### Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.9–3.14 | https://python.org |
| Google Chrome | 120+ | https://google.com/chrome |

### 1. Setup

```bash
cd Final-year-project
python -m venv venv

# Windows:
venv\Scripts\activate
# macOS / Linux:
# source venv/bin/activate

pip install -r requirements.txt
```

### 2. Run the Backend

```bash
cd backend
python app.py
```

The Flask server starts at `http://127.0.0.1:5000`. Verify by visiting that URL in a browser — you should see `PhishVoider backend running`.

### 3. Load the Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top-right)
3. Click **Load unpacked** → select the `extension/` folder
4. Pin PhishVoider to the toolbar

The extension now automatically analyses every page you visit.

---

## Project Structure

```
Final-year-project/
│
├── backend/                   # Flask REST API
│   ├── app.py                 # Main application (prediction endpoints)
│   ├── model_training.py      # Model training pipeline
│   ├── evaluate_model.py      # Evaluation + graph generation
│   ├── page_features.py       # Rule-based page content scoring
│   ├── test_predict.py        # API endpoint tests
│   ├── test_false_positives.py# False positive regression tests
│   ├── phishing_model.pkl     # Trained Random Forest (21 MB)
│   ├── vectorizer.pkl         # Fitted TF-IDF vectorizer
│   ├── phishvoider.db         # SQLite scan history
│   ├── top10k.txt             # Top 10,000 trusted domains
│   └── evaluation/            # Generated evaluation plots
│
├── extension/                 # Chrome MV3 Extension
│   ├── manifest.json
│   ├── background.js          # Service worker (URL interception)
│   ├── content.js             # DOM feature extraction
│   ├── popup.html / .js / .css
│   ├── options.html / .js / .css
│   ├── warning.html / .js
│   └── icon-*.png             # Safe, danger, default icons
│
├── dataset/
│   └── urls.csv               # 671,182 URLs (~49 MB, public dataset)
│
├── requirements.txt
├── README.txt                 # Full setup guide (detailed)
└── README.md                  # This file
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check |
| `/predict` | POST | Analyse a URL for phishing |
| `/analyze-page` | POST | Score DOM-level page features |
| `/history` | GET | Last 50 scan history entries |
| `/export/csv` | GET | Download history as CSV |
| `/stats` | GET | Scan statistics |
| `/dashboard` | GET | Web dashboard |
| `/evaluation/<file>` | GET | Evaluation graph PNG |

### `/predict` Example

```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://secure-login.xyz/account/verify"}'
```

Response (phishing detected):
```json
{
  "label": "phishing",
  "phishing_probability": 0.9629,
  "risk_level": "HIGH",
  "risk_factors": [
    "Suspicious top-level domain detected",
    "URL contains suspicious keywords (secure, login, verify, account)"
  ],
  "reason": "Machine learning URL analysis"
}
```

---

## Dataset

The dataset (`dataset/urls.csv`) is a **merged collection of public datasets** (not self-collected):

| Label | Count |
|-------|-------|
| benign | 448,094 |
| defacement | 96,457 |
| phishing | 94,111 |
| malware | 32,520 |
| **Total** | **671,182** |

**Sources (free for research):**
- [ISCX-URL2016](https://www.unb.ca/cic/datasets/url-2016.html) — University of New Brunswick
- [PhishStorm](https://research.aalto.fi/en/datasets/phishstorm---a-phishing-url-dataset) — Aalto University
- [Kaggle Phishing Dataset](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning)
- [Kaggle Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset)

---

## Performance

| Metric | Value |
|--------|-------|
| Accuracy | 96.3% |
| Precision | 95.8% |
| Recall | 96.9% |
| F1-Score | 96.3% |
| AUC-ROC | 0.992 |
| AUCPR | 0.994 |
| Avg. Latency | <100 ms |

Evaluation graphs are served at `http://127.0.0.1:5000/evaluation/roc_curve.png` (etc.) when the backend is running.

---

## Testing

With the backend running:

```bash
cd backend
python test_predict.py             # 16 test cases across 8 categories
python test_false_positives.py      # Regression test on real-world URLs
```

---

## Retraining (Optional)

```bash
cd backend
python model_training.py      # Trains model and saves .pkl files
python evaluate_model.py      # Generates evaluation graphs in evaluation/
```

Training uses 100,000 balanced samples (50K safe + 50K malicious) with a Random Forest classifier (100 trees, `max_depth=50`) and char n-gram TF-IDF (3-5 grams, 15,000 max features).

---

## Extension Features

- **Real-time scanning** — every page load triggers a URL analysis
- **Colour-coded icon** — green (safe), red (phishing detected)
- **Warning page** — automatic redirect on phishing detection with bypass option
- **Explainable verdicts** — popup shows risk factors and confidence percentage
- **Page content analysis** — DOM-level signal detection (hidden forms, iframes, brand mismatch, malvertising)
- **Whitelist** — mark trusted domains to skip scanning
- **Scan history** — searchable log with CSV export
- **Dashboard** — web-based scan history viewer

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "Failed to load model" | Run `python model_training.py` in `backend/` |
| Extension shows "not analysed" | Confirm Flask is running on `http://127.0.0.1:5000`, reload the page |
| Port 5000 in use | Change port in `app.py` and update extension API URL in Options |
| Extension icon not updating | Go to `chrome://extensions/` → PhishVoider → check Service Worker |
| `pip install` conflicts | Use a fresh venv: `pip install -r requirements.txt` |

---

*For the complete detailed guide with all tool versions, library references, and dataset download links, see [`README.txt`](./README.txt).*
