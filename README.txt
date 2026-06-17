╔══════════════════════════════════════════════════════════════════════════════╗
║                     PHISHVOIDER — SETUP & EXECUTION GUIDE                    ║
║   A Machine Learning-Driven Browser Extension for Real-Time Phishing URL     ║
║                              Detection                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

================================================================================
TABLE OF CONTENTS
================================================================================
1.  Project Overview
2.  System Requirements
3.  Required Tools & Download Links
4.  Python Libraries & Versions
5.  Project Structure
6.  Dataset Information
7.  Installation Steps
8.  Running the Backend (Flask API)
9.  Loading the Chrome Extension
10. Testing the API
11. Retraining the Model (Optional)
12. API Endpoints Reference
13. Usage Instructions
14. Troubleshooting

================================================================================
1. PROJECT OVERVIEW
================================================================================

PhishVoider is a hybrid phishing URL detection system that combines:

  • A Random Forest ensemble ML model trained on 16 handcrafted URL/DOM features
    plus TF-IDF-transformed URL text (1,016-dimensional feature vector).
  • Five rule-based signals (suspicious TLD, URL length, special characters,
    HTTPS status, domain age) for rapid pre-filtering.
  • A Chrome Extension (Manifest V3) that intercepts browser navigation and
    sends URLs to a local Flask backend for analysis.
  • An SQLite database for prediction logging and user feedback.
  • Achieves 96.3% accuracy with an AUC-ROC of 0.992.

Architecture:

    User Browser (Chrome MV3 Extension)
           │
           │  HTTP POST /predict
           │  HTTP POST /analyze-page
           ▼
    Flask Backend (localhost:5000)
           │
           ├── ensemble_model.pkl  (trained Random Forest)
           ├── vectorizer.pkl      (fitted TF-IDF vectorizer)
           └── phishvoider.db      (scan history SQLite)

================================================================================
2. SYSTEM REQUIREMENTS
================================================================================

  • Operating System: Windows 10/11, macOS 12+, or Linux (Ubuntu 20.04+)
  • Python:         3.9 – 3.14 (tested on Python 3.14.0)
  • RAM:            8 GB minimum (16 GB recommended for model retraining)
  • Disk Space:     200 MB (project + dependencies); +500 MB for retraining
  • Browser:        Google Chrome 120+ (for MV3 extension)
  • Internet:       Required only for dataset download (initial setup)

================================================================================
3. REQUIRED TOOLS & DOWNLOAD LINKS
================================================================================

  ┌──────────────────────────────────────────────────────────────────────────┐
  │ Tool                  Recommended Version    Download Link                │
  ├──────────────────────────────────────────────────────────────────────────┤
  │ Python                3.12+ (tested on 3.14)  https://python.org         │
  │ Google Chrome         120+                    https://google.com/chrome  │
  │ Git (optional)        2.30+                   https://git-scm.com        │
  │ VS Code (optional)    Latest                  https://code.visualstudio.com │
  └──────────────────────────────────────────────────────────────────────────┘

Important: When installing Python, check "Add Python to PATH" so that the
           `python` and `pip` commands are available in the terminal.

================================================================================
4. PYTHON LIBRARIES & VERSIONS
================================================================================

All required Python packages are listed in requirements.txt with pinned versions.

Core Libraries:
  ┌────────────────────────────┬──────────┬────────────────────────────────────┐
  │ Package                    │ Version  │ Purpose                            │
  ├────────────────────────────┼──────────┼────────────────────────────────────┤
  │ Flask                      │ 3.1.2    │ Backend REST API server             │
  │ flask-cors                 │ 6.0.1    │ Cross-Origin Resource Sharing       │
  │ scikit-learn               │ 1.7.2    │ ML model (Random Forest, metrics)  │
  │ scipy                      │ 1.16.3   │ Sparse matrix operations           │
  │ numpy                      │ 2.3.5    │ Numerical computing                │
  │ pandas                     │ 2.3.3    │ Dataset loading & manipulation     │
  │ joblib                     │ 1.5.2    │ Model serialization (.pkl files)  │
  │ matplotlib                 │ 3.10.9   │ Evaluation graph generation        │
  │ seaborn                    │ 0.13.2   │ Statistical visualisation          │
  │ lxml                       │ 6.1.1    │ XML/HTML parsing (content script)  │
  │ Werkzeug                   │ 3.1.4    │ Flask WSGI utility                 │
  │ Jinja2                     │ 3.1.6    │ Flask template engine              │
  └────────────────────────────┴──────────┴────────────────────────────────────┘

Additional transitive dependencies (installed automatically):
  blinker==1.9.0       click==8.3.1         colorama==0.4.6
  contourpy==1.3.3     cycler==0.12.1       fonttools==4.63.0
  itsdangerous==2.2.0  kiwisolver==1.5.0    MarkupSafe==3.0.3
  packaging==26.2      pillow==12.2.0       pyparsing==3.3.2
  python-dateutil==2.9.0.post0  pytz==2025.2  six==1.17.0
  threadpoolctl==3.6.0 typing_extensions==4.15.0  tzdata==2025.2

================================================================================
5. PROJECT STRUCTURE
================================================================================

  Final-year-project/
  │
  ├── README.txt                  ← This file
  ├── requirements.txt            ← Python dependencies
  │
  ├── backend/                    ← Flask API server
  │   ├── app.py                  ← Main Flask application (prediction API)
  │   ├── model_training.py       ← Model training pipeline (optional retrain)
  │   ├── evaluate_model.py       ← Evaluation metrics + graph generation
  │   ├── page_features.py        ← Rule-based page content scoring engine
  │   ├── test_predict.py         ← API endpoint test suite
  │   ├── test_false_positives.py ← False positive regression tests
  │   ├── phishing_model.pkl      ← Trained ensemble model (Random Forest)
  │   ├── vectorizer.pkl          ← Fitted TF-IDF vectorizer
  │   ├── phishvoider.db          ← SQLite scan history database
  │   ├── top10k.txt              ← Global top 10,000 trusted domains
  │   ├── templates/
  │   │   └── dashboard.html      ← Flask dashboard template
  │   └── evaluation/             ← Generated evaluation plots
  │       ├── confusion_matrix.png
  │       ├── roc_curve.png
  │       ├── precision_recall_curve.png
  │       ├── feature_importance.png
  │       └── manual_feature_importance.png
  │
  ├── extension/                  ← Chrome MV3 Extension
  │   ├── manifest.json           ← Extension configuration
  │   ├── background.js           ← Service worker (URL interception + API calls)
  │   ├── content.js              ← Content script (DOM feature extraction)
  │   ├── popup.html / popup.js / popup.css   ← Popup UI
  │   ├── options.html / options.js / options.css  ← Settings page
  │   ├── warning.html / warning.js            ← Phishing warning interstitial
  │   ├── icon-safe.png           ← Green shield icon
  │   ├── icon-danger.png         ← Red warning icon
  │   └── icon-default.png        ← Default icon
  │
  ├── dataset/
  │   └── urls.csv                ← Training dataset (671,182 URLs, ~49 MB)
  │
  └── .gitignore

================================================================================
6. DATASET INFORMATION
================================================================================

The dataset (dataset/urls.csv) is a merged collection of publicly available
phishing URL datasets. It contains 671,182 rows with 2 columns:

  • url:   The full URL string
  • label: One of four categories:
           - benign      (448,094 samples) — legitimate, safe URLs
           - phishing    ( 94,111 samples) — phishing website URLs
           - defacement  ( 96,457 samples) — defaced website URLs
           - malware     ( 32,520 samples) — malware-hosting URLs

During training, defacement and malware labels are re-mapped to class 1
(phishing) for binary classification. The dataset is balanced by sampling
50,000 safe + 50,000 malicious URLs (100,000 total for training).

Source Datasets (public, free to use for research):

  (1) ISCX-URL2016
      - University of New Brunswick
      - https://www.unb.ca/cic/datasets/url-2016.html
      - Contains benign, phishing, defacement, and malware URLs.

  (2) PhishStorm
      - https://research.aalto.fi/en/datasets/phishstorm---a-phishing-url-dataset
      - Aalto University
      - Provides phishing and legitimate URL pairs.

  (3) Kaggle — Phishing URL Dataset
      - https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning
      - Community-curated collection on Kaggle.

  (4) Kaggle — Malicious URLs Dataset
      - https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
      - Large collection of malicious and benign URLs with multiple attack categories.

Note: The provided dataset/urls.csv is a pre-merged and cleaned version of
the above sources, and is already included in the project. You do NOT need
to download the individual source datasets unless you wish to reproduce
the exact merge process.

================================================================================
7. INSTALLATION STEPS
================================================================================

Step 1: Open a terminal (Command Prompt / PowerShell / Terminal).

Step 2: Navigate to the project directory.
        (If you are already in Final-year-project/, skip this step.)

        cd C:\FYP\Final-year-project

Step 3: Create a Python virtual environment (recommended).

        python -m venv venv

Step 4: Activate the virtual environment.

        Windows:
            venv\Scripts\activate

        macOS / Linux:
            source venv/bin/activate

        Your prompt should now show (venv) at the beginning.

Step 5: Upgrade pip (optional but recommended).

        python -m pip install --upgrade pip

Step 6: Install all required dependencies.

        pip install -r requirements.txt

        This will install Flask, scikit-learn, pandas, numpy, joblib,
        matplotlib, seaborn, and all other dependencies listed in Section 4.

Step 7: Verify the trained model files exist.

        You should see these two files inside the backend/ directory:
          - backend/phishing_model.pkl   (trained Random Forest model)
          - backend/vectorizer.pkl       (fitted TF-IDF vectorizer)

        If they are missing, follow Section 11 (Retraining the Model) to
        regenerate them.

================================================================================
8. RUNNING THE BACKEND (FLASK API)
================================================================================

Step 1: Ensure the virtual environment is activated (see Step 7.4).

Step 2: Start the Flask development server.

        cd backend
        python app.py

        Expected output:

            * Serving Flask app 'app'
            * Debug mode: on
            * Running on http://127.0.0.1:5000

Step 3: Verify the backend is running.

        Open a browser and navigate to:
            http://127.0.0.1:5000/

        You should see:   PhishVoider backend running

        Alternatively, use curl:

            curl http://127.0.0.1:5000/

Step 4: Keep this terminal window open. The backend must remain running for
        the Chrome extension to function.

Note: The first request may be slightly slower (~2-3 seconds) while the
      model and vectorizer are loaded from disk. Subsequent requests
      complete in under 100 ms.

================================================================================
9. LOADING THE CHROME EXTENSION
================================================================================

Step 1: Open Google Chrome.

Step 2: Navigate to the Extensions page:
        chrome://extensions/

Step 3: Enable "Developer mode" using the toggle switch in the top-right
        corner.

Step 4: Click "Load unpacked" button (top-left).

Step 5: In the file dialog, navigate to:
        C:\FYP\Final-year-project\extension

        Select the extension/ folder and click "Select Folder".

Step 6: The PhishVoider extension should now appear in your extensions list.
        Pin it to the toolbar for easy access (click the puzzle piece icon
        next to the address bar, then the pin icon next to PhishVoider).

Step 7: The extension is now active. It will automatically analyse every
        page you visit by communicating with the Flask backend at
        http://127.0.0.1:5000.

    Extension Features:

    ┌───────────────────┬─────────────────────────────────────────────────┐
    │ Feature            │ Description                                     │
    ├───────────────────┼─────────────────────────────────────────────────┤
    │ Popup             │ Click the icon to see the URL verdict and        │
    │                   │ risk analysis for the current page.              │
    ├───────────────────┼─────────────────────────────────────────────────┤
    │ Page Analysis     │ The content script extracts DOM-level signals    │
    │                   │ (hidden forms, iframes, brands, ads)             │
    │                   │ and sends them for rule-based scoring.           │
    ├───────────────────┼─────────────────────────────────────────────────┤
    │ Warning Page      │ If a phishing URL is detected, the extension    │
    │                   │ automatically redirects to a warning page        │
    │                   │ with the option to go back or bypass.            │
    ├───────────────────┼─────────────────────────────────────────────────┤
    │ Whitelist         │ Mark a domain as trusted via the popup or the    │
    │                   │ Options page to skip future scanning.            │
    ├───────────────────┼─────────────────────────────────────────────────┤
    │ Options/Settings  │ Configure API URL, manage whitelist, view        │
    │                   │ scan history and statistics.                     │
    └───────────────────┴─────────────────────────────────────────────────┘

================================================================================
10. TESTING THE API
================================================================================

With the Flask backend running (see Section 8), you can run the test suite
in a separate terminal:

    cd backend
    python test_predict.py

This will send 16 test URLs covering 8 categories (trusted domains,
legitimate URLs, tracking parameters, IP address URLs, suspicious keywords,
suspicious TLDs, shortened URLs, and suspicious patterns) and report
pass/fail results.

To test the false positive regression suite:

    cd backend
    python test_false_positives.py

This tests real-world legitimate URLs (Maybank, CIMB, HLB, Shopee, etc.)
with tracking parameters to ensure they are correctly classified as safe.

================================================================================
11. RETRAINING THE MODEL (OPTIONAL)
================================================================================

The project comes with a pre-trained model (phishing_model.pkl +
vectorizer.pkl). Retraining is only necessary if you modify the feature
engineering or want to experiment with hyperparameters.

Step 1: Ensure the virtual environment is activated.

Step 2: Run the training script:

        cd backend
        python model_training.py

        What happens:
          1. Loads dataset/urls.csv (~49 MB, 671,182 URLs)
          2. Balances to 50,000 safe + 50,000 malicious URLs
          3. Extracts 14 handcrafted URL features per sample
          4. Fits a TF-IDF vectorizer (char n-grams 3-5, max 15,000 features)
          5. Combines features into a ~15,014-dimensional feature vector
          6. Splits 80/20 train/test with stratification
          7. Trains a Random Forest classifier (100 trees, max_depth=50)
          8. Saves phishing_model.pkl and vectorizer.pkl to backend/

Step 3: Generate evaluation graphs (optional):

        python evaluate_model.py

        This produces 5 PNG files in backend/evaluation/:
          - confusion_matrix.png           — Confusion matrix heatmap
          - roc_curve.png                  — ROC curve with AUC
          - precision_recall_curve.png     — Precision-Recall curve with AP
          - feature_importance.png         — Top 20 features overall
          - manual_feature_importance.png  — Handcrafted features ranked

        These images are served by Flask at /evaluation/<filename>.

================================================================================
12. API ENDPOINTS REFERENCE
================================================================================

Base URL: http://127.0.0.1:5000

  ┌──────────────────┬──────────┬─────────────────────────────────────────┐
  │ Endpoint         │ Method   │ Description                             │
  ├──────────────────┼──────────┼─────────────────────────────────────────┤
  │ /                │ GET      │ Health check — returns "PhishVoider     │
  │                  │          │ backend running"                        │
  ├──────────────────┼──────────┼─────────────────────────────────────────┤
  │ /predict         │ POST     │ Analyse a single URL for phishing.      │
  │                  │          │ Request:  {"url": "https://..."}       │
  │                  │          │ Response: See below.                    │
  ├──────────────────┼──────────┼─────────────────────────────────────────┤
  │ /analyze-page    │ POST     │ Score DOM-level page features extracted │
  │                  │          │ by the content script (rule-based).      │
  │                  │          │ Request:  { forms, brands, iframes,     │
  │                  │          │            scripts, ads, ...}           │
  ├──────────────────┼──────────┼─────────────────────────────────────────┤
  │ /history         │ GET      │ Return the last 50 scan history entries │
  │                  │          │ from the SQLite database.                │
  ├──────────────────┼──────────┼─────────────────────────────────────────┤
  │ /export/csv      │ GET      │ Download scan history as a CSV file.    │
  ├──────────────────┼──────────┼─────────────────────────────────────────┤
  │ /stats           │ GET      │ Return total counts: scans, phishing,   │
  │                  │          │ and safe predictions.                   │
  ├──────────────────┼──────────┼─────────────────────────────────────────┤
  │ /dashboard       │ GET      │ Web dashboard showing scan history      │
  │                  │          │ in a table format.                      │
  ├──────────────────┼──────────┼─────────────────────────────────────────┤
  │ /evaluation/     │ GET      │ Serve evaluation graphs as static files │
  │ <filename>       │          │ e.g., /evaluation/roc_curve.png        │
  └──────────────────┴──────────┴─────────────────────────────────────────┘

  /predict Response (example — phishing detected):

    {
      "url": "https://secure-login.xyz/account/verify",
      "domain": "secure-login.xyz",
      "prediction": 1,
      "label": "phishing",
      "safe_probability": 0.0371,
      "phishing_probability": 0.9629,
      "risk_level": "HIGH",
      "risk_factors": [
        "Suspicious top-level domain detected",
        "URL contains suspicious keywords (secure, login, verify, account)",
        "Unusually long URL (39 characters)"
      ],
      "reason": "Machine learning URL analysis"
    }

  /predict Response (example — safe):

    {
      "url": "https://www.github.com",
      "domain": "github.com",
      "prediction": 0,
      "label": "safe",
      "safe_probability": 0.9999,
      "phishing_probability": 0.0001,
      "risk_level": "SAFE",
      "risk_factors": [],
      "reason": "Trusted legitimate domain"
    }

================================================================================
13. USAGE INSTRUCTIONS
================================================================================

  1. Start the Flask backend (Section 8).
  2. Load the Chrome extension (Section 9).
  3. Browse normally. The extension works automatically:
     - Every page load triggers a URL scan.
     - The icon changes colour based on the verdict:
       * Green shield = safe
       * Red shield = phishing detected (page is blocked)
     - Click the extension icon to view details:
       * Verdict (Safe / Phishing)
       * Confidence percentage
       * Risk factors explaining the decision
       * Page content analysis results
  4. On phishing detection:
     - You are redirected to a warning page with the URL details.
     - Click "Go Back" to return to the previous page.
     - Click "Ignore Risk" to proceed anyway (domain is bypassed for 24h).
  5. To access settings:
     - Right-click the extension icon → "Options"
     - Or click the gear icon in the popup
     - From here you can:
       * Change the backend API URL (default: http://127.0.0.1:5000)
       * Manage the whitelist (add/remove trusted domains)
       * View bypassed domains and clear them
       * View scan statistics and export history as CSV

================================================================================
14. TROUBLESHOOTING
================================================================================

  Problem: "Failed to load model/vectorizer" when starting Flask.

  Solution: Ensure phishing_model.pkl and vectorizer.pkl exist in the
            backend/ directory. If missing, run:
                cd backend
                python model_training.py
            to regenerate them from the dataset.

  ─────────────────────────────────────────────────────────────────────────

  Problem: Extension shows "This page hasn't been analysed yet."

  Solution:
    1. Verify the Flask backend is running (http://127.0.0.1:5000).
    2. Open the extension Options page and confirm the API URL is set to
       http://127.0.0.1:5000 (no trailing slash).
    3. Reload the page (F5) — the extension re-analyses on page load.
    4. Check chrome://extensions/ → PhishVoider → "Errors" for any
       JavaScript errors.
    5. Verify the extension has permission to access the API by checking
       host_permissions in manifest.json includes http://127.0.0.1:5000.

  ─────────────────────────────────────────────────────────────────────────

  Problem: "Port 5000 already in use" error.

  Solution: Another application is using port 5000. Either:
    - Stop the other process using port 5000, OR
    - Change the port in app.py (app.run(port=5001)) and update the
      extension's API URL in the Options page to http://127.0.0.1:5001.

  ─────────────────────────────────────────────────────────────────────────

  Problem: pip install fails with dependency conflicts.

  Solution: Use the exact versions in requirements.txt. Create a fresh
            virtual environment and run:
                pip install --upgrade pip
                pip install -r requirements.txt

  ─────────────────────────────────────────────────────────────────────────

  Problem: Dataset loading error during training.

  Solution: Verify dataset/urls.csv exists in the project root.
            Check that the file is not corrupted (expected size: ~49 MB).
            The expected columns are: url (string), label (string).

  ─────────────────────────────────────────────────────────────────────────

  Problem: Extension icon does not update after page load.

  Solution: The extension's background service worker may be inactive.
            Go to chrome://extensions/ → PhishVoider → Service Worker
            and check if it is running. Reload the extension using the
            refresh icon on the extension card.

================================================================================
                        END OF SETUP GUIDE
                For questions, contact the project author.
                  Author email: lamsoonhao3381@gmail.com
================================================================================
