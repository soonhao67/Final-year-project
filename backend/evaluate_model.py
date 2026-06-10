import os
import re
import math
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, precision_recall_curve,
    average_precision_score, classification_report
)

# -----------------------------------
# Setup
# -----------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "evaluation")
os.makedirs(OUT_DIR, exist_ok=True)

print("=" * 60)
print("  PHISHVOIDER - Model Performance Evaluation")
print("=" * 60)

# -----------------------------------
# 1. Load Dataset
# -----------------------------------
print("\n[1/7] Loading dataset...")
dataset_path = os.path.join(BASE_DIR, "..", "dataset", "urls.csv")
df = pd.read_csv(dataset_path)
df["label"] = df["label"].map({"benign": 0, "phishing": 1, "defacement": 1, "malware": 1})
df = df.dropna(subset=["url", "label"])
df["url"] = df["url"].astype(str)

# -----------------------------------
# 2. Balanced Sampling
# -----------------------------------
print("[2/7] Balancing dataset (100k samples)...")
safe_df = df[df["label"] == 0]
phish_df = df[df["label"] == 1]
sample_size = min(len(safe_df), len(phish_df), 50000)
safe_df = safe_df.sample(sample_size, random_state=42)
phish_df = phish_df.sample(sample_size, random_state=42)
df = pd.concat([safe_df, phish_df]).sample(frac=1, random_state=42)
print(f"    Final dataset: {len(df)} samples ({sample_size} per class)")

# -----------------------------------
# 3. Feature Extraction
# -----------------------------------
print("[3/7] Extracting features...")

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

MANUAL_FEATURE_NAMES = [
    "URL Length",
    "Number of Dots",
    "Number of Hyphens",
    "Number of Slashes",
    "Number of Digits",
    "Uses HTTPS",
    "Contains @",
    "Number of =",
    "Number of ?",
    "IP Address Detected",
    "Suspicious Keywords",
    "URL Entropy",
    "Subdomain Count",
    "Suspicious TLD"
]

def extract_features(url):
    features = []
    features.append(len(url))
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("/"))
    features.append(sum(c.isdigit() for c in url))
    features.append(1 if "https" in url else 0)
    features.append(1 if "@" in url else 0)
    features.append(url.count("="))
    features.append(url.count("?"))
    ip_pattern = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    features.append(1 if ip_pattern.search(url) else 0)
    suspicious_keywords = ["login", "verify", "secure", "account", "update", "bank", "signin", "confirm", "password", "wallet"]
    keyword_count = sum(kw in url.lower() for kw in suspicious_keywords)
    features.append(keyword_count)
    features.append(calculate_entropy(url))
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    parts = domain.split(".")
    subdomain_count = max(0, len(parts) - 2)
    features.append(subdomain_count)
    suspicious_tlds = [".xyz", ".top", ".club", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".io"]
    has_suspicious_tld = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
    features.append(has_suspicious_tld)
    return features

manual_features = np.array([extract_features(url) for url in df["url"]])
manual_features_sparse = csr_matrix(manual_features)
print(f"    Manual features: {manual_features.shape[1]}")

# -----------------------------------
# 4. Load Vectorizer & Transform
# -----------------------------------
print("[4/7] Loading vectorizer and transforming URLs...")
vectorizer_path = os.path.join(BASE_DIR, "vectorizer.pkl")
vectorizer = joblib.load(vectorizer_path)
tfidf_features = vectorizer.transform(df["url"].str.lower())
print(f"    TF-IDF features: {tfidf_features.shape[1]}")

# Combine features
X = hstack([tfidf_features, manual_features_sparse])
y = df["label"]
print(f"    Combined features: {X.shape[1]}")

# -----------------------------------
# 5. Load Model
# -----------------------------------
print("[5/7] Loading trained model...")
model_path = os.path.join(BASE_DIR, "phishing_model.pkl")
model = joblib.load(model_path)

# -----------------------------------
# 6. Split & Predict
# -----------------------------------
print("[6/7] Evaluating on test set (20% holdout)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

# Metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
tpr_val = tp / (tp + fn) if (tp + fn) > 0 else 0
fpr_val = fp / (fp + tn) if (fp + tn) > 0 else 0

sep = "-" * 40
print(f"\n{sep}")
print(f"  Accuracy : {accuracy:.4f}")
print(f"  Precision: {precision:.4f}")
print(f"  Recall   : {recall:.4f}")
print(f"  F1-Score : {f1:.4f}")
print(f"{sep}")
print(f"  True Positives : {tp}")
print(f"  False Positives: {fp}")
print(f"  True Negatives : {tn}")
print(f"  False Negatives: {fn}")
print(f"{sep}")
print(f"  TPR (Sensitivity): {tpr_val:.4f}")
print(f"  FPR (Fall-out)   : {fpr_val:.4f}")
print(f"{sep}\n")

# -----------------------------------
# 7. Generate Plots
# -----------------------------------
print("[7/7] Generating plots...")

sns.set_theme(style="whitegrid", font_scale=1.1)

# --- Plot 1: Confusion Matrix ---
print("    -> confusion_matrix.png")
fig, ax = plt.subplots(figsize=(6, 5))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False,
            xticklabels=["Safe", "Phishing"], yticklabels=["Safe", "Phishing"], ax=ax)
ax.set_xlabel("Predicted Label")
ax.set_ylabel("True Label")
ax.set_title("Confusion Matrix", fontsize=14, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "confusion_matrix.png"), dpi=150)
plt.close()

# --- Plot 2: ROC Curve ---
print("    -> roc_curve.png")
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
fig, ax = plt.subplots(figsize=(7, 6))
ax.plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC curve (AUC = {roc_auc:.4f})")
ax.plot([0, 1], [0, 1], color="navy", lw=1.5, linestyle="--", label="Random classifier")
ax.fill_between(fpr, tpr, alpha=0.15, color="darkorange")
ax.set_xlim([0.0, 1.0])
ax.set_ylim([0.0, 1.05])
ax.set_xlabel("False Positive Rate (FPR)")
ax.set_ylabel("True Positive Rate (TPR)")
ax.set_title("ROC Curve", fontsize=14, fontweight="bold")
ax.legend(loc="lower right")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "roc_curve.png"), dpi=150)
plt.close()

# --- Plot 3: Precision-Recall Curve ---
print("    -> precision_recall_curve.png")
precision_vals, recall_vals, _ = precision_recall_curve(y_test, y_prob)
avg_precision = average_precision_score(y_test, y_prob)
fig, ax = plt.subplots(figsize=(7, 6))
ax.plot(recall_vals, precision_vals, color="green", lw=2,
        label=f"PR curve (AP = {avg_precision:.4f})")
ax.fill_between(recall_vals, precision_vals, alpha=0.15, color="green")
ax.set_xlim([0.0, 1.0])
ax.set_ylim([0.0, 1.05])
ax.set_xlabel("Recall")
ax.set_ylabel("Precision")
ax.set_title("Precision-Recall Curve", fontsize=14, fontweight="bold")
ax.legend(loc="lower left")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "precision_recall_curve.png"), dpi=150)
plt.close()

# --- Plot 4: Feature Importance (Top 20) ---
print("    -> feature_importance.png")
importances = model.feature_importances_
num_tfidf = tfidf_features.shape[1]

# Get top 20 overall
top_indices = np.argsort(importances)[-20:][::-1]
top_values = importances[top_indices]

# Build labels: manual features get named labels, TF-IDF get generic labels
feature_labels = []
for idx in top_indices:
    if idx >= num_tfidf:
        manual_idx = idx - num_tfidf
        if 0 <= manual_idx < len(MANUAL_FEATURE_NAMES):
            feature_labels.append(f"[Manual] {MANUAL_FEATURE_NAMES[manual_idx]}")
        else:
            feature_labels.append(f"[Manual] Feature {manual_idx}")
    else:
        feature_labels.append(f"[TF-IDF] n-gram #{idx}")

fig, ax = plt.subplots(figsize=(9, 7))
bars = ax.barh(range(len(top_values)), top_values, color="steelblue")
ax.set_yticks(range(len(top_values)))
ax.set_yticklabels(feature_labels)
ax.invert_yaxis()
ax.set_xlabel("Importance Score")
ax.set_title("Top 20 Feature Importances", fontsize=14, fontweight="bold")
# Annotate values on bars
for i, (bar, val) in enumerate(zip(bars, top_values)):
    ax.text(val + 0.0001, i, f"{val:.4f}", va="center", fontsize=8)
ax.set_xlim(0, max(top_values) * 1.25)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "feature_importance.png"), dpi=150)
plt.close()

# --- Plot 5: Manual Feature Importance ---
print("    -> manual_feature_importance.png")
manual_importances = importances[num_tfidf:]
manual_indices = np.argsort(manual_importances)[::-1]
manual_values = manual_importances[manual_indices]
manual_labels = [MANUAL_FEATURE_NAMES[i] for i in manual_indices]

fig, ax = plt.subplots(figsize=(9, 6))
colors = ["#e74c3c" if v > 0.01 else "#3498db" for v in manual_values]
bars = ax.barh(range(len(manual_values)), manual_values, color=colors)
ax.set_yticks(range(len(manual_values)))
ax.set_yticklabels(manual_labels)
ax.invert_yaxis()
ax.set_xlabel("Importance Score")
ax.set_title("Handcrafted Feature Importances", fontsize=14, fontweight="bold")
for bar, val in zip(bars, manual_values):
    ax.text(val + 0.00005, bar.get_y() + bar.get_height() / 2,
            f"{val:.4f}", va="center", fontsize=9)
ax.set_xlim(0, max(manual_values) * 1.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "manual_feature_importance.png"), dpi=150)
plt.close()

# Summary
dline = "=" * 60
print(f"\n{dline}")
print("  Evaluation complete! All plots saved to:")
print(f"  {OUT_DIR}")
print(f"{dline}")
print("  confusion_matrix.png           - True vs Predicted breakdown")
print(f"  roc_curve.png                  - ROC curve (AUC = {roc_auc:.4f})")
print(f"  precision_recall_curve.png     - Precision-Recall (AP = {avg_precision:.4f})")
print("  feature_importance.png         - Top 20 features overall")
print("  manual_feature_importance.png  - Handcrafted feature ranking")
print(f"{dline}")
