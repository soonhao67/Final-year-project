import pandas as pd
import numpy as np
import re
import joblib
import math
from urllib.parse import urlparse

from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split

from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# -----------------------------------
# Load Dataset
# -----------------------------------
print("Loading dataset...")

import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.join(BASE_DIR, "..", "dataset", "urls.csv")
df = pd.read_csv(dataset_path)

# -----------------------------------
# Label Mapping
# -----------------------------------
df['label'] = df['label'].map({
    'benign': 0,
    'phishing': 1,
    'defacement': 1,
    'malware': 1
})

# -----------------------------------
# Clean Dataset
# -----------------------------------
df = df.dropna(subset=['url', 'label'])

df['url'] = df['url'].astype(str)

# -----------------------------------
# Balanced Sampling
# -----------------------------------
print("Balancing dataset...")

safe_df = df[df['label'] == 0]
phish_df = df[df['label'] == 1]

# FYP 2 Optimization: 50,000 per class (100k total)
# Provides the optimal trade-off between high accuracy and manageable RAM usage.
sample_size = min(
    len(safe_df),
    len(phish_df),
    50000
)

safe_df = safe_df.sample(
    sample_size,
    random_state=42
)

phish_df = phish_df.sample(
    sample_size,
    random_state=42
)

df = pd.concat([
    safe_df,
    phish_df
])

# Shuffle dataset
df = df.sample(
    frac=1,
    random_state=42
)

print(f"Final dataset size: {len(df)}")

# -----------------------------------
# Handcrafted URL Features
# -----------------------------------
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

print("\nExtracting handcrafted features...")

manual_features = np.array([

    extract_features(url)

    for url in df['url']

])

# Convert to sparse matrix
manual_features_sparse = csr_matrix(
    manual_features
)

# -----------------------------------
# TF-IDF Features
# -----------------------------------
print("Extracting TF-IDF features...")

vectorizer = TfidfVectorizer(

    analyzer='char',

    ngram_range=(3, 5),

    max_features=15000,

    sublinear_tf=True

)

tfidf_features = vectorizer.fit_transform(
    df['url'].str.lower()
)

# -----------------------------------
# Combine Features
# -----------------------------------
print("Combining features...")

X = hstack([

    tfidf_features,

    manual_features_sparse

])

y = df['label']

# -----------------------------------
# Train-Test Split
# -----------------------------------
print("Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.2,

    random_state=42,

    stratify=y

)

# -----------------------------------
# Train Model
# -----------------------------------
print("Training Random Forest Classifier...")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=50,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Training completed.")

# -----------------------------------
# Evaluation
# -----------------------------------
print("\nEvaluating model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred
)

recall = recall_score(
    y_test,
    y_pred
)

f1 = f1_score(
    y_test,
    y_pred
)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-Score : {f1:.4f}")

# -----------------------------------
# Confusion Matrix
# -----------------------------------
print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)

# -----------------------------------
# Classification Report
# -----------------------------------
print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred
    )
)

# -----------------------------------
# Save Model
# -----------------------------------
print("\nSaving model files...")

joblib.dump(
    model,
    "phishing_model.pkl"
)

joblib.dump(
    vectorizer,
    "vectorizer.pkl"
)

print("Model & vectorizer saved successfully.")