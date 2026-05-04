import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import joblib

print("Loading dataset...")
df = pd.read_csv("../dataset/urls.csv")
df['label'] = df['label'].map({
    'benign': 0,
    'phishing': 1,
    'defacement': 1,
    'malware': 1
})

print(f"Total URLs in dataset: {len(df)}")

# Clean dataset
df = df.dropna(subset=['url', 'label'])
df['url'] = df['url'].astype(str)

# Sample 10,000 URLs for testing
df = df.sample(10000, random_state=42)
print(f"Using {len(df)} URLs for training/testing.")

y = df['label']

print("Extracting features from URLs...")
vectorizer = CountVectorizer(analyzer='char', ngram_range=(3, 5))
X = vectorizer.fit_transform(df['url'].str.lower()) # URLs are case-insensitive.
print("Feature extraction completed.")

print("Splitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print("Dataset split done.")

print("Training Logistic Regression model...")
model = LogisticRegression(max_iter=2000) 
model.fit(X_train, y_train)
print("Model training completed.")

print("Evaluating model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy on test set: {accuracy:.4f}")

print("Saving model & vectorizer...")
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
print("Files saved successfully.")
