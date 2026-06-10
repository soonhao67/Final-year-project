import urllib.request
import urllib.error
import json
import sys

API_URL = "http://127.0.0.1:5000/predict"

test_cases = [
    # (URL, expected_label, category)
    # --- Trusted Domains (should always be SAFE) ---
    ("https://www.google.com", "safe", "Trusted Domains"),
    ("https://www.youtube.com/watch?v=abc123", "safe", "Trusted Domains"),
    ("https://www.github.com", "safe", "Trusted Domains"),
    ("https://www.facebook.com", "safe", "Trusted Domains"),
    ("https://www.microsoft.com", "safe", "Trusted Domains"),

    # --- Clean Legitimate URLs ---
    ("https://blog.example.com/article/how-to-code", "safe", "Clean Legitimate URLs"),
    ("https://www.wikipedia.org/wiki/Machine_learning", "safe", "Clean Legitimate URLs"),

    # --- Tracking Parameters ---
    ("https://www.example.com/page?utm_source=google&utm_medium=cpc&utm_campaign=test", "safe", "Tracking Parameters"),
    ("https://shop.example.com/products?id=12345&ref=homepage&campaign=sale2026", "safe", "Tracking Parameters"),

    # --- IP Address URLs ---
    ("http://192.168.1.1/login", "phishing", "IP Address URLs"),
    ("http://10.0.0.5/bank/verify", "phishing", "IP Address URLs"),

    # --- Suspicious Keywords ---
    ("https://secure-login.example.com/verify-account", "phishing", "Suspicious Keywords"),

    # --- Suspicious TLDs ---
    ("https://free-money.xyz/claim-prize", "phishing", "Suspicious TLDs"),
    ("https://account-verify.tk/update-password", "phishing", "Suspicious TLDs"),

    # --- Shortened URL ---
    ("https://bit.ly/3xK9mN2", "phishing", "Shortened URL"),

    # --- Suspicious Pattern ---
    ("https://www.xyz123.top/secure/update/bank/account/login/verify/confirm", "phishing", "Suspicious Pattern"),
]

def test_url(url, expected_label, category):
    payload = json.dumps({"url": url}).encode("utf-8")
    req = urllib.request.Request(API_URL, data=payload,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read().decode("utf-8"))
        actual = result.get("label", "error")
        risk = result.get("risk_level", "---")
        prob = result.get("phishing_probability", 0)
        passed = actual == expected_label
        return passed, actual, risk, prob, result.get("reason", "")
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}", "---", 0, e.read().decode()
    except Exception as e:
        return False, f"Error", "---", 0, str(e)

def main():
    print("=" * 80)
    print("  PHISHVOIDER - API Test Suite")
    print("=" * 80)
    print(f"\n  Target: {API_URL}")
    print(f"  Tests : {len(test_cases)}")
    print(f"\n  {'':3} {'Category':20} {'Expected':10} {'Actual':10} {'Risk':8} {'Prob':8} {'Result':6}")
    print("  " + "-" * 72)

    passed = 0
    failed = 0

    for i, (url, expected, category) in enumerate(test_cases, 1):
        success, actual, risk, prob, reason = test_url(url, expected, category)
        prob_pct = f"{prob*100:.1f}%" if isinstance(prob, (int, float)) else "---"
        status = "[PASS]" if success else "[FAIL]"

        print(f"  {i:2} {category:20} {expected:10} {str(actual):10} {risk:8} {prob_pct:8} {status:6}")

        if success:
            passed += 1
        else:
            failed += 1

    print("  " + "-" * 72)
    print(f"\n  Results: {passed}/{len(test_cases)} passed, {failed}/{len(test_cases)} failed")
    print(f"  Success Rate: {passed/len(test_cases)*100:.1f}%")
    print()

    # Summary by category
    print("  " + "=" * 40)
    print("  Breakdown by Category")
    print("  " + "=" * 40)
    categories = {}
    for url, expected, category in test_cases:
        categories.setdefault(category, {"total": 0, "passed": 0})
    for url, expected, category in test_cases:
        categories[category]["total"] += 1
    for i, (url, expected, category) in enumerate(test_cases, 1):
        success, actual, risk, prob, reason = test_url(url, expected, category)
        if success:
            categories[category]["passed"] += 1

    for cat, counts in categories.items():
        pct = counts["passed"] / counts["total"] * 100
        print(f"  {cat:25} {counts['passed']}/{counts['total']} ({pct:.0f}%)")

    print()
    print("  " + "=" * 40)
    print("  Test Complete")
    print("  " + "=" * 40)

if __name__ == "__main__":
    # Quick check if server is running
    try:
        urllib.request.urlopen("http://127.0.0.1:5000/", timeout=3)
        print("  Backend is running.\n")
    except Exception:
        print("  ERROR: Backend is not running at http://127.0.0.1:5000")
        print("  Start it first with: python app.py")
        sys.exit(1)

    main()
