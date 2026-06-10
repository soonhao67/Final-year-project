"""Test previously false-positive URLs with the retrained model."""
import urllib.request
import json
import ssl

BASE = "http://127.0.0.1:5000/predict"

def post_json(url, data):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        return json.loads(resp.read())

test_urls = [
    # Previously false positives
    ("HLB Bank (with tracking params)", "https://www.hlb.com.my/en/personal-banking/promotions/cards-acquisition-promotion.html?ecp=PSGoAACCajTKK250226L5&utm_source=google&utm_medium=cpm&utm_campaign=cc_always_on_mar26jul26&utm_content=cc_en_ad_copy_1&gad_source=1&gad_campaignid=22262203894&gbraid=0AAAAAC948SBO1JSGLMMMJXTI_E0ADVWXB&gclid=CjwKCAjw5S_qBhADEiwAddG_BRExMGomW3_IBQvG3wNx2OX4DYOpKMnI2ZUjUGZHAH4iL7hUDRxPRROCnWEQAvD_BwE"),
    ("Bank Islam", "https://www.bankislam.com/"),
    ("HLB Bank (clean, no params)", "https://www.hlb.com.my/"),
    ("MMU CLiC", "https://clic.mmu.edu.my/psp/csprd/?cmd=login&languagecd=eng"),
    ("MMU (with tracking)", "https://www.mmu.edu.my/intake/?utm_source=google&utm_medium=cpc&utm_campaign=bottom_julyintake_q2_2026&gad_source=1&gclid=CjwKCAjw5S_qBhADEiwAddG_BLpxYCI211NBRDI5_H-KwQHJH1lx6T_3NxQO2CJM8ERVqr652DJw9hoCHLAQAvD_BwE"),
    ("Maybank (with tracking)", "https://www.maybank2u.com.my/personal-banking/promotions/cards-acquisition-promotion.html?utm_source=google&utm_medium=cpc&utm_campaign=brand_always_on&gad_source=1&gclid=CjwKCAjw5S_qBhADEiwAddG_BRExMGomW3_IBQvG3wNx2OX4DYOpKMnI2ZUjUGZHAH4iL7hUDRxPRROCnWEQAvD_BwE"),
    ("CIMB Bank (with tracking)", "https://www.cimb.com.my/personal-banking/promotions/fd-promotion.html?utm_source=google&utm_medium=cpc&utm_campaign=fd_campaign&gad_source=1"),
    ("Google Search (long params)", "https://www.google.com/search?q=online+banking+malaysia&sca_esv=853093b83e557101&sxsrf=ANbl-n44i36LFyyo69w2v-WGnoiIk0eWXQ:1779726750391&source=hp&ei=nnkUAOsjFA_n2roPK_w42Ag&oq=online+banking&gs_lp=EgZnd3Mtd2l6"),
    ("Amazon product (with tracking)", "https://www.amazon.com/dp/B0EXAMPLE1?ref=footer&utm_source=google&utm_medium=cpc&utm_campaign=summer_sale"),
    ("Shopee (with tracking)", "https://shopee.com.my/deals/today-deals?utm_source=google&utm_medium=cpc&utm_campaign=brand_terms_q2"),
    # Actual phishing URLs (should still be detected)
    ("Phishing: suspicious TLD", "https://secure-login.xyz/account/verify"),
    ("Phishing: IP address", "http://192.168.1.1/login"),
    ("Phishing: account verify", "https://account-verify.tk/update-password"),
    ("Phishing: free money", "https://free-money.xyz/claim-prize"),
    ("Phishing: paypal fake", "http://paypal-secure-login.xyz/account/verify"),
]

print(f"{'Test Case':<35} {'Label':<12} {'Phish%':<8} {'Safe%':<8} {'Risk':<8} {'Result'}")
print("=" * 85)

for name, url in test_urls:
    try:
        data = post_json(BASE, {"url": url})
        label = data.get("label", "error")
        phish = data.get("phishing_probability", 0)
        safe = data.get("safe_probability", 0)
        risk = data.get("risk_level", "?")
        
        # Determine if correct (heuristic)
        is_actually_phishing = ("phishing" in name.lower() or "fake" in name.lower())
        is_actually_safe = not is_actually_phishing
        correct = (label == "phishing" and is_actually_phishing) or (label == "safe" and is_actually_safe)
        
        mark = "PASS" if correct else "FAIL"
        print(f"{name:<35} {label:<12} {phish:<8.2%} {safe:<8.2%} {risk:<8} {mark}")
    except Exception as e:
        print(f"{name:<35} ERROR: {e}")
