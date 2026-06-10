# PhishVoider Page Content Analysis
# Scores DOM-level features extracted by the extension content script.
# Operates as a rule-based scoring system — no ML model needed.

import logging

logger = logging.getLogger(__name__)

# ─── Score Weights ─────────────────────────────────
# Each signal contributes a score delta. Negative values reduce suspicion.

WEIGHTS = {
    "form_action_mismatch":       0.30,
    "brand_domain_mismatch":      0.25,
    "hidden_iframes":             0.18,
    "excessive_hidden_inputs":    0.12,
    "high_external_script_ratio": 0.12,
    "has_password_field":         0.08,
    "has_credit_card_field":      0.15,
    "many_external_domains":      0.10,
    "suspicious_ad_network":      0.22,
    "many_ad_networks":           0.15,
    "popup_ad_elements":          0.18,
    "oversized_ad":               0.12,
    "autoplay_video_ad":          0.10,
}

THRESHOLD_HIGH   = 0.50
THRESHOLD_MEDIUM = 0.30
THRESHOLD_LOW    = 0.15


def score_page_features(features):
    """
    Accepts the feature object from the content script.
    Returns { score: float, level: str, factors: [str] }.
    """
    score = 0.0
    factors = []

    forms  = features.get("forms", {}) or {}
    brands = features.get("brands", {}) or {}
    iframes = features.get("iframes", {}) or {}
    scripts = features.get("scripts", {}) or {}
    ads = features.get("ads", {}) or {}
    ad_elements = features.get("ad_elements", {}) or {}
    autoplay_media = features.get("autoplay_media", {}) or {}

    # ── 1. Form action mismatch ────────────────────
    if forms.get("form_action_mismatch"):
        score += WEIGHTS["form_action_mismatch"]
        domains = forms.get("form_action_domains", [])
        target = domains[0] if domains else "an external domain"
        factors.append(f"Form submits to a different domain ({target})")

    # ── 2. Brand domain mismatch ───────────────────
    if brands.get("brand_domain_mismatch"):
        score += WEIGHTS["brand_domain_mismatch"]
        mentioned = brands.get("mentioned_brands", [])
        if mentioned:
            factors.append(f"Page mentions {mentioned[0].capitalize()} but domain is not the official site")

    # ── 3. Hidden iframes ──────────────────────────
    if iframes.get("hidden_iframes"):
        score += WEIGHTS["hidden_iframes"]
        factors.append("Hidden iframe detected (may be used for clickjacking or credential theft)")

    # ── 4. Credit card field ───────────────────────
    if forms.get("has_credit_card_field"):
        score += WEIGHTS["has_credit_card_field"]
        factors.append("Page contains credit card input fields")

    # ── 5. Hidden form inputs ──────────────────────
    hidden = forms.get("hidden_inputs", 0)
    if hidden > 2:
        score += WEIGHTS["excessive_hidden_inputs"]
        factors.append(f"Contains {hidden} hidden form inputs")

    # ── 6. External script ratio ───────────────────
    ratio = scripts.get("external_script_ratio", 0)
    if ratio > 0.70:
        score += WEIGHTS["high_external_script_ratio"]
        pct = round(ratio * 100)
        factors.append(f"{pct}% of scripts loaded from external domains")

    # ── 7. Many external script domains ────────────
    ext_count = len(scripts.get("external_script_domains", []))
    if ext_count > 5:
        score += WEIGHTS["many_external_domains"]
        factors.append(f"Resources loaded from {ext_count} different external domains")

    # ── 8. Password field (baseline signal) ────────
    if forms.get("has_password_field") and score < 0.05:
        score += WEIGHTS["has_password_field"]
        factors.append("Page contains a password input field")

    # ── 9. Suspicious ad network (popup / malvertising) ────
    suspicious_domains = ads.get("suspicious_ad_domains", [])
    if suspicious_domains:
        score += WEIGHTS["suspicious_ad_network"]
        networks = ", ".join(suspicious_domains[:3])
        if len(suspicious_domains) > 3:
            networks += f" and {len(suspicious_domains) - 3} more"
        factors.append(f"Page loads scripts from known ad networks ({networks})")

    # ── 10. Many different ad networks loaded ──────
    major_domains = ads.get("major_ad_domains", [])
    total_ad_networks = len(major_domains) + len(suspicious_domains)
    if total_ad_networks > 3 and not suspicious_domains:
        score += WEIGHTS["many_ad_networks"]
        factors.append(f"Page loads scripts from {total_ad_networks} different ad networks")

    # ── 11. Popup-style ad elements ────────────────
    if ad_elements.get("has_popup_ad"):
        score += WEIGHTS["popup_ad_elements"]
        count = ad_elements.get("popup_ad_count", 0)
        factors.append(f"Page contains {count} pop-up style ad element(s)")

    # ── 12. Oversized / sticky ad elements ─────────
    if ad_elements.get("oversized_ad") and not suspicious_domains:
        score += WEIGHTS["oversized_ad"]
        factors.append("Page contains an oversized ad element (>30% of viewport)")

    # ── 13. Auto-playing video ads (common in malvertising) ──
    if autoplay_media.get("has_autoplay_video_ad"):
        score += WEIGHTS["autoplay_video_ad"]
        count = autoplay_media.get("autoplay_video_count", 1)
        factors.append(f"Page has {count} auto-playing video ad(s) with sound")

    # ── Clamp score ────────────────────────────────
    score = max(0.0, min(1.0, score))

    # ── Risk level ─────────────────────────────────
    if score >= THRESHOLD_HIGH:
        level = "HIGH"
    elif score >= THRESHOLD_MEDIUM:
        level = "MEDIUM"
    elif score >= THRESHOLD_LOW:
        level = "LOW"
    else:
        level = "SAFE"

    return {
        "page_risk_score": round(score, 4),
        "page_risk_level": level,
        "page_risk_factors": factors,
    }
