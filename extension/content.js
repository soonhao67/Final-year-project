// PhishVoider Page Content Analyzer
// Extracts DOM-level features for phishing detection

(function () {
  const BRAND_KEYWORDS = [
    "paypal", "google", "gmail", "facebook", "instagram", "microsoft",
    "apple", "netflix", "amazon", "linkedin", "twitter", "whatsapp",
    "yahoo", "dropbox", "adobe", "zoom", "chase", "bank of america",
    "wells fargo", "hsbc", "coinbase", "binance", "steam", "ebay",
    "shopify", "tiktok", "snapchat", "telegram", "discord", "reddit",
    "spotify", "twitch", "outlook", "office 365", "microsoft 365",
    "american express", "visa", "mastercard", "paypal.com",
    "icloud", "protonmail", "samsung", "huawei", "xiaomi"
  ];

  // Ad network domains used to detect ad-supported pages and malvertising
  const AD_NETWORK_DOMAINS = {
    major: [
      "doubleclick.net", "googlesyndication.com", "googleadservices.com",
      "google-analytics.com", "googletagmanager.com", "googletagservices.com",
      "amazon-adsystem.com", "adnxs.com", "rubiconproject.com",
      "openx.net", "pubmatic.com", "criteo.com", "casalemedia.com",
      "indexww.com", "adsrvr.org", "sharethrough.com", "sovrn.com",
      "taboola.com", "outbrain.com", "revcontent.com",
    ],
    suspicious: [
      "popads.net", "popcash.net", "adcash.com", "propellerads.com",
      "mgid.com", "exosrv.com", "adskeeper.co.uk", "adsterra.com",
      "clickadu.com", "adreactor.com", "adbooth.com",
      "trafficfactory.biz", "ad-maven.com", "onclickads.net",
      "adbucks.com", "pushcrew.com", "ntvcld.com",
    ],
  };

  const AD_CLASS_KEYWORDS = [
    "ad", "ads", "advertisement", "ad-container", "ad-slot", "ad-unit",
    "advert", "adbox", "adwrap", "banner_ad", "sponsored", "sponsor",
    "google_ads", "dfp-ad", "dfp-tag", "popup", "pop-under",
    "sticky-ad", "sticky_ads", "floating-ad", "adhesion",
  ];

  function getPageDomain() {
    try { return window.location.hostname.replace(/^www\./, "").toLowerCase(); }
    catch (e) { return ""; }
  }

  // ─── Form Analysis ──────────────────────────────
  function analyzeForms() {
    const forms = document.querySelectorAll("form");
    if (forms.length === 0) return null;

    let hasPassword = false;
    let hasCC = false;
    let totalInputs = 0;
    let hiddenInputs = 0;
    let formActionMismatch = false;
    let actionDomains = [];

    const pageDomain = getPageDomain();

    forms.forEach((f) => {
      const inputs = f.querySelectorAll("input, select, textarea");
      totalInputs += inputs.length;

      inputs.forEach((inp) => {
        const t = (inp.type || "").toLowerCase();
        if (t === "password") hasPassword = true;
        if (t === "hidden") hiddenInputs++;
      });

      inputs.forEach((inp) => {
        const name = (inp.name || inp.id || "").toLowerCase();
        const placeholder = (inp.placeholder || "").toLowerCase();
        const pattern = (inp.getAttribute("pattern") || "").toLowerCase();
        if (
          /card|cc|cvv|cvc|credit.?card/.test(name + placeholder + pattern)
        ) {
          hasCC = true;
        }
      });

      let action = (f.getAttribute("action") || "").trim();
      if (action && action !== "#" && action !== "javascript:void(0)") {
        try {
          const resolved = new URL(action, window.location.href);
          const actionDomain = resolved.hostname.replace(/^www\./, "").toLowerCase();
          actionDomains.push(actionDomain);
          if (actionDomain && actionDomain !== pageDomain) {
            formActionMismatch = true;
          }
        } catch (_) {}
      }
    });

    return {
      has_password_field: hasPassword,
      has_credit_card_field: hasCC,
      total_inputs: totalInputs,
      hidden_inputs: hiddenInputs,
      form_action_mismatch: formActionMismatch,
      form_action_domains: actionDomains,
    };
  }

  // ─── Brand Detection ────────────────────────────
  function detectBrands() {
    const pageDomain = getPageDomain();
    const bodyText = (document.body ? document.body.innerText || "" : "").toLowerCase();
    const title = (document.title || "").toLowerCase();
    const fullText = title + " " + bodyText;

    const found = [];
    for (const brand of BRAND_KEYWORDS) {
      if (fullText.includes(brand)) {
        found.push(brand);
      }
    }

    const unique = [...new Set(found)].slice(0, 5);

    let brandMismatch = false;
    const brandDomains = [
      { label: "paypal",          domain: "paypal.com" },
      { label: "google",          domain: "google.com" },
      { label: "facebook",        domain: "facebook.com" },
      { label: "instagram",       domain: "instagram.com" },
      { label: "microsoft",       domain: "microsoft.com" },
      { label: "apple",           domain: "apple.com" },
      { label: "netflix",         domain: "netflix.com" },
      { label: "amazon",          domain: "amazon.com" },
      { label: "linkedin",        domain: "linkedin.com" },
      { label: "twitter",         domain: "twitter.com" },
      { label: "whatsapp",        domain: "whatsapp.com" },
      { label: "yahoo",           domain: "yahoo.com" },
      { label: "dropbox",         domain: "dropbox.com" },
      { label: "zoom",            domain: "zoom.us" },
      { label: "coinbase",        domain: "coinbase.com" },
      { label: "binance",         domain: "binance.com" },
      { label: "steam",           domain: "steampowered.com" },
      { label: "ebay",            domain: "ebay.com" },
      { label: "shopify",         domain: "shopify.com" },
      { label: "reddit",          domain: "reddit.com" },
      { label: "spotify",         domain: "spotify.com" },
      { label: "twitch",          domain: "twitch.tv" },
      { label: "paypal.com",      domain: "paypal.com" },
      { label: "icloud",          domain: "icloud.com" },
      { label: "samsung",         domain: "samsung.com" },
    ];

    for (const b of brandDomains) {
      if (unique.includes(b.label) && pageDomain !== b.domain) {
        if (!pageDomain.endsWith("." + b.domain) && pageDomain !== b.domain) {
          brandMismatch = true;
          break;
        }
      }
    }

    return {
      mentioned_brands: unique,
      brand_domain_mismatch: brandMismatch,
    };
  }

  // ─── Iframe Analysis ────────────────────────────
  function analyzeIframes() {
    const iframes = document.querySelectorAll("iframe");
    if (iframes.length === 0) return { has_iframe: false, hidden_iframes: false };

    let hidden = false;
    iframes.forEach((f) => {
      const w = f.offsetWidth || parseInt(f.getAttribute("width") || "0", 10);
      const h = f.offsetHeight || parseInt(f.getAttribute("height") || "0", 10);
      const style = window.getComputedStyle(f);
      if (
        w <= 1 || h <= 1 ||
        style.display === "none" ||
        style.visibility === "hidden" ||
        style.opacity === "0" ||
        f.getAttribute("aria-hidden") === "true"
      ) {
        hidden = true;
      }
    });

    return { has_iframe: true, hidden_iframes: hidden };
  }

  // ─── Script Analysis ────────────────────────────
  function analyzeScripts() {
    const scripts = document.querySelectorAll("script[src]");
    const pageDomain = getPageDomain();
    let external = 0;
    const externalDomains = new Set();

    scripts.forEach((s) => {
      const src = s.getAttribute("src");
      if (!src) return;
      try {
        const url = new URL(src, window.location.href);
        const domain = url.hostname.replace(/^www\./, "").toLowerCase();
        if (domain && domain !== pageDomain) {
          external++;
          externalDomains.add(domain);
        }
      } catch (_) {}
    });

    const total = scripts.length;
    return {
      external_scripts: external,
      total_scripts: total,
      external_script_ratio: total > 0 ? external / total : 0,
      external_script_domains: [...externalDomains],
    };
  }

  // ─── Malicious Ad Detection ─────────────────────

  // Detect scripts loaded from known ad network domains
  function detectAdNetworks() {
    const scripts = document.querySelectorAll("script[src]");
    const pageDomain = getPageDomain();
    let majorCount = 0;
    let suspiciousCount = 0;
    const majorDomains = new Set();
    const suspiciousDomains = new Set();

    scripts.forEach((s) => {
      const src = s.getAttribute("src");
      if (!src) return;
      try {
        const url = new URL(src, window.location.href);
        const domain = url.hostname.replace(/^www\./, "").toLowerCase();
        if (!domain || domain === pageDomain) return;

        if (AD_NETWORK_DOMAINS.major.includes(domain)) {
          majorCount++;
          majorDomains.add(domain);
        }
        if (AD_NETWORK_DOMAINS.suspicious.includes(domain)) {
          suspiciousCount++;
          suspiciousDomains.add(domain);
        }
      } catch (_) {}
    });

    return {
      major_ad_domains: [...majorDomains],
      suspicious_ad_domains: [...suspiciousDomains],
      major_ad_script_count: majorCount,
      suspicious_ad_script_count: suspiciousCount,
    };
  }

  // Detect DOM elements that look like ads (popups, banners, injected containers)
  function detectAdElements() {
    let popupAdCount = 0;
    let adClassElements = 0;
    let adElementHeight = 0;
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;

    // Check all divs/sections for ad-like patterns
    const allElements = document.querySelectorAll("div, section, aside, ins");
    for (const el of allElements) {
      const style = window.getComputedStyle(el);
      const classes = (el.className || "").toLowerCase();
      const elId = (el.id || "").toLowerCase();
      const combinedIds = classes + " " + elId;

      // Check CSS class/ID for ad keywords
      if (AD_CLASS_KEYWORDS.some((kw) => combinedIds.includes(kw))) {
        adClassElements++;
        const h = el.offsetHeight;
        if (h > adElementHeight) adElementHeight = h;
      }

      // Detect pop-up style ads: fixed position, mid-to-high z-index, prominent on page
      if (style.position === "fixed" || style.position === "absolute") {
        const zIdx = parseInt(style.zIndex);
        if (zIdx >= 100 && zIdx < 10000) {
          const text = (el.textContent || "").toLowerCase();
          // Likely an ad if it has common ad link text but not scam phrases
          const hasAdText =
            /\b(ad|sponsored|promoted|recommended|advertisement)\b/.test(classes + " " + elId);
          const isSmall = el.offsetWidth <= 400 && el.offsetHeight <= 400;
          if (hasAdText || isSmall) {
            popupAdCount++;
          }
        }
      }
    }

    return {
      has_popup_ad: popupAdCount > 0,
      popup_ad_count: popupAdCount,
      ad_class_element_count: adClassElements,
      max_ad_element_height: adElementHeight,
      oversized_ad: viewportHeight > 0 && adElementHeight > viewportHeight * 0.3,
    };
  }

  // Detect auto-playing video/audio ads (common in malvertising)
  function detectAutoPlayMedia() {
    let autoPlayVideoCount = 0;
    let autoPlayAudioCount = 0;

    const videos = document.querySelectorAll("video");
    videos.forEach((v) => {
      if (v.autoplay && !v.muted) {
        autoPlayVideoCount++;
      }
    });

    const audios = document.querySelectorAll("audio");
    audios.forEach((a) => {
      if (a.autoplay) {
        autoPlayAudioCount++;
      }
    });

    return {
      has_autoplay_video_ad: autoPlayVideoCount > 0,
      autoplay_video_count: autoPlayVideoCount,
      has_autoplay_audio: autoPlayAudioCount > 0,
    };
  }

  // ─── Main Extraction ────────────────────────────
  function extractFeatures() {
    const pageDomain = getPageDomain();
    if (!pageDomain) return null;

    const forms      = analyzeForms();
    const brands     = detectBrands();
    const iframes    = analyzeIframes();
    const scripts    = analyzeScripts();
    const adNetworks = detectAdNetworks();
    const adElements = detectAdElements();
    const autoMedia  = detectAutoPlayMedia();

    const hasSignal =
      (forms && (forms.has_password_field || forms.form_action_mismatch || forms.hidden_inputs > 2)) ||
      brands.brand_domain_mismatch ||
      iframes.hidden_iframes ||
      scripts.external_scripts > 5 ||
      adNetworks.suspicious_ad_script_count > 0 ||
      adNetworks.major_ad_domains.length > 3 ||
      adElements.has_popup_ad ||
      adElements.ad_class_element_count > 5 ||
      autoMedia.has_autoplay_video_ad;

    if (!hasSignal) return null;

    return {
      url: window.location.href,
      page_domain: pageDomain,
      forms: forms || { has_password_field: false, has_credit_card_field: false, total_inputs: 0, hidden_inputs: 0, form_action_mismatch: false, form_action_domains: [] },
      brands: brands,
      iframes: iframes,
      scripts: scripts,
      ads: adNetworks,
      ad_elements: adElements,
      autoplay_media: autoMedia,
    };
  }

  const features = extractFeatures();
  if (features) {
    chrome.runtime.sendMessage(
      { type: "PAGE_FEATURES", data: features },
      () => { /* fire-and-forget */ }
    );
  }
})();
