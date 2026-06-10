// Track previous URL per tab — used by warning.html "Go Back" button
const tabNavHistory = {};

// Bypassed domains expire after 24 hours
const BYPASS_EXPIRY_MS = 24 * 60 * 60 * 1000;

// Get the domain string from a bypassed entry (handles both old string and new object format)
function getBypassDomain(entry) {
    return typeof entry === "string" ? entry : entry.domain;
}

// Check and clean up expired bypassed entries in-place
function filterExpiredBypasses(bypassed) {
    const now = Date.now();
    return bypassed.filter((entry) => {
        if (typeof entry === "string") return true; // old format, keep
        return now - new Date(entry.bypassedAt).getTime() < BYPASS_EXPIRY_MS;
    });
}

// Store a tab's prediction data in the per-tab map (merges with existing data)
function storePrediction(tabId, data) {
    chrome.storage.local.get(["predictions"], (result) => {
        const predictions = result.predictions || {};
        predictions[tabId] = { ...(predictions[tabId] || {}), ...data };
        chrome.storage.local.set({ predictions });
    });
}

// Clean up prediction data when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.local.get(["predictions"], (result) => {
        const predictions = result.predictions || {};
        if (predictions[tabId]) {
            delete predictions[tabId];
            chrome.storage.local.set({ predictions });
        }
    });
});

// ─── Page Content Analysis ─────────────────────────
// Receives DOM features from content.js, sends to backend for scoring.
// Results are stored in predictions[tabId].page_analysis for display in the popup.
chrome.runtime.onMessage.addListener((message, sender) => {
    if (message.type !== "PAGE_FEATURES" || !sender.tab) return;
    
    const tabId = sender.tab.id;
    const features = message.data;
    
    chrome.storage.local.get(["apiUrl"], (result) => {
        const apiUrl = (result.apiUrl || "http://127.0.0.1:5000").replace(/\/+$/, "");
        
        fetch(apiUrl + "/analyze-page", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(features)
        })
        .then(r => r.json())
        .then(pageResult => {
            chrome.storage.local.get(["predictions"], (store) => {
                const predictions = store.predictions || {};
                const existing = predictions[tabId] || {};

                existing.page_analysis = {
                    score: pageResult.page_risk_score,
                    level: pageResult.page_risk_level,
                    factors: pageResult.page_risk_factors
                };

                predictions[tabId] = existing;
                chrome.storage.local.set({ predictions });

                // Store page analysis data for popup display only
                if (pageResult.page_risk_level === "HIGH" || pageResult.page_risk_level === "MEDIUM") {
                    chrome.action.setIcon({
                        tabId: tabId,
                        path: {
                            "16": "/icon-default.png",
                            "48": "/icon-default.png",
                            "128": "/icon-default.png"
                        }
                    }, () => { let e = chrome.runtime.lastError; if(e) console.error(e); });
                }
            });
        })
        .catch(err => console.error("Page analysis error:", err));
    });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
        console.log(`Checking URL: ${tab.url}`);

        // Store the previous URL before updating for next navigation
        const previousUrl = tabNavHistory[tabId] || null;
        tabNavHistory[tabId] = tab.url;

        try {
            const urlObj = new URL(tab.url);
            let domain = urlObj.hostname.toLowerCase();
            if (domain.startsWith("www.")) {
                domain = domain.substring(4);
            }

            // Bypass localhost/127.0.0.1 — don't scan the backend itself
            if (domain === "127.0.0.1" || domain === "localhost") {
                storePrediction(tabId, {
                    url: tab.url, domain: domain, prediction: 0,
                    label: "safe", safe_probability: 1.0,
                    phishing_probability: 0.0, risk_level: "SAFE",
                    reason: "Local server (bypassed)",
                    _meta_previousUrl: previousUrl || ""
                });
                chrome.action.setIcon({ tabId: tabId, path: { "16": "/icon-safe.png", "48": "/icon-safe.png", "128": "/icon-safe.png" } }, () => { let e = chrome.runtime.lastError; if(e) console.error(e); });
                return;
            }

            // 1. Check Whitelist + Bypassed Domains + Read API URL
            chrome.storage.local.get(["userWhitelist", "bypassedDomains", "apiUrl"], (result) => {
                const whitelist = result.userWhitelist || [];
                let bypassed  = result.bypassedDomains || [];
                const apiUrl = (result.apiUrl || "http://127.0.0.1:5000").replace(/\/+$/, "");

                // Filter out expired bypasses before checking
                bypassed = filterExpiredBypasses(bypassed);
                chrome.storage.local.set({ bypassedDomains: bypassed });

                // Skip if whitelisted or user has bypassed the warning
                if (whitelist.includes(domain) || bypassed.some((e) => getBypassDomain(e) === domain)) {
                    console.log(`Domain ${domain} is whitelisted/bypassed. Skipping API.`);
                    
                    const safeData = {
                        url: tab.url,
                        domain: domain,
                        prediction: 0,
                        label: "safe",
                        safe_probability: 1.0,
                        phishing_probability: 0.0,
                        risk_level: "SAFE",
                        reason: "User Whitelisted",
                        _meta_previousUrl: previousUrl || ""
                    };

                    storePrediction(tabId, safeData);
                    chrome.action.setIcon({ 
                        tabId: tabId, 
                        path: {
                            "16": "/icon-safe.png", 
                            "48": "/icon-safe.png", 
                            "128": "/icon-safe.png"
                        } 
                    }, () => { 
                        let err = chrome.runtime.lastError; 
                        if(err) console.error(err);
                    });
                    return; // Stop here, don't call backend
                }

                // 2. Not in bypass list, call backend API
                fetchBackendAPI(tab.url, tabId, apiUrl, previousUrl, tab);
            });

        } catch (e) {
            console.error("Invalid URL:", e);
        }
    }
});

function fetchBackendAPI(url, tabId, apiUrl, previousUrl, tab) {
    fetch(apiUrl + "/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        console.log("Backend response:", data);
        
        data._meta_previousUrl = previousUrl || "";
        storePrediction(tabId, data);
        const isPhishing = parseInt(data.prediction) === 1;
        const iconPath = isPhishing ? "/icon-danger.png" : "/icon-safe.png";
        
        chrome.action.setIcon({ 
            tabId: tabId, 
            path: {
                "16": iconPath, 
                "48": iconPath, 
                "128": iconPath
            } 
        }, () => { 
            let err = chrome.runtime.lastError; 
            if (err) console.error("Icon Error:", err.message);
        });

        if (isPhishing) {
            // Show notification
            chrome.notifications.create({
                type: "basic",
                iconUrl: "icon-danger.png",
                title: "PhishVoider Warning",
                message: "⚠️ Potential phishing website detected!"
            });

            // BLOCK the page — redirect to warning interstitial
            const riskLevel = data.risk_level || "HIGH";
            const confidence = data.phishing_probability
                ? (data.phishing_probability * 100).toFixed(1)
                : "0";

            let warningUrl = chrome.runtime.getURL("warning.html") +
                "?url=" + encodeURIComponent(url) +
                "&risk=" + encodeURIComponent(riskLevel) +
                "&confidence=" + encodeURIComponent(confidence);
            if (previousUrl) {
                warningUrl += "&prev=" + encodeURIComponent(previousUrl);
            }
            chrome.tabs.update(tabId, { url: warningUrl });
        }
    })
    .catch(err => console.error("Error fetching prediction:", err));
}
