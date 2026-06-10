// PhishVoider Warning Page — handles "Go Back" and "Ignore Risk" actions

function renderPageAnalysis(analysis) {
    const factors = analysis?.factors || [];
    if (!factors.length) return;

    const pageCard = document.getElementById("page-details-card");
    const pageList = document.getElementById("page-factors-list");
    const pageArrow = document.getElementById("page-details-arrow");
    const pageBody  = document.getElementById("page-details-body");

    pageList.innerHTML = "";
    factors.forEach((f) => {
        const li = document.createElement("li");
        li.textContent = f;
        pageList.appendChild(li);
    });
    pageCard.classList.remove("hidden");

    document.getElementById("page-details-toggle").addEventListener("click", () => {
        const isHidden = pageBody.classList.toggle("hidden");
        pageArrow.textContent = isHidden ? "▸" : "▾";
    });
}

function showFactors(result, tabId) {
    const data = (result.predictions || {})[tabId];
    if (!data) return;

    const isPhishing = parseInt(data.prediction) === 1;

    // URL risk factors
    const detailsCard = document.getElementById("details-card");
    const factorsList = document.getElementById("factors-list");
    const detailsArrow = document.getElementById("details-arrow");
    const detailsBody  = document.getElementById("details-body");

    const riskFactors = data.risk_factors || [];
    factorsList.innerHTML = "";
    if (isPhishing && riskFactors.length === 0) {
        const li = document.createElement("li");
        li.textContent = "Deceptive patterns detected by ML analysis";
        factorsList.appendChild(li);
    } else if (riskFactors.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No suspicious patterns detected";
        factorsList.appendChild(li);
    } else {
        riskFactors.forEach((factor) => {
            const li = document.createElement("li");
            li.textContent = factor;
            factorsList.appendChild(li);
        });
    }
    detailsCard.classList.remove("hidden");

    document.getElementById("details-toggle").addEventListener("click", () => {
        const isHidden = detailsBody.classList.toggle("hidden");
        detailsArrow.textContent = isHidden ? "▸" : "▾";
    });

    // Page content analysis factors
    if (data.page_analysis) {
        renderPageAnalysis(data.page_analysis);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const domainEl   = document.getElementById("warning-domain");
    const riskEl     = document.getElementById("warning-risk");
    const confEl     = document.getElementById("warning-confidence");
    const goBackBtn  = document.getElementById("go-back-btn");
    const ignoreBtn  = document.getElementById("ignore-btn");
    const confirmBox = document.getElementById("ignore-confirm");
    const confirmBtn = document.getElementById("confirm-ignore-btn");
    const allowBtn   = document.getElementById("allow-btn");

    // Read blocked URL from URL params
    const params = new URLSearchParams(window.location.search);
    const blockedUrl  = params.get("url") || "";
    const riskLevel   = params.get("risk") || "HIGH";
    const confidence  = params.get("confidence") || "0";
    const previousUrl = params.get("prev") || "";

    // Show details
    try {
        const urlObj = new URL(blockedUrl);
        domainEl.textContent = urlObj.hostname;
    } catch {
        domainEl.textContent = blockedUrl || "Unknown";
    }
    riskEl.textContent = riskLevel;
    confEl.textContent = confidence + "%";

    // Load risk factors + page analysis from stored prediction
    chrome.storage.local.get(["predictions"], (result) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tabId = tabs[0]?.id;
            if (!tabId) return;
            showFactors(result, tabId);

            // Watch for late-arriving page analysis data
            chrome.storage.onChanged.addListener(function onChanged(changes, area) {
                if (area !== "local" || !changes.predictions) return;
                const newData = (changes.predictions.newValue || {})[tabId];
                const pageCard = document.getElementById("page-details-card");
                if (newData?.page_analysis && pageCard?.classList.contains("hidden")) {
                    renderPageAnalysis(newData.page_analysis);
                    chrome.storage.onChanged.removeListener(onChanged);
                }
            });
        });
    });

    // ─── Go Back ──────────────────────────────────────────
    goBackBtn.addEventListener("click", () => {
        const targetUrl = previousUrl || "about:blank";
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]?.id) {
                chrome.tabs.update(tabs[0].id, { url: targetUrl });
            }
        });
    });

    // ─── Ignore Risk (requires confirmation) ──────────────
    ignoreBtn.addEventListener("click", () => {
        confirmBox.classList.remove("hidden");
        ignoreBtn.disabled = true;
        ignoreBtn.style.opacity = "0.5";
    });

    confirmBtn.addEventListener("click", () => {
        // Add domain to session bypass so it doesn't re-block
        if (blockedUrl) {
            try {
                const urlObj = new URL(blockedUrl);
                const domain = urlObj.hostname.replace(/^www\./, "").toLowerCase();

                chrome.storage.local.get(["bypassedDomains"], (result) => {
                    let bypassed = result.bypassedDomains || [];
                    const alreadyExists = bypassed.some((e) => {
                        const d = typeof e === "string" ? e : e.domain;
                        return d === domain;
                    });
                    if (!alreadyExists) {
                        bypassed.push({ domain, bypassedAt: new Date().toISOString() });
                        chrome.storage.local.set({ bypassedDomains: bypassed });
                    }
                });
            } catch (_) {}
        }

        // Navigate to the blocked URL (replace history so back button skips warning)
        if (blockedUrl) window.location.replace(blockedUrl);
    });

    // ─── Always Allow (permanent whitelist) ──────────────
    allowBtn.addEventListener("click", () => {
        if (blockedUrl) {
            try {
                const urlObj = new URL(blockedUrl);
                const domain = urlObj.hostname.replace(/^www\./, "").toLowerCase();

                chrome.storage.local.get(["userWhitelist"], (result) => {
                    let whitelist = result.userWhitelist || [];
                    if (!whitelist.includes(domain)) {
                        whitelist.push(domain);
                        chrome.storage.local.set({ userWhitelist: whitelist });
                    }
                });
            } catch (_) {}
        }

        // Navigate to the blocked URL (replace history so back button skips warning)
        if (blockedUrl) window.location.replace(blockedUrl);
    });
});
