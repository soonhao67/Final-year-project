document.addEventListener("DOMContentLoaded", () => {
    const body = document.getElementById("app-body");
    const loadingView = document.getElementById("loading-view");
    const loadingText = document.getElementById("loading-text");
    const resultView = document.getElementById("result-view");
    const statusIcon = document.getElementById("status-icon");
    const statusTitle = document.getElementById("status-title");
    const statusUrl = document.getElementById("status-url");
    const confidenceValue = document.getElementById("confidence-value");
    const confidenceFill = document.getElementById("confidence-fill");
    const whitelistBtn = document.getElementById("whitelist-btn");
    const detailsToggle = document.getElementById("details-toggle");
    const detailsPanel = document.getElementById("details-panel");
    const factorsList = document.getElementById("factors-list");
    const pageToggle = document.getElementById("page-toggle");
    const pagePanel = document.getElementById("page-panel");
    const pageFactorsList = document.getElementById("page-factors-list");
    let currentDomain = "";
    let currentTabId = null;

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0]?.id) {
            loadingText.innerText = "Could not identify the current tab.";
            document.querySelector(".spinner").style.display = "none";
            return;
        }
        currentTabId = tabs[0].id;

        chrome.storage.local.get(["predictions"], (result) => {
            const predictions = result.predictions || {};
            const data = predictions[currentTabId];

            if (!data || data.error) {
                loadingText.innerText = data
                    ? "Error: " + data.error
                    : "This page hasn't been analyzed yet. Reload the page to scan it.";
                document.querySelector(".spinner").style.display = "none";
                console.error("No prediction data for tab", currentTabId, data);
                return;
            }

            currentDomain = data.domain || "Unknown Domain";
            const isPhishing = parseInt(data.prediction) === 1;
            const confidence = isPhishing ? data.phishing_probability : data.safe_probability;
            const confidencePercent = confidence !== undefined ? (confidence * 100).toFixed(1) : 0;
            
            loadingView.classList.remove("active");
            resultView.classList.add("active");
            statusUrl.innerText = currentDomain;
            confidenceValue.innerText = `${confidencePercent}%`;
            
            setTimeout(() => { confidenceFill.style.width = `${confidencePercent}%`; }, 100);

            if (isPhishing) {
                body.classList.add("theme-danger");
                statusIcon.innerText = "⚠️";
                statusTitle.innerText = "Phishing Detected!";
                whitelistBtn.classList.remove("hidden");
            } else {
                body.classList.add("theme-safe");
                statusTitle.innerText = data.reason === "User Whitelisted" ? "Whitelisted Site" : "Safe Website";
                whitelistBtn.classList.add("hidden");
            }

            // Populate prediction breakdown
            const riskFactors = data.risk_factors || [];
            factorsList.innerHTML = "";
            if (isPhishing && riskFactors.length === 0) {
                const li = document.createElement("li");
                li.textContent = "Deceptive patterns detected by ML analysis";
                factorsList.appendChild(li);
            } else if (riskFactors.length === 0) {
                const li = document.createElement("li");
                li.className = "safe-factor";
                li.textContent = "No suspicious patterns detected";
                factorsList.appendChild(li);
            } else {
                riskFactors.forEach((factor) => {
                    const li = document.createElement("li");
                    li.textContent = factor;
                    factorsList.appendChild(li);
                });
            }

            // ─── Page Analysis ──────────────────────
            const pageAnalysis = data.page_analysis;
            if (pageAnalysis && pageAnalysis.factors && pageAnalysis.factors.length > 0) {
                pageFactorsList.innerHTML = "";
                pageAnalysis.factors.forEach((factor) => {
                    const li = document.createElement("li");
                    li.textContent = factor;
                    pageFactorsList.appendChild(li);
                });
                pageToggle.classList.remove("hidden");
                pageToggle.textContent = "Page Content Analysis result ▾";

                // If URL was safe but page analysis found risk, update display
                if (!isPhishing && (pageAnalysis.level === "HIGH" || pageAnalysis.level === "MEDIUM")) {
                    statusTitle.textContent += " (Suspicious Page)";
                    body.classList.add("theme-warning");
                    statusIcon.innerText = "🔍";
                    whitelistBtn.classList.remove("hidden");
                }
            }
        });
    });

    // Details toggle
    detailsToggle.addEventListener("click", () => {
        const isHidden = detailsPanel.classList.contains("hidden");
        detailsPanel.classList.toggle("hidden");
        detailsToggle.innerText = isHidden ? "URL Analysis result ▴" : "URL Analysis result ▾";
    });

    // Page Analysis toggle
    pageToggle.addEventListener("click", () => {
        const isHidden = pagePanel.classList.contains("hidden");
        pagePanel.classList.toggle("hidden");
        pageToggle.textContent = isHidden ? "Page Content Analysis result ▴" : "Page Content Analysis result ▾";
    });

    document.getElementById("settings-btn").addEventListener("click", () => {
        chrome.runtime.openOptionsPage();
    });

    whitelistBtn.addEventListener("click", () => {
        if (!currentDomain) return;
        chrome.storage.local.get(["userWhitelist"], (result) => {
            let whitelist = result.userWhitelist || [];
            if (!whitelist.includes(currentDomain)) {
                whitelist.push(currentDomain);
                chrome.storage.local.set({ userWhitelist: whitelist }, () => {
                    whitelistBtn.innerText = "Whitelisted!";
                    whitelistBtn.style.backgroundColor = "var(--success-bg)";
                    whitelistBtn.style.color = "var(--success-color)";
                    whitelistBtn.style.borderColor = "var(--success-color)";
                    whitelistBtn.disabled = true;

                    // Update the cached prediction so re-opening shows "Whitelisted Site"
                    chrome.storage.local.get(["predictions"], (predResult) => {
                        const predictions = predResult.predictions || {};
                        let data = predictions[currentTabId];
                        if (data) {
                            data.prediction = 0; data.label = "safe"; data.safe_probability = 1.0;
                            data.phishing_probability = 0.0; data.risk_level = "SAFE"; data.reason = "User Whitelisted";
                            predictions[currentTabId] = data;
                            chrome.storage.local.set({ predictions });
                            statusTitle.innerText = "Whitelisted Site";
                            body.classList.remove("theme-danger", "theme-warning");
                            body.classList.add("theme-safe");
                            statusIcon.innerText = "✅";
                        }
                    });
                });
            }
        });
    });
});
