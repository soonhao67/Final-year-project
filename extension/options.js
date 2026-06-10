// === PhishVoider Options Page ===

document.addEventListener("DOMContentLoaded", () => {
    const apiUrlInput      = document.getElementById("api-url");
    const testBtn          = document.getElementById("test-btn");
    const saveUrlBtn       = document.getElementById("save-url-btn");
    const connectionStatus = document.getElementById("connection-status");

    const whitelistList    = document.getElementById("whitelist-list");
    const whitelistEmpty   = document.getElementById("whitelist-empty");
    const domainInput      = document.getElementById("domain-input");
    const addDomainBtn     = document.getElementById("add-domain-btn");

    const bypassList       = document.getElementById("bypass-list");
    const bypassEmpty      = document.getElementById("bypass-empty");
    const clearBypassBtn   = document.getElementById("clear-bypass-btn");

    const statsLoading     = document.getElementById("stats-loading");
    const statsContent     = document.getElementById("stats-content");
    const statTotal        = document.getElementById("stat-total");
    const statPhishing     = document.getElementById("stat-phishing");
    const statSafe         = document.getElementById("stat-safe");

    const historyLoading   = document.getElementById("history-loading");
    const historyContent   = document.getElementById("history-content");
    const historyBody      = document.getElementById("history-body");
    const historyEmpty     = document.getElementById("history-empty");
    const historySummary   = document.getElementById("history-summary");

    let currentApiUrl = "http://127.0.0.1:5000";

    // =============================================
    // Load saved settings
    // =============================================
    chrome.storage.local.get(["apiUrl"], (result) => {
        if (result.apiUrl) {
            currentApiUrl = result.apiUrl;
            apiUrlInput.value = currentApiUrl;
        } else {
            apiUrlInput.value = currentApiUrl;
        }
    });

    // =============================================
    // API URL - Save
    // =============================================
    saveUrlBtn.addEventListener("click", () => {
        const url = apiUrlInput.value.trim().replace(/\/+$/, "");
        if (!url) {
            setConnectionStatus("Please enter a URL.", "error");
            return;
        }
        currentApiUrl = url;
        chrome.storage.local.set({ apiUrl: url }, () => {
            setConnectionStatus("API URL saved successfully!", "success");
        });
    });

    // =============================================
    // API URL - Test Connection
    // =============================================
    testBtn.addEventListener("click", async () => {
        const url = apiUrlInput.value.trim().replace(/\/+$/, "");
        if (!url) {
            setConnectionStatus("Please enter a URL first.", "error");
            return;
        }
        testBtn.disabled = true;
        testBtn.innerText = "Testing...";
        setConnectionStatus("Testing connection...", "");

        try {
            const response = await fetch(url + "/", { signal: AbortSignal.timeout(5000) });
            const text = await response.text();
            if (text.includes("PhishVoider")) {
                setConnectionStatus("✅ Connected — PhishVoider backend is running.", "success");
                currentApiUrl = url;
            } else {
                setConnectionStatus("⚠️  Server responded, but it may not be PhishVoider.", "error");
            }
        } catch (err) {
            setConnectionStatus("❌ Connection failed — " + err.message, "error");
        } finally {
            testBtn.disabled = false;
            testBtn.innerText = "Test";
        }
    });

    function setConnectionStatus(msg, type) {
        connectionStatus.textContent = msg;
        connectionStatus.className = "status-msg" + (type ? " " + type : "");
    }

    // =============================================
    // Whitelist - Render
    // =============================================
    function renderWhitelist(whitelist) {
        whitelistList.innerHTML = "";
        if (!whitelist || whitelist.length === 0) {
            whitelistEmpty.classList.remove("hidden");
            return;
        }
        whitelistEmpty.classList.add("hidden");

        whitelist.forEach((domain) => {
            const li = document.createElement("li");
            li.innerHTML = `
                <span class="domain-name">${escapeHtml(domain)}</span>
                <button class="btn btn-danger remove-btn" data-domain="${escapeHtml(domain)}">Remove</button>
            `;
            whitelistList.appendChild(li);
        });

        // Attach remove handlers
        document.querySelectorAll(".remove-btn").forEach((btn) => {
            btn.addEventListener("click", () => {
                const domain = btn.getAttribute("data-domain");
                removeFromWhitelist(domain);
            });
        });
    }

    function loadWhitelist() {
        chrome.storage.local.get(["userWhitelist"], (result) => {
            renderWhitelist(result.userWhitelist || []);
        });
    }

    function removeFromWhitelist(domain) {
        chrome.storage.local.get(["userWhitelist"], (result) => {
            let whitelist = result.userWhitelist || [];
            whitelist = whitelist.filter((d) => d !== domain);
            chrome.storage.local.set({ userWhitelist: whitelist }, () => {
                renderWhitelist(whitelist);
            });
        });
    }

    // =============================================
    // Whitelist - Add Domain
    // =============================================
    addDomainBtn.addEventListener("click", () => {
        let domain = domainInput.value.trim().toLowerCase();
        if (!domain) return;

        // Strip protocol and path if user pasted a full URL
        try {
            if (domain.startsWith("http")) {
                domain = new URL(domain).hostname;
            }
        } catch (_) {}

        // Remove www.
        if (domain.startsWith("www.")) {
            domain = domain.substring(4);
        }

        chrome.storage.local.get(["userWhitelist"], (result) => {
            let whitelist = result.userWhitelist || [];
            if (!whitelist.includes(domain)) {
                whitelist.push(domain);
                chrome.storage.local.set({ userWhitelist: whitelist }, () => {
                    renderWhitelist(whitelist);
                    domainInput.value = "";
                });
            } else {
                domainInput.value = "";
            }
        });
    });

    domainInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") addDomainBtn.click();
    });

    // =============================================
    // Bypassed Domains - Render
    // =============================================
    const BYPASS_EXPIRY_MS = 24 * 60 * 60 * 1000;

    function getBypassDomain(entry) {
        return typeof entry === "string" ? entry : entry.domain;
    }

    function formatTimeSince(isoString) {
        const diff = Date.now() - new Date(isoString).getTime();
        const mins = Math.floor(diff / 60000);
        if (mins < 1) return "just now";
        if (mins < 60) return mins + "m ago";
        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return hrs + "h ago";
        const days = Math.floor(hrs / 24);
        return days + "d ago";
    }

    function formatTimeRemaining(isoString) {
        const elapsed = Date.now() - new Date(isoString).getTime();
        const remaining = BYPASS_EXPIRY_MS - elapsed;
        if (remaining <= 0) return "expired";
        const mins = Math.floor(remaining / 60000);
        if (mins < 60) return "expires in " + mins + "m";
        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return "expires in " + hrs + "h";
        const days = Math.floor(hrs / 24);
        return "expires in " + days + "d";
    }

    function renderBypassList(bypassed) {
        bypassList.innerHTML = "";
        if (!bypassed || bypassed.length === 0) {
            bypassEmpty.classList.remove("hidden");
            clearBypassBtn.classList.add("hidden");
            return;
        }
        bypassEmpty.classList.add("hidden");
        clearBypassBtn.classList.remove("hidden");

        bypassed.forEach((entry) => {
            const domain = getBypassDomain(entry);
            const li = document.createElement("li");

            let metaHtml = "";
            if (typeof entry === "object" && entry.bypassedAt) {
                metaHtml = `<div class="bypass-meta">${escapeHtml(formatTimeSince(entry.bypassedAt))} · ${escapeHtml(formatTimeRemaining(entry.bypassedAt))}</div>`;
            } else {
                metaHtml = `<div class="bypass-meta">Legacy entry (no expiry)</div>`;
            }

            li.innerHTML = `
                <div class="bypass-row">
                    <span class="domain-name">${escapeHtml(domain)}</span>
                    <button class="btn btn-danger remove-bypass-btn" data-domain="${escapeHtml(domain)}">Remove</button>
                </div>
                ${metaHtml}
            `;
            bypassList.appendChild(li);
        });

        document.querySelectorAll(".remove-bypass-btn").forEach((btn) => {
            btn.addEventListener("click", () => {
                const domain = btn.getAttribute("data-domain");
                removeFromBypass(domain);
            });
        });
    }

    function loadBypassList() {
        chrome.storage.local.get(["bypassedDomains"], (result) => {
            renderBypassList(result.bypassedDomains || []);
        });
    }

    function removeFromBypass(domain) {
        chrome.storage.local.get(["bypassedDomains"], (result) => {
            let bypassed = result.bypassedDomains || [];
            bypassed = bypassed.filter((e) => getBypassDomain(e) !== domain);
            chrome.storage.local.set({ bypassedDomains: bypassed }, () => {
                renderBypassList(bypassed);
            });
        });
    }

    clearBypassBtn.addEventListener("click", () => {
        chrome.storage.local.set({ bypassedDomains: [] }, () => {
            renderBypassList([]);
        });
    });

    // =============================================
    // Statistics
    // =============================================
    async function loadStats() {
        statsLoading.classList.remove("hidden");
        statsContent.classList.add("hidden");

        try {
            const response = await fetch(currentApiUrl + "/stats", { signal: AbortSignal.timeout(5000) });
            const data = await response.json();
            statTotal.textContent    = data.total_scans ?? 0;
            statPhishing.textContent = data.total_phishing ?? 0;
            statSafe.textContent     = data.total_safe ?? 0;
            statsLoading.classList.add("hidden");
            statsContent.classList.remove("hidden");
        } catch (_) {
            statsLoading.textContent = "Could not load stats — is the backend running?";
        }
    }

    // =============================================
    // History
    // =============================================
    async function loadHistory() {
        historyLoading.classList.remove("hidden");
        historyContent.classList.add("hidden");

        try {
            const response = await fetch(currentApiUrl + "/history", { signal: AbortSignal.timeout(5000) });
            const data = await response.json();
            const rows = data.history || [];

            historyBody.innerHTML = "";

            if (rows.length === 0) {
                historyEmpty.classList.remove("hidden");
                historySummary.innerHTML = "";
            } else {
                historyEmpty.classList.add("hidden");

                // Calculate summary stats from this batch
                const total = rows.length;
                const phishingCount = rows.filter((r) => r.label === "phishing").length;
                const safeCount = total - phishingCount;
                const phishRate = total > 0 ? ((phishingCount / total) * 100).toFixed(1) : "0.0";

                historySummary.innerHTML = `
                    <span class="summary-stat">
                        Total: <span class="stat-num">${escapeHtml(total)}</span>
                    </span>
                    <span class="summary-divider"></span>
                    <span class="summary-stat">
                        Phishing: <span class="stat-num danger">${escapeHtml(phishingCount)}</span>
                        (${escapeHtml(phishRate)}%)
                    </span>
                    <span class="summary-divider"></span>
                    <span class="summary-stat">
                        Safe: <span class="stat-num safe">${escapeHtml(safeCount)}</span>
                    </span>
                `;

                rows.forEach((row) => {
                    const tr = document.createElement("tr");
                    const date = row.timestamp ? row.timestamp.slice(0, 10) : "";
                    const time = row.timestamp ? row.timestamp.slice(11, 19) : "--";
                    const urlDisplay = row.url || "--";
                    const domain = row.domain || "--";
                    const risk = (row.risk_level || "UNKNOWN").toLowerCase();
                    const phishingProb = row.phishing_probability !== undefined
                        ? (row.phishing_probability * 100).toFixed(1)
                        : null;

                    let probClass = "prob-cell";
                    let probDisplay = "--";
                    if (phishingProb !== null) {
                        probDisplay = phishingProb + "%";
                        if (parseFloat(phishingProb) >= 70) probClass += " prob-danger";
                        else if (parseFloat(phishingProb) >= 30) probClass += " prob-warn";
                        else probClass += " prob-safe";
                    }

                    tr.innerHTML = `
                        <td class="date-cell">${escapeHtml(date)}<br><span class="time-cell">${escapeHtml(time)}</span></td>
                        <td class="url-cell" title="${escapeHtml(urlDisplay)}">${escapeHtml(urlDisplay)}</td>
                        <td>${escapeHtml(domain)}</td>
                        <td><span class="risk-badge ${risk}">${escapeHtml(row.risk_level || "---")}</span></td>
                        <td class="${probClass}">${probDisplay}</td>
                    `;
                    historyBody.appendChild(tr);
                });
            }

            historyLoading.classList.add("hidden");
            historyContent.classList.remove("hidden");
        } catch (_) {
            historyLoading.textContent = "Could not load history — is the backend running?";
        }
    }

    // ─── Click to expand/collapse long URLs ──────
    historyBody.addEventListener("click", (e) => {
        const cell = e.target.closest(".url-cell");
        if (cell) cell.classList.toggle("expanded");
    });

    // =============================================
    // Utilities
    // =============================================
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    // =============================================
    // Initial Load
    // =============================================
    loadWhitelist();
    loadBypassList();
    loadStats();
    loadHistory();
});
