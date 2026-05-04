chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
        console.log(`Checking URL: ${tab.url}`);

        fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: tab.url })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Backend response:", data);

            const iconPath = parseInt(data.prediction) === 1 
                ? "icon-danger.png"
                : "icon-safe.png";

            chrome.action.setIcon({ tabId, path: iconPath });
        })
        .catch(err => {
            console.error("Error fetching prediction:", err);
        });
    }
});
