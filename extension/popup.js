chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {

    fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: tabs[0].url })
    })
    .then(res => res.json())
    .then(data => {
        const message = data.prediction === 1
            ? `⚠ Phishing detected!\nConfidence: ${(data.confidence * 100).toFixed(1)}%`
            : `✔ Safe website`;

        document.getElementById("status").innerText = message;
    });

});
