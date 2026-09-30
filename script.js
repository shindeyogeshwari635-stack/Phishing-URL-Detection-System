function checkURL() {
    const url = document.getElementById("urlInput").value.trim().toLowerCase();
    const result = document.getElementById("result");

    if (url === "") {
        result.innerHTML = "⚠️ Please enter a URL!";
        result.className = "result phishing";
        updateRiskScore(0);
        return;
    }

    let score = 0;
    let reasons = [];

    const keywordPatterns = [
        "login", "verify", "secure", "account", "update",
        "bank", "paypal", "amazon", "facebook",
        "signin", "reset", "confirm", "payment",
        "free", "bonus", "reward", "urgent", "click"
    ];

    const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq"];

    // ✅ Keyword check
    keywordPatterns.forEach(word => {
        if (url.includes(word)) {
            score++;
            reasons.push(`Contains suspicious keyword: "${word}"`);
        }
    });

    // ✅ Suspicious TLD check
    suspiciousTLDs.forEach(tld => {
        if (url.endsWith(tld)) {
            score++;
            reasons.push(`Uses suspicious domain extension: "${tld}"`);
        }
    });

    // ✅ IP Address check
    const ipPattern = /\b\d{1,3}(\.\d{1,3}){3}\b/;
    if (ipPattern.test(url)) {
        score++;
        reasons.push("Uses an IP address instead of a domain name");
    }

    // ✅ @ symbol check
    if (url.includes("@")) {
        score++;
        reasons.push("Contains '@' symbol");
    }

    // ✅ HTTP instead of HTTPS
    if (url.startsWith("http://")) {
        score++;
        reasons.push("Uses HTTP instead of HTTPS");
    }

    // ✅ Risk logic based on TOTAL score
    let riskPercentage = Math.min(score * 20, 100);

    updateRiskScore(riskPercentage);

    let status = "Safe";

    if (score >= 1) {
        status = "Phishing";
        result.innerHTML = `
            ⚠️ <strong>Phishing URL Detected!</strong><br><br>
            <u>Reasons:</u>
            <ul>
                ${reasons.map(r => `<li>${r}</li>`).join("")}
            </ul>
        `;
        result.className = "result phishing";
    } else {
        result.innerHTML = "✅ <strong>URL Looks Safe</strong>";
        result.className = "result safe";
    }

    localStorage.setItem("lastRisk", riskPercentage);
    saveToHistory(url, status);
    loadHistory();
}

function saveToHistory(url, status) {
    let history = JSON.parse(localStorage.getItem("urlHistory")) || [];

    history.unshift({
        url: url,
        status: status,
        time: new Date().toLocaleString()
    });

    localStorage.setItem("urlHistory", JSON.stringify(history));
}

function loadHistory() {
    const historyList = document.getElementById("historyList");
    if (!historyList) return;

    let history = JSON.parse(localStorage.getItem("urlHistory")) || [];
    historyList.innerHTML = "";

    history.forEach(item => {
        const li = document.createElement("li");

        li.innerHTML = `
            <span>${item.url}</span><br>
            <strong class="${item.status === 'Phishing' ? 'phishing' : 'safe'}">
                ${item.status}
            </strong>
            <br>
            <small>${item.time}</small>
        `;

        historyList.appendChild(li);
    });

    updateStatistics();
}

function clearHistory() {
    localStorage.removeItem("urlHistory");
    localStorage.removeItem("lastRisk");

    const historyList = document.getElementById("historyList");
    if (historyList) historyList.innerHTML = "";

    const safeCount = document.getElementById("safeCount");
    const phishingCount = document.getElementById("phishingCount");
    const totalCount = document.getElementById("totalCount");

    if (safeCount) safeCount.innerText = "0";
    if (phishingCount) phishingCount.innerText = "0";
    if (totalCount) totalCount.innerText = "0";

    updateRiskScore(0);
}

window.onload = function () {
    loadHistory();
    loadRiskScore();
};

function updateStatistics() {
    let history = JSON.parse(localStorage.getItem("urlHistory")) || [];

    let safe = 0;
    let phishing = 0;

    history.forEach(item => {
        if (item.status === "Safe") safe++;
        if (item.status === "Phishing") phishing++;
    });

    document.getElementById("safeCount").innerText = safe;
    document.getElementById("phishingCount").innerText = phishing;
    document.getElementById("totalCount").innerText = history.length;
}

function updateRiskScore(percent) {
    const fill = document.getElementById("riskFill");
    const text = document.getElementById("riskText");

    if (!fill || !text) return;

    if (percent <= 0) {
        fill.style.width = "0%";
        fill.style.background = "#6b7280";
        text.innerText = "0% Risk (No Threat Detected)";
        return;
    }

    fill.style.width = percent + "%";

    if (percent < 30) {
        fill.style.background = "#1ac61f";
        text.innerText = `${Math.round(percent)}% Risk (Low)`;
    } 
    else if (percent < 60) {
        fill.style.background = "#facc15";
        text.innerText = `${Math.round(percent)}% Risk (Medium)`;
    } 
    else {
        fill.style.background = "#d51212";
        text.innerText = `${Math.round(percent)}% Risk (High)`;
    }
}

function loadRiskScore() {
    const lastRisk = localStorage.getItem("lastRisk");
    if (lastRisk !== null) {
        updateRiskScore(Number(lastRisk));
    }
}