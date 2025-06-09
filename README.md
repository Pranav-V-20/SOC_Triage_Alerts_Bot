# 🛡️ SOC Triage Alerts Bot

A Python-based **Security Operations Center (SOC) triage bot** that automates the enrichment, classification, and alerting of security incidents from SIEM logs using threat intelligence APIs.

---

## 🔍 Features

- ✅ Ingest alerts from SIEM/logs
- 🌐 Enrich IPs and URLs using [VirusTotal API](https://www.virustotal.com/)
- 🚦 Auto-classify alert severity (Low, Medium, High)
- 📢 Send alert summaries to Slack channels
- 🧩 Easily extendable for Discord, AbuseIPDB, or dashboards

---

## 📦 Requirements

- Python 3.8+
- Slack Bot Token
- VirusTotal API Key

### 📚 Python Dependencies

Install with:

```bash
pip install requests slack_sdk
````

---

## ⚙️ Configuration

Create a `config.py` file with your credentials:

```python
# config.py

VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
SLACK_TOKEN = "xoxb-your-slack-bot-token"
SLACK_CHANNEL = "#alerts"  # Name of the channel to send alerts
```

---

## 🚀 How It Works

### 1. Alert Input (sample)

```python
alerts = [
    {
        "source_ip": "8.8.8.8",
        "destination_ip": "192.168.1.10",
        "url": "http://malicious-example.com",
        "timestamp": "2025-06-07 14:00:00",
        "alert_type": "Suspicious Outbound Connection"
    }
]
```

### 2. Threat Intelligence Lookup

The bot uses **VirusTotal** to analyze:

* IP address reputation
* URL malicious detection counts

### 3. Severity Classification

Based on the number of detections:

* **High**: ≥10 detections
* **Medium**: 3–9
* **Low**: <3

### 4. Slack Alert Output

> 🚨 **New Alert: Suspicious Outbound Connection**
> ➤ Source IP: `8.8.8.8`
> ➤ Destination IP: `192.168.1.10`
> ➤ URL: `http://malicious-example.com`
> ➤ Severity: **High**
> ➤ VT Detections: `12 engines flagged it`

---

## 📎 How to Use

```bash
python soc_triage_bot.py
```

Make sure you have invited your bot to the target Slack channel using:

```bash
/invite @YourBotName
```

---

## 🧠 Future Enhancements

* [ ] Discord webhook support
* [ ] AbuseIPDB integration
* [ ] Real-time log stream input (Kafka/syslog)
* [ ] Web UI with Streamlit or Flask
* [ ] Database logging (MongoDB/SQLite)

## 🤝 Contributions

Feel free to fork, modify, and submit pull requests! If you use this in your SOC, we'd love to hear from you.

---

