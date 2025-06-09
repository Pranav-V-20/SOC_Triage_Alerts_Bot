import json
import requests
from slack_sdk import WebClient
from config import VIRUSTOTAL_API_KEY, SLACK_TOKEN, SLACK_CHANNEL

# Sample input alert (normally comes from SIEM)
alerts = [
    {
        "source_ip": "8.8.8.8",
        "destination_ip": "192.168.1.10",
        "url": "http://malicious-example.com",
        "timestamp": "2025-06-09",
        "alert_type": "Suspicious Outbound Connection"
    }
]

def query_virustotal_url(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls", headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def query_virustotal_ip(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def classify_severity(positives):
    if positives >= 10:
        return "High"
    elif positives >= 3:
        return "Medium"
    else:
        return "Low"

def send_slack_alert(alert, severity, vt_data):
    client = WebClient(token=SLACK_TOKEN)
    message = (
        f"*🚨 New Alert Detected: {alert['alert_type']}*\n"
        f"> Source IP: `{alert['source_ip']}`\n"
        f"> Destination IP: `{alert['destination_ip']}`\n"
        f"> URL: {alert.get('url', 'N/A')}\n"
        f"> Timestamp: {alert['timestamp']}\n"
        f"> Severity: *{severity}*\n"
        f"> VT Detections: {vt_data} engines flagged it"
    )
    client.chat_postMessage(channel=SLACK_CHANNEL, text=message)

def triage_alert(alert):
    print(f"🔍 Triage alert from {alert['source_ip']}")
    vt_result = 0

    # Check IP reputation
    ip_data = query_virustotal_ip(alert['source_ip'])
    if ip_data and 'data' in ip_data:
        vt_result += ip_data['data']['attributes']['last_analysis_stats']['malicious']

    # Check URL if present
    if 'url' in alert:
        # VirusTotal requires URL encoding
        url_id = requests.utils.quote(alert['url'], safe='')
        url_data = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        ).json()
        if 'data' in url_data:
            vt_result += url_data['data']['attributes']['last_analysis_stats']['malicious']

    severity = classify_severity(vt_result)
    send_slack_alert(alert, severity, vt_result)

# Run triage
for alert in alerts:
    triage_alert(alert)
