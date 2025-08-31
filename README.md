PiSOC: Raspberry Pi Mini Security Operations Center  
*A Hands-On Cybersecurity Portfolio Project*  

![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%204%2F5-red)  
![Category](https://img.shields.io/badge/Security-SOC%20Lab-green)  
![License](https://img.shields.io/badge/License-MIT-blue)  

---

📖 Overview
This project demonstrates how to build a **Mini Security Operations Center (SOC)** on affordable Raspberry Pi 4/5 hardware.  

It covers the **full security lifecycle**:  
- 📝 **Log Collection** – Centralizing logs into a SIEM (ELK Stack).  
- 🔍 **Intrusion Detection** – Suricata rules for port scans, brute force attempts, and suspicious traffic.  
- 🎭 **Honeypots** – Cowrie SSH/Telnet honeypot to capture attacker behavior.  
- 📡 **Packet Capture & Forensics** – Tcpdump/Wireshark for network analysis.  

**Why this matters:**  
- Employer-relevant (SOC workflows, SIEM dashboards, IDS rules).  
- Affordable & portable lab (Pi hardware instead of enterprise servers).  
- Expandable to firewalling, malware sandboxing, or cloud SIEM integrations.  

---

🏗️ Architecture  

<img width="881" height="788" alt="Screenshot 2025-08-31 092912" src="https://github.com/user-attachments/assets/03696e75-3279-450d-995b-4dac8a454bdd" />



🔧 Hardware & Requirements

Raspberry Pi 4 or 5 (4GB or 8GB recommended).

32GB+ microSD card.

Ethernet or Wi-Fi network.

External SSD/HDD for PCAP/log storage (optional).

Separate attacker box/VM (Kali Linux or Parrot).

⚙️ Setup Instructions
1. Bootstrap

Clone repo, then run bootstrap script:

git clone https://github.com/<your-username>/<repo-name>.git
cd PiSOC
sudo bash scripts/bootstrap_pi.sh


This installs and configures:

ELK stack (Elasticsearch, Logstash, Kibana)

Suricata IDS

Cowrie honeypot

Filebeat + Rsyslog forwarding

Tcpdump rotation

2. Services Overview

Logstash Pipeline: configs/logstash/pipeline/pisoc.conf

Suricata Rules: configs/suricata/rules/local.rules

Cowrie Config: configs/cowrie/cowrie.cfg

Filebeat Config: configs/filebeat/filebeat.yml

PCAP Rotation Script: configs/tcpdump/rotate_pcap.sh

Enable services after bootstrap:

sudo systemctl enable --now suricata rsyslog cowrie tcpdump-rotate.timer
sudo systemctl enable --now elasticsearch kibana logstash filebeat

🧪 Attack Demonstrations
Demo 1: Port Scan (Nmap)
nmap -sS -T4 -p- <PI_IP>


✅ Suricata logs alert: “Nmap Scan Detected”.

Demo 2: SSH Brute Force (Hydra → Cowrie)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<PI_IP>


✅ Cowrie logs failed logins + credentials → forwarded to ELK.

Demo 3: Suspicious Download
curl http://testmyids.com -o malware.bin


✅ Suricata EVE logs show HTTP download event.

📊 Dashboards & Screenshots

📸 Replace these placeholders with your actual lab screenshots:

Kibana Dashboard –

Suricata Alerts –

Cowrie Session Log –

🚀 Future Expansion

🔒 Firewalling with pfSense on Pi.

🧪 Malware sandboxing (Cuckoo + VM).

☁️ Cloud SIEM integration (Splunk Cloud, Azure Sentinel).

📝 Lessons Learned

Raspberry Pi = surprisingly capable SOC testbed.

Correlation between honeypot activity + IDS alerts is powerful.

Dashboards tell the story — visuals matter in detection engineering.

Resource limits push efficiency (light configs, minimal dashboards).

📌 Repo Structure
PiSOC/
├── README.md
├── configs/
│   ├── logstash/pipeline/pisoc.conf
│   ├── suricata/rules/local.rules
│   ├── cowrie/cowrie.cfg
│   ├── filebeat/filebeat.yml
│   └── tcpdump/rotate_pcap.sh
├── scripts/
│   ├── bootstrap_pi.sh
│   └── attack_demos/attack_walkthroughs.md
└── assets/screenshots/
    ├── topology_diagram.png
    ├── kibana_dashboard.png
    ├── suricata_alerts.png
    └── cowrie_session.png
