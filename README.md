# PiSOC: Raspberry Pi Mini Security Operations Center

*A Hands-On Cybersecurity Portfolio Project*

![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%204%2F5-red)
![Category](https://img.shields.io/badge/Security-SOC%20Lab-green)
![License](https://img.shields.io/badge/License-MIT-blue)

---

📖 Overview

This project demonstrates how to build a **Mini Security Operations Center (SOC)** on affordable Raspberry Pi 4/5 hardware.

It covers the **full security lifecycle**:

* 📝 **Log Collection** – Centralizing logs into a SIEM (ELK Stack).
* 🔍 **Intrusion Detection** – Suricata rules for port scans, brute force attempts, and suspicious traffic.
* 🎭 **Honeypots** – Cowrie SSH/Telnet honeypot to capture attacker behavior.
* 📡 **Packet Capture & Forensics** – Tcpdump/Wireshark for network analysis.

**Why this matters:**

* Employer-relevant (SOC workflows, SIEM dashboards, IDS rules).
* Affordable & portable lab (Pi hardware instead of enterprise servers).
* Expandable to firewalling, malware sandboxing, or cloud SIEM integrations.

---

🏗️ Architecture

```mermaid
flowchart TD
    A[Attacker/Kali VM] -->|Port Scans, Brute Force| B[Raspberry Pi Honeypot]
    A -->|Suspicious Traffic| C[Raspberry Pi IDS (Suricata)]
    B -->|Attack Logs| D[Log Collector (ELK Stack)]
    C -->|Alerts| D
    E[Packet Capture Node] -->|PCAP Files| D
    D -->|Dashboards & Alerts| F[Analyst Laptop / Kibana UI]
```

📸 Replace placeholder with real diagram:
![Architecture Diagram](assets/screenshots/topology_diagram.png)

---

🔧 Hardware & Requirements

* Raspberry Pi 4 or 5 (4GB or 8GB recommended).
* 32GB+ microSD card.
* Ethernet or Wi-Fi network.
* External SSD/HDD for PCAP/log storage (optional).
* Separate attacker box/VM (Kali Linux or Parrot).

---

⚙️ Setup Instructions

1. Bootstrap

Clone repo, then run bootstrap script:

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd PiSOC
sudo bash scripts/bootstrap_pi.sh
```

This installs and configures:

* ELK stack (Elasticsearch, Logstash, Kibana)
* Suricata IDS
* Cowrie honeypot
* Filebeat + Rsyslog forwarding
* Tcpdump rotation

---

2. Services Overview

* **Logstash Pipeline:** `configs/logstash/pipeline/pisoc.conf`
* **Suricata Rules:** `configs/suricata/rules/local.rules`
* **Cowrie Config:** `configs/cowrie/cowrie.cfg`
* **Filebeat Config:** `configs/filebeat/filebeat.yml`
* **PCAP Rotation Script:** `configs/tcpdump/rotate_pcap.sh`

Enable services after bootstrap:

```bash
sudo systemctl enable --now suricata rsyslog cowrie tcpdump-rotate.timer
sudo systemctl enable --now elasticsearch kibana logstash filebeat
```

---

🧪 Attack Demonstrations

Demo 1: Port Scan (Nmap)

```bash
nmap -sS -T4 -p- <PI_IP>
```

✅ Suricata logs alert: “Nmap Scan Detected”.

---

Demo 2: SSH Brute Force (Hydra → Cowrie)

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<PI_IP>
```

✅ Cowrie logs failed logins + credentials → forwarded to ELK.

---

Demo 3: Suspicious Download

```bash
curl http://testmyids.com -o malware.bin
```

✅ Suricata EVE logs show HTTP download event.

---

📊 Dashboards & Screenshots

📸 Replace these placeholders with your actual lab screenshots:

* **Kibana Dashboard** – ![Kibana Dashboard](assets/screenshots/kibana_dashboard.png)
* **Suricata Alerts** – ![Suricata Alerts](assets/screenshots/suricata_alerts.png)
* **Cowrie Session Log** – ![Cowrie Session](assets/screenshots/cowrie_session.png)

---

## 🚀 Future Expansion

* 🔒 Firewalling with pfSense on Pi.
* 🧪 Malware sandboxing (Cuckoo + VM).
* ☁️ Cloud SIEM integration (Splunk Cloud, Azure Sentinel).

---

📝 Lessons Learned

* Raspberry Pi = surprisingly capable SOC testbed.
* Correlation between **honeypot activity + IDS alerts** is powerful.
* Dashboards tell the story — visuals matter in detection engineering.
* Resource limits push efficiency (light configs, minimal dashboards).

---

📌 Repo Structure

```
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
    ├── kibana_dashboard.png
    ├── suricata_alerts.png
    └── cowrie_session.png
```

---

📣 How to Showcase

* Pin this repo on your GitHub profile.
* Use repo **topics**: `cybersecurity`, `raspberry-pi`, `soc`, `ids`, `honeypot`, `siem`.
* Add screenshots/logs → turns repo into a **portfolio case study**.
* Share a post on LinkedIn with your repo link.

---

🔗 MIT License © 2025
