# PiSOC: Raspberry Pi Mini Security Operations Center  
*A Hands-On Cybersecurity Portfolio Project*  

![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%204%2F5-red)  
![Category](https://img.shields.io/badge/Security-SOC%20Lab-green)  
![License](https://img.shields.io/badge/License-MIT-blue)  

---

## 📖 Overview
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

## 🏗️ Architecture  

![Architecture Diagram](assets/screenshots/topology_diagram.png)  

**Data Flow:**
1. Attacker/test traffic hits Raspberry Pi honeypot and IDS sensors
2. Suricata IDS analyzes packets and generates alerts  
3. Cowrie honeypot captures SSH/Telnet attack attempts
4. All logs flow into centralized ELK SIEM via Filebeat
5. Kibana dashboards visualize threats and analyst workflows
6. PCAP files captured for forensic analysis

---

## 🔧 Hardware & Requirements
- **Raspberry Pi 4 or 5** (4GB or 8GB recommended)  
- **32GB+ microSD card** (Class 10 or better)
- **Ethernet or Wi-Fi network**  
- **External SSD/HDD** for PCAP/log storage (optional but recommended)
- **Separate attacker box/VM** (Kali Linux or Parrot OS)  

---

## ⚙️ Setup Instructions  

### 1. Quick Bootstrap
Clone repo, then run bootstrap script:  
```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd PiSOC
sudo bash scripts/bootstrap_pi.sh
```

This installs and configures:
- **ELK stack** (Elasticsearch, Logstash, Kibana)
- **Suricata IDS** with custom rules
- **Cowrie honeypot** (SSH/Telnet)
- **Filebeat + Rsyslog** forwarding
- **Tcpdump rotation** with systemd timers

### 2. Service Configuration Files
| Component | Config File | Purpose |
|-----------|-------------|---------|
| Logstash Pipeline | `configs/logstash/pipeline/pisoc.conf` | Parse logs from Suricata, Cowrie, syslog |
| Suricata Rules | `configs/suricata/rules/local.rules` | Custom detection rules |
| Cowrie Config | `configs/cowrie/cowrie.cfg` | Honeypot behavior settings |
| Filebeat Config | `configs/filebeat/filebeat.yml` | Log shipping configuration |
| PCAP Rotation | `configs/tcpdump/rotate_pcap.sh` | Automated packet capture |

### 3. Enable Services
After bootstrap completion:
```bash
sudo systemctl enable --now suricata rsyslog cowrie tcpdump-rotate.timer
sudo systemctl enable --now elasticsearch kibana logstash filebeat
```

### 4. Access Dashboards
- **Kibana Dashboard:** http://PI_IP:5601
- **Elasticsearch:** http://PI_IP:9200  
- **Default login:** elastic/changeme (update in production)

---

## 🧪 Attack Demonstrations  

### Demo 1: Port Scan Detection
```bash
# From attacker machine
nmap -sS -T4 -p- <PI_IP>
```
**Expected Result:** ✅ Suricata logs alert: "Nmap Scan Detected" → visible in Kibana dashboard

### Demo 2: SSH Brute Force (Honeypot)
```bash
# From attacker machine  
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<PI_IP>
```
**Expected Result:** ✅ Cowrie logs failed login attempts + credentials → forwarded to ELK → dashboard shows attack timeline

### Demo 3: Suspicious Download
```bash
# From attacker machine
curl -A "Malicious-Bot" http://testmyids.com -o malware.bin
```
**Expected Result:** ✅ Suricata HTTP logs + user-agent analysis → alerts in SIEM

### Demo 4: Custom Rule Testing
```bash
# Trigger custom detection rule
echo "TEST_ALERT_PAYLOAD" | nc <PI_IP> 80
```
**Expected Result:** ✅ Custom Suricata rule fires → correlated with network traffic logs

---

## 📊 Dashboards & Screenshots

Replace these placeholders with your actual lab screenshots:

| Dashboard | Purpose | Screenshot |
|-----------|---------|------------|
| **Main SOC Overview** | High-level threat metrics | ![Kibana Dashboard](assets/screenshots/kibana_dashboard.png) |
| **Suricata Alerts** | IDS alert timeline & severity | ![Suricata Alerts](assets/screenshots/suricata_alerts.png) |
| **Cowrie Sessions** | Honeypot attack attempts | ![Cowrie Sessions](assets/screenshots/cowrie_session.png) |
| **Network Traffic** | PCAP analysis & top talkers | ![Network Analysis](assets/screenshots/network_traffic.png) |

---

## 🚀 Future Expansion Ideas

### Phase 2: Enhanced Detection
- 🔒 **Firewall Integration** – pfSense on Pi for traffic filtering
- 🧪 **Malware Sandbox** – Cuckoo Sandbox VM integration  
- ☁️ **Cloud SIEM** – Forward logs to Splunk Cloud or Azure Sentinel
- 📱 **Mobile Alerts** – Slack/Discord webhooks for real-time notifications

### Phase 3: Advanced Analytics  
- 🤖 **ML-Based Detection** – Anomaly detection with Elastic ML
- 🔍 **OSINT Integration** – Threat intel feeds (MISP, OTX)
- 📈 **Custom Dashboards** – Executive reporting & KPIs
- 🔄 **Automated Response** – SOAR-like playbook automation

---

## 📝 Lessons Learned

Through building this lab, I gained hands-on experience with:

**Technical Skills:**
- **SIEM Architecture** – Log ingestion, parsing, correlation, and visualization
- **IDS Tuning** – Writing custom Suricata rules and reducing false positives  
- **Honeypot Operations** – Capturing attacker TTPs and IOCs
- **Network Forensics** – PCAP analysis and traffic correlation
- **Linux Administration** – Systemd services, log rotation, and resource optimization

**SOC Workflows:**
- **Incident Detection** – Alert triage and prioritization processes
- **Log Correlation** – Connecting honeypot activity with network alerts
- **Dashboard Design** – Building actionable visualizations for analysts
- **Documentation** – Creating runbooks and detection engineering notes

**Resource Constraints:**
- Raspberry Pi hardware limitations require efficient configurations
- Log retention strategies for storage-constrained environments  
- Performance tuning for low-resource SIEM deployments

---

## 📌 Repository Structure
```
PiSOC/
├── README.md                           # This file
├── configs/                           # Configuration files
│   ├── logstash/pipeline/pisoc.conf   # Logstash parsing rules
│   ├── suricata/                      # IDS configurations
│   │   ├── suricata.yaml             # Main Suricata config
│   │   └── rules/local.rules         # Custom detection rules
│   ├── cowrie/cowrie.cfg             # Honeypot settings
│   ├── filebeat/filebeat.yml         # Log shipping config
│   ├── rsyslog/10-pisoc.conf         # Syslog forwarding
│   ├── tcpdump/rotate_pcap.sh        # PCAP rotation script
│   └── systemd/                      # Service definitions
├── scripts/                          # Automation scripts
│   ├── bootstrap_pi.sh              # One-click setup
│   ├── generate_test_logs.sh        # Test data generator
│   └── attack_demos/                # Attack walkthroughs
├── kibana/                          # Dashboard exports
│   └── pisoc_dashboards.ndjson     # Saved objects
└── assets/screenshots/              # Documentation images
    ├── topology_diagram.png        # Architecture diagram
    ├── kibana_dashboard.png        # Main dashboard
    ├── suricata_alerts.png         # IDS alerts view
    └── cowrie_session.png          # Honeypot logs
```

---

## 📣 How to Showcase This Project

### For Your Resume
**Raspberry Pi Mini-SOC Lab** – Built a portable SOC using Raspberry Pi 4, Suricata IDS, Cowrie honeypot, ELK SIEM, and tcpdump packet capture. Developed dashboards, correlation rules, and attack demos (Nmap, Hydra, malware download) to demonstrate SOC analyst workflows and detection engineering skills.

### For GitHub
1. **Pin this repo** on your GitHub profile
2. **Add topics:** `cybersecurity`, `raspberry-pi`, `soc`, `ids`, `honeypot`, `siem`, `suricata`, `elk`
3. **Include screenshots** – Replace placeholders with real dashboards
4. **Add releases** – Package configs for easy download

### For LinkedIn
Share your project with a professional post highlighting the practical skills demonstrated.

---

## 🔗 License & Contact

**License:** MIT License © 2025  

**Questions?** Open an issue or connect with me on LinkedIn.

**Want to collaborate?** Fork this repo and submit a pull request with your enhancements!

---

*This project demonstrates hands-on cybersecurity engineering skills using affordable hardware. Perfect for building practical SOC experience and showcasing detection capabilities to potential employers.*