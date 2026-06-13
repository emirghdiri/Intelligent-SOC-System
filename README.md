# 🛡️ Intelligent SOC System — Automated Cyberattack Detection

> Final Year Project | TEK-UP University | Cybersecurity Engineering  
> **Author:** Amir Ghediri  
> **Academic Supervisors:** Ms. Khouala Ammar & Mr. Hamdi Chebbi

---

## 📌 Project Overview

This project presents the design and implementation of an **Intelligent Security Operations Center (SOC)** built exclusively on open-source technologies and Machine Learning.

The goal is to demonstrate that a complete and effective monitoring infrastructure can be built to:
- Detect known attacks in real time
- Identify abnormal behaviors using AI
- Respond autonomously to detected incidents

---

## 🏗️ Architecture

The lab environment is built on **VMware Workstation** and consists of four virtual machines operating in an isolated network:

```
WAN (External)                    LAN (Internal) — 192.168.45.0/24
┌──────────────┐                 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Kali Linux  │                 │  Windows 10  │  │  Kali Linux  │  │ Ubuntu Server│
│ (External    │──── pfSense ────│  (Victim)    │  │ (Internal    │  │  (SOC)       │
│  Attacker)   │   Firewall/     │  192.168.45.20│  │  Attacker)   │  │ 192.168.45.10│
└──────────────┘   Router        │  Sysmon +    │  │ 192.168.45.50│  │ Wazuh Manager│
                                 │  Wazuh Agent │  └──────────────┘  │ Suricata NIDS│
                                 └──────────────┘                    │ ML Engine    │
                                                                     └──────────────┘
```

### Network Zones
- **WAN Zone** — Simulates the external Internet (external attacker)
- **LAN Zone** — Internal secured SOC network

### Virtual Machines
| VM | Role | Key Components |
|---|---|---|
| Kali Linux (WAN) | External attacker | Nmap, Hydra, enum4linux |
| Kali Linux (LAN) | Internal attacker | Nmap, Hydra, enum4linux |
| Windows 10 | Victim machine | Sysmon, Wazuh Agent |
| Ubuntu Server | SOC server | Wazuh Manager, Suricata, ML Engine |
| pfSense | Firewall / Router | WAN/LAN filtering, OpenVPN, HTTPS |

---

## 🛠️ Tools & Technologies

| Tool | Role |
|---|---|
| **Wazuh** | SIEM / EDR — log collection, correlation, analysis |
| **Suricata** | NIDS — real-time network intrusion detection |
| **Sysmon** | Windows event enrichment (processes, network, registry) |
| **pfSense** | Firewall and router — WAN/LAN traffic filtering |
| **Random Forest** | ML classification — known attack detection |
| **Isolation Forest** | ML anomaly detection — unknown threats |
| **Python** | Data collection, model training, automated response |
| **VMware Workstation** | Lab virtualization |
| **Kali Linux** | Attack simulation |

---

## 🔄 ML Pipeline

```
Wazuh Alerts  ──►  Data Collection  ──►  Dataset (alerts.csv)
                   (collect_data.py)       29,000+ alerts

Dataset  ──►  Model Training  ──►  Trained Models
              (train_model.py)      rf_model.pkl
                                    iso_model.pkl

Trained Models  ──►  Real-Time Detection  ──►  Automated Response
                      (detect_response.py)       Email alert
                                                 IP Blacklist
```

### Dataset
- **Total alerts collected:** 28,186
- **Normal events:** 9,576
- **Attack events:** 18,610
- **Features used:** `rule_id`, `rule_level`, `firedtimes`, `event_id`, `agent_encoded`

### Model Results
| Model | Precision | Recall | F1-Score |
|---|---|---|---|
| Random Forest | 1.00 | 1.00 | 1.00 |
| Isolation Forest | Unsupervised anomaly detection | — | — |

---

## ⚔️ Simulated Attacks

### Phase 1 — External Attacks (WAN)
- Nmap scan against the internal network from the WAN
- pfSense firewall tested before and after applying filtering rules
- **Result:** All unauthorized traffic blocked. Only OpenVPN (UDP 1194) and HTTPS (TCP 443) allowed

### Phase 2 — Internal Attacks (LAN)
| Attack | Tool | MITRE ATT&CK |
|---|---|---|
| Network scan | Nmap | T1046 |
| Vulnerability scan | Nmap `--script=vuln` | T1046 |
| SMB enumeration | enum4linux | T1135 |
| SMB brute force | Hydra | T1110 |
| RDP brute force | Hydra | T1110 |
| Encoded PowerShell | PowerShell | T1059.001 |
| User account creation | net user | T1136 |
| Persistence actions | Windows admin commands | T1098 |

---

## 🤖 Automated Response System

When a malicious activity is detected, `detect_response.py` automatically:

1. **Classifies** the alert using the trained ML models
2. **Sends an email alert** to the SOC administrator containing:
   - Attack type
   - Source IP address
   - Severity level
   - Detection timestamp
3. **Adds the malicious IP** to a local blacklist (`blacklist.txt`)
4. **Logs** the incident for audit trail

---

## 📁 Repository Structure

```
intelligent-soc-lab/
│
├── soc-ml/
│   ├── collect_data.py        # Collect alerts from Wazuh API
│   ├── train_model.py         # Train Random Forest + Isolation Forest
│   ├── detect_response.py     # Real-time detection + automated response
│   ├── alerts.csv             # Generated dataset (28,186 alerts)
│   ├── rf_model.pkl           # Trained Random Forest model
│   ├── iso_model.pkl          # Trained Isolation Forest model
│   ├── label_encoder.pkl      # Label encoder for categorical features
│   └── blacklist.txt          # Auto-generated malicious IP blacklist
│
├── configs/
│   ├── ossec.conf             # Wazuh agent configuration
│   ├── suricata.yaml          # Suricata NIDS configuration
│   └── sysmonconfig.xml       # Sysmon configuration
│
├── docs/
│   └── architecture.png       # SOC architecture diagram
│
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- VMware Workstation
- Ubuntu Server 22.04 (SOC Server)
- Windows 10 (Victim Machine)
- Kali Linux (Attacker Machine)
- pfSense 2.x (Firewall)

### 1. Deploy Wazuh Manager (Ubuntu Server)
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

### 2. Deploy Suricata NIDS
```bash
sudo apt-get install suricata -y
sudo suricata-update
```

### 3. Install Wazuh Agent (Windows 10)
Download and install the Wazuh agent from the Wazuh dashboard, then configure `ossec.conf` to enable Sysmon log collection.

### 4. Run the ML Pipeline
```bash
# Collect alerts from Wazuh
sudo python3 soc-ml/collect_data.py

# Train the models
sudo python3 soc-ml/train_model.py

# Start real-time detection and automated response
sudo python3 soc-ml/detect_response.py
```

---

## 📊 Detection Results

The system successfully detected all simulated attacks:

- ✅ **Nmap scans** — detected by Suricata, forwarded to Wazuh
- ✅ **SMB / RDP brute force** — detected by Wazuh Windows security rules
- ✅ **Post-exploitation (PowerShell, user creation)** — detected by Sysmon via Wazuh
- ✅ **Real-time ML classification** — Random Forest achieved 100% accuracy on the test set
- ✅ **Automated email alerts** sent upon attack detection
- ✅ **Malicious IPs automatically blacklisted**

---

## 🔮 Future Improvements

- Integration of a full **SOAR** platform
- Automatic IP blocking directly via **pfSense API**
- Use of **Deep Learning** models for improved detection
- Deployment in a **cloud environment** (AWS / Azure)
- Advanced **incident dashboard** for real-time monitoring

---

## 📚 References

- [Wazuh Documentation](https://documentation.wazuh.com)
- [Suricata Documentation](https://suricata.readthedocs.io)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Sysmon - Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [pfSense Documentation](https://docs.netgate.com/pfsense)
- Breiman, L. (2001). *Random Forests*. Machine Learning Journal.
- Liu, F.T., Ting, K.M., Zhou, Z.H. (2008). *Isolation Forest*. IEEE ICDM.

---

## 📄 License

This project was developed as part of a Final Year Engineering Project at TEK-UP University.  
For academic and educational use only.
