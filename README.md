<div align="center">

# 🛡️ Blue Team Lab

### Windows Forensics • SOC Investigation • Malware Analysis • Threat Hunting

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,50:2563eb,100:22c55e&height=180&section=header&text=Blue%20Team%20Lab&fontSize=48&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=Hands-on%20SOC%20Investigation%20%7C%20DFIR%20%7C%20Threat%20Hunting&descAlignY=58&descSize=16" />

<br>

![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC%20Analyst-2563eb?style=for-the-badge\&logo=securityscorecard\&logoColor=white)
![DFIR](https://img.shields.io/badge/DFIR-Windows%20Forensics-22c55e?style=for-the-badge\&logo=windows\&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-Log%20Analysis-f97316?style=for-the-badge\&logo=splunk\&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-Network%20Forensics-06b6d4?style=for-the-badge\&logo=wireshark\&logoColor=white)

</div>

---

## 📌 About This Lab Repository

This folder contains hands-on **Blue Team investigation labs** focused on real-world SOC and DFIR workflows.

Each lab is written like an incident response case study: starting from an alert, collecting evidence, analyzing logs, pivoting through artifacts, and mapping attacker behavior across the attack chain.

The goal of this repository is not only to answer lab questions, but to build a strong investigation mindset:

> **Follow the evidence. Build the timeline. Understand the attack.**

---

## 🧭 Lab Index

| Lab                               | Scenario                                                                     | Main Skills                                      | Status      |
| --------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------ | ----------- |
| 🦠 [Rhysida Lab](./Rhysida%20Lab) | Phishing, credential theft, persistence, lateral movement, ransomware impact | Splunk, Sysmon, Windows Event Logs, MITRE ATT&CK | ✅ Completed |
| 🌪️ [Tempest](./Tempest)          | Malicious document execution, C2 traffic, privilege escalation, persistence  | Wireshark, EVTX, CyberChef, Timeline Analysis    | ✅ Completed |

---

## 🔥 What You Will Practice

### 🕵️ SOC Investigation

* Alert triage
* Event log analysis
* Suspicious process investigation
* Authentication review
* Timeline reconstruction
* Evidence-based conclusion writing

### 🪟 Windows Forensics

* Sysmon Event ID analysis
* Process creation tracking
* Registry persistence hunting
* File creation monitoring
* Windows Security log investigation
* PowerShell and command-line analysis

### 🌐 Network Forensics

* PCAP analysis
* HTTP traffic inspection
* DNS investigation
* C2 communication discovery
* Suspicious domain and IP pivoting

### 🧬 Malware & Attack Behavior

* Malicious document execution
* Payload download behavior
* Persistence mechanisms
* Credential dumping traces
* Remote access tool activity
* Ransomware deployment indicators

---

## 🧰 Tools Used

| Tool                  | Purpose                                       |
| --------------------- | --------------------------------------------- |
| **Splunk**            | Searching and correlating Windows/Sysmon logs |
| **Wireshark**         | PCAP and network traffic analysis             |
| **EvtxECmd**          | Parsing Windows EVTX logs                     |
| **Timeline Explorer** | Timeline-based log review                     |
| **CyberChef**         | Decoding, deobfuscation, Base64 analysis      |
| **VirusTotal**        | Hash and malware reputation checking          |
| **MITRE ATT&CK**      | Mapping attacker techniques                   |

---

## 🧩 Investigation Methodology

```text
Alert
  ↓
Initial Triage
  ↓
Identify Host / User / Time Range
  ↓
Analyze Process Tree
  ↓
Review Network Connections
  ↓
Check Persistence
  ↓
Hunt Credential Access
  ↓
Trace Lateral Movement
  ↓
Find Exfiltration / Impact
  ↓
Map to MITRE ATT&CK
  ↓
Write Findings
```

---

## 📚 Lab Structure

Each lab usually contains:

```text
Lab Name/
├── README.md
├── image.png
├── image 1.png
├── image 2.png
└── ...
```

Inside each lab write-up, you can expect:

* Scenario description
* Investigation questions
* Useful queries
* Screenshots as evidence
* Analysis notes
* Attack flow explanation
* Final findings

---

## 🎯 Skills Matrix

| Skill Area              | Covered |
| ----------------------- | ------- |
| Initial Access Analysis | ✅       |
| Execution Analysis      | ✅       |
| Persistence Hunting     | ✅       |
| Defense Evasion         | ✅       |
| Credential Access       | ✅       |
| Discovery               | ✅       |
| Lateral Movement        | ✅       |
| Command & Control       | ✅       |
| Exfiltration            | ✅       |
| Impact / Ransomware     | ✅       |

---

## 🧠 Example Query Style

```spl
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time host User ParentImage ParentCommandLine Image CommandLine ProcessId ParentProcessId
| sort 0 _time
```

```spl
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| table _time host Image SourceIp DestinationIp DestinationPort Protocol
| sort 0 _time
```

```spl
index=* EventCode=4624
| table _time host Account_Name Logon_Type IpAddress WorkstationName AuthenticationPackageName
| sort 0 _time
```

---

## 🧬 MITRE ATT&CK Focus

This repository focuses on identifying and explaining attacker behavior through MITRE ATT&CK techniques such as:

| Tactic              | Example Behavior                              |
| ------------------- | --------------------------------------------- |
| Initial Access      | Phishing, malicious document                  |
| Execution           | PowerShell, command-line execution            |
| Persistence         | Startup folder, registry run keys             |
| Defense Evasion     | Log clearing, disabling protection            |
| Credential Access   | Dumping credentials, browser credential theft |
| Discovery           | Host, user, network, and service discovery    |
| Lateral Movement    | Remote execution and administrative tools     |
| Command and Control | Beaconing, suspicious outbound traffic        |
| Exfiltration        | Data staging and archive creation             |
| Impact              | Ransomware execution                          |

---

## 🚀 How To Use This Repository

Clone the repository:

```bash
git clone https://github.com/HuyVjpPro1806/Blue_Team_Lab.git
cd Blue_Team_Lab/Lab
```

Open any lab folder:

```bash
cd "Tempest"
```

Read the investigation:

```bash
cat README.md
```

Or view directly on GitHub for screenshots and formatted analysis.

---

## ✍️ Write-up Format I Follow

For each investigation, I try to structure the analysis like this:

```text
1. What happened?
2. Which artifact proves it?
3. Which event ID or log source shows it?
4. What fields are important?
5. What Splunk query can find it?
6. What does this mean in the attack chain?
7. Which MITRE ATT&CK technique does it map to?
```

---

## 🏆 Goal

This repository is part of my learning journey toward becoming a stronger **SOC Analyst / Blue Team practitioner**.

The main objectives are:

* Improve log analysis skills
* Practice real-world investigation flow
* Build strong Windows forensics fundamentals
* Understand attacker behavior from evidence
* Create clean and useful security write-ups

---

## 👨‍💻 Author

<div align="center">

**HuyVjpPro1806**

Blue Team Learner • SOC Analyst Path • Digital Forensics Enthusiast

[![GitHub](https://img.shields.io/badge/GitHub-HuyVjpPro1806-181717?style=for-the-badge\&logo=github)](https://github.com/HuyVjpPro1806)

</div>

---

<div align="center">

### ⭐ If this repository helps you, consider giving it a star!

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:22c55e,50:2563eb,100:0f172a&height=120&section=footer" />

</div>
