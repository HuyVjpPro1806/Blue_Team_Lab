<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,45:2563eb,100:16a34a&height=210&section=header&text=Blue%20Team%20Lab&fontSize=52&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=SOC%20Investigation%20%7C%20DFIR%20%7C%20Threat%20Hunting%20%7C%20SIEM%20Analysis&descAlignY=58&descSize=16" alt="Blue Team Lab banner" />

# Blue Team Lab

**A collection of hands-on Blue Team write-ups focused on SOC investigation, DFIR, threat hunting, and SIEM analysis.**

![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC%20Analyst-2563eb?style=for-the-badge&logo=securityscorecard&logoColor=white)
![DFIR](https://img.shields.io/badge/DFIR-Incident%20Response-16a34a?style=for-the-badge&logo=windows&logoColor=white)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20%7C%20Elastic-f97316?style=for-the-badge&logo=splunk&logoColor=white)
![Threat Hunting](https://img.shields.io/badge/Threat%20Hunting-MITRE%20ATT%26CK-7c3aed?style=for-the-badge)

</div>

---

## Overview

This repository contains hands-on Blue Team labs completed as part of my cybersecurity learning journey. Each lab is written like a real investigation case: starting from a scenario, analyzing logs, querying SIEM data, following attacker activity, and answering each question with evidence.

The goal is not only to complete the lab questions, but also to build a stronger investigation mindset:

> **Follow the evidence. Build the timeline. Understand the attack.**

## Lab Index

| # | Lab | Main Focus | Tools / Data | Status |
| --- | --- | --- | --- | --- |
| 1 | [Boss Of The SOC v1](./Lab/Boss%20Of%20The%20SOC%20v1%20Lab) | APT, website defacement, ransomware, kill chain | Splunk, web logs, Sysmon | Completed |
| 2 | [ElasticCase](./Lab/ElasticCase%20Lab) | Malicious file, process tree, registry, PowerShell, pivoting | Elastic SIEM, Windows/Linux logs | Completed |
| 3 | [FalconEye](./Lab/FalconEye%20Lab) | AD breach, BloodHound, privilege escalation, DCSync, Pass-the-Hash | Splunk, Sysmon, AD logs | Completed |
| 4 | [GhostConnect - TA583](./Lab/GhostConnect%20_TA583_Lab) | Phishing link, PowerShell, browser artifacts, persistence, exfiltration | Splunk, endpoint telemetry | Completed |
| 5 | [Kerberoasted](./Lab/Kerberoasted%20Lab) | Kerberoasting detection, Kerberos events, service ticket hunting | Splunk, DC logs, Sysmon | Completed |
| 6 | [Poisoned PyTorch](./Lab/Poisoned%20PyTorch%20Lab) | Supply chain compromise, Python payload, domain activity, ransomware prep | Splunk, host artifacts | Completed |
| 7 | [Rhysida - Vice Society](./Lab/Rhysida%20Lab) | Phishing, credential theft, persistence, lateral movement, ransomware | Splunk, Sysmon, Windows logs | Completed |
| 8 | [ShadowRoast](./Lab/ShadowRoast%20Lab) | Initial access, registry persistence, AD activity, privilege escalation | Splunk, Windows/Sysmon logs | Completed |
| 9 | [Tempest](./Lab/Tempest) | Malicious document, C2 traffic, EVTX timeline, network forensics | Wireshark, EvtxECmd, Timeline Explorer, CyberChef | Completed |

## What This Repository Covers

- Analyzing Windows Security, Sysmon, PowerShell, and Active Directory logs.
- Querying SIEM data with Splunk SPL and Elastic/KQL.
- Investigating process creation, command lines, file creation, registry modification, and network connections.
- Reconstructing attacker timelines from initial access to impact.
- Identifying IOCs such as IP addresses, domains, hashes, usernames, hostnames, file paths, and process IDs.
- Mapping attacker behavior to MITRE ATT&CK techniques.
- Writing evidence-based investigation reports with screenshots and queries.

## Skills Practiced

| Skill Area | Coverage |
| --- | --- |
| SOC Triage | Identifying alerts, hosts, users, timestamps, and investigation scope |
| Windows Forensics | Security Event Logs, Sysmon Event IDs, process trees, registry activity, and file activity |
| Active Directory | Kerberoasting, DCSync, Pass-the-Hash, lateral movement, and account compromise |
| Network Forensics | HTTP/DNS analysis, C2 traffic, PCAP inspection, and suspicious IP/domain pivoting |
| Malware Behavior | Payload execution, persistence, credential access, defense evasion, ransomware impact |
| Reporting | Documenting queries, evidence, answers, and attack flow in a clear format |

## Tools

| Tool | Purpose |
| --- | --- |
| Splunk | Searching, filtering, and correlating logs in SOC labs |
| Elastic SIEM | Investigating endpoint, process, network, and authentication events |
| Sysmon | Tracking process creation, network connections, file activity, and registry activity |
| Wireshark | Analyzing PCAP files and network traffic |
| EvtxECmd | Parsing Windows EVTX files into CSV |
| Timeline Explorer | Reviewing event timelines |
| CyberChef | Decoding, deobfuscation, and string/data analysis |
| MITRE ATT&CK | Mapping tactics and techniques to attacker behavior |

## Investigation Methodology

```text
Alert / Scenario
      |
      v
Initial Triage
      |
      v
Identify Host, User, Time Range
      |
      v
Process / File / Registry Analysis
      |
      v
Authentication & Network Review
      |
      v
Persistence, Credential Access, Lateral Movement
      |
      v
Impact / Exfiltration
      |
      v
Timeline + Findings
```

## Repository Structure

```text
Blue_Team_Lab/
|-- Lab/
|   |-- Boss Of The SOC v1 Lab/
|   |-- ElasticCase Lab/
|   |-- FalconEye Lab/
|   |-- GhostConnect _TA583_Lab/
|   |-- Kerberoasted Lab/
|   |-- Poisoned PyTorch Lab/
|   |-- Rhysida Lab/
|   |-- ShadowRoast Lab/
|   `-- Tempest/
`-- README.md
```

Each lab usually contains:

- A Markdown write-up file.
- Screenshots stored in an `images/` folder or placed with the lab.
- Scenario, questions, queries, evidence, and final answers.
