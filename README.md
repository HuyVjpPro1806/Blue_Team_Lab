<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,45:2563eb,100:16a34a&height=210&section=header&text=Blue%20Team%20Lab&fontSize=52&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=SOC%20Investigation%20%7C%20DFIR%20%7C%20Threat%20Hunting%20%7C%20SIEM%20Analysis&descAlignY=58&descSize=16" alt="Blue Team Lab banner" />

# Blue Team Lab

**Bộ sưu tập write-up thực hành Blue Team, SOC Investigation, DFIR và Threat Hunting.**

![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC%20Analyst-2563eb?style=for-the-badge&logo=securityscorecard&logoColor=white)
![DFIR](https://img.shields.io/badge/DFIR-Incident%20Response-16a34a?style=for-the-badge&logo=windows&logoColor=white)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20%7C%20Elastic-f97316?style=for-the-badge&logo=splunk&logoColor=white)
![Threat Hunting](https://img.shields.io/badge/Threat%20Hunting-MITRE%20ATT%26CK-7c3aed?style=for-the-badge)

</div>

---

## Tổng quan

Repository này tổng hợp các bài lab mình đã thực hành trong quá trình học Blue Team. Mỗi lab được viết theo hướng một case điều tra thực tế: bắt đầu từ scenario, phân tích log, truy vấn SIEM, lần theo dấu vết attacker và đưa ra câu trả lời dựa trên bằng chứng.

Mục tiêu không chỉ là hoàn thành câu hỏi của lab, mà còn rèn tư duy điều tra:

> **Follow the evidence. Build the timeline. Understand the attack.**

## Lab Index

| # | Lab | Chủ đề chính | Công cụ / dữ liệu | Trạng thái |
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

## Nội dung chính

- Phân tích log Windows Security, Sysmon, PowerShell và Active Directory.
- Truy vấn SIEM bằng Splunk SPL và Elastic/KQL.
- Điều tra process creation, command line, file creation, registry modification và network connection.
- Dựng timeline tấn công từ initial access đến impact.
- Tìm IOC: IP, domain, hash, username, hostname, file path và process ID.
- Mapping hành vi attacker theo MITRE ATT&CK.
- Viết báo cáo điều tra có bằng chứng rõ ràng bằng ảnh chụp và truy vấn.

## Kỹ năng thực hành

| Nhóm kỹ năng | Nội dung |
| --- | --- |
| SOC Triage | Xác định alert, host, user, timestamp và phạm vi điều tra |
| Windows Forensics | Security Event Log, Sysmon Event ID, process tree, registry, file activity |
| Active Directory | Kerberoasting, DCSync, Pass-the-Hash, lateral movement, account compromise |
| Network Forensics | HTTP/DNS analysis, C2 traffic, PCAP inspection, suspicious IP/domain pivoting |
| Malware Behavior | Payload execution, persistence, credential access, defense evasion, ransomware impact |
| Reporting | Ghi lại truy vấn, bằng chứng, câu trả lời và luồng tấn công một cách dễ theo dõi |

## Tools

| Tool | Mục đích sử dụng |
| --- | --- |
| Splunk | Truy vấn, lọc và tương quan log trong các lab SOC |
| Elastic SIEM | Điều tra endpoint, process, network và authentication events |
| Sysmon | Theo dõi process creation, network connection, file/registry activity |
| Wireshark | Phân tích PCAP và lưu lượng mạng |
| EvtxECmd | Parse Windows EVTX sang CSV |
| Timeline Explorer | Dựng và đọc timeline sự kiện |
| CyberChef | Decode, deobfuscation, phân tích chuỗi và dữ liệu mã hóa |
| MITRE ATT&CK | Mapping tactic/technique để hiểu hành vi attacker |

## Phương pháp điều tra

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

## Cấu trúc repository

```text
Blue_Team_Lab/
├── Lab/
│   ├── Boss Of The SOC v1 Lab/
│   ├── ElasticCase Lab/
│   ├── FalconEye Lab/
│   ├── GhostConnect _TA583_Lab/
│   ├── Kerberoasted Lab/
│   ├── Poisoned PyTorch Lab/
│   ├── Rhysida Lab/
│   ├── ShadowRoast Lab/
│   └── Tempest/
├── note.md
└── README.md
```

Mỗi lab thường bao gồm:

- File write-up Markdown.
- Ảnh minh họa trong thư mục `images/` hoặc ảnh đi kèm lab.
- Scenario, câu hỏi, truy vấn, bằng chứng và câu trả lời.

## Tài liệu ghi chú

Ngoài các bài lab, repository còn có file [note.md](./note.md) dùng để tra cứu nhanh Windows Event ID, Sysmon Event ID và quy trình điều tra gợi ý khi phân tích log.

## Ví dụ truy vấn thường dùng

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

## Cách sử dụng

Clone repository:

```bash
git clone https://github.com/HuyVjpPro1806/Blue_Team_Lab.git
cd Blue_Team_Lab
```

Mở thư mục `Lab/`, chọn một bài lab và đọc file Markdown tương ứng. Nên đọc scenario trước, sau đó đi lần lượt từng câu hỏi để hiểu cách truy vấn, pivot và kết luận.

## Ghi chú

Nội dung trong repository chỉ phục vụ mục đích học tập, nghiên cứu phòng thủ và nâng cao kỹ năng điều tra an toàn thông tin. Các kỹ thuật tấn công được nhắc đến chỉ được trình bày trong bối cảnh phân tích, phát hiện và ứng phó sự cố.

---

<div align="center">

**Nếu repository hữu ích, hãy để lại một star để ủng hộ quá trình học Blue Team.**

</div>
