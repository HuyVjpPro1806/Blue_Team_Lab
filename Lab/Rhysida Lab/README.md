# Rhysida - Vice Society Lab

# **Scenario**

A system administrator unknowingly submitted their credentials to a realistic phishing page disguised as a Microsoft login portal. Within hours, multiple login attempts from external sources were observed using this privileged account. Internal monitoring soon flagged unusual process activity, registry modifications, and outbound traffic to unfamiliar destinations. Remote administration tools appeared across critical systems, and event logs began vanishing. The SOC suspects a full compromise is underway—spanning initial access, persistence, lateral movement, and potentially ransomware deployment. Your task is to uncover the attacker’s path, identify persistence mechanisms, and assess the scope of data access and exfiltration.

# **Initial Access & Execution**

## Q1: What is the domain of the phishing page that captured the administrator’s credentials?

Splunk query: 

`index=* source= XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=22
| table _time, query, host`

![image.png](image.png)

## Q2: Following an unauthorized SSH login, a file appeared on the system, likely transferred via SCP or SFTP using OpenSSH. What is the Process ID of the process that wrote the file to disk?

Splunk query:

`index=* source= XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=29 host="WS3"
| table _time, Image, ProcessId, TargetFilename`

![image.png](image%201.png)

## Q3: After stealing the credentials, the attacker attempted to authenticate to the system using a specific protocol. What service was used to gain initial access?

Splunk query: `index=* EventCode=4624 host="WS3”`

![image.png](image%202.png)

## Q4: Based on log analysis, what was the exact timestamp of the attacker’s first success login attempt using the compromised account?

Splunk query:

`index=* EventCode=4624 host="WS3" eventtype=windows_logon_success Logon_Type=3 process_name="C:\\Program Files\\OpenSSH\\sshd-session.exe”`

![image.png](image%203.png)

## Q5: An attempt to use a deprecated download method failed. The attacker then switched to a native Windows utility to fetch their payloads. Which tool was successfully used?

`index=* EventCode=1 host="WS3" "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory`

<img width="1920" height="112" alt="image" src="https://github.com/user-attachments/assets/33f4bffd-c918-4d98-ac72-88485ef51191" />

# **Persistence & Defense Evasion**

## Q6: To maintain persistence, the attacker created a registry value with a legitimate-sounding name. What is the name of the registry value used for persistence?

Splunk query: `index=* EventCode=13 host="WS3" "WindowsUpdate.dll”`

<img width="1558" height="327" alt="image" src="https://github.com/user-attachments/assets/1aa3a58c-c4be-41ec-a752-18c023e132ea" />


## Q7: To evade detection, the attacker executed a command to disable endpoint protection. What command was used to weaken real-time monitoring?

Splunk query: 
`index=* EventCode=1 host="WS3" "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory`

![image.png](image%206.png)

![image.png](image%207.png)

## Q8:  The attacker disabled system auditing entirely. What command-line utility was used to achieve this?

Splunk query like Q7

<img width="1910" height="188" alt="image" src="https://github.com/user-attachments/assets/a941bbf1-90dd-4a13-85cc-94c4a7c3857a" />


## Q9: Log records indicate several event categories were erased from the system. What logs did the attacker clear to cover their tracks?

Splunk query like Q7

![image.png](image%209.png)

# **Credential Access & Privilege Escalation**

## Q10: A credential-dumping utility was executed to extract browser-stored credentials. What is the SHA256 hash of the malicious binary used?

Splunk query: : 
`index=* EventCode=1 "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory, host` 

<img width="1920" height="529" alt="image" src="https://github.com/user-attachments/assets/7583d92a-a7a1-4fe2-9425-cb75531fdad1" />


Splunk query: `index=* "BCleaner.exe" EventID=29` 

<img width="1901" height="593" alt="image" src="https://github.com/user-attachments/assets/5e784c42-c44c-40f7-ab21-d53b160feee8" />


## Q11: While expanding control over the network, a file containing dumped credentials was created. What is the name of the file used to store the stolen credentials?

Splunk query:
`index=* EventCode=1 host="WS3" "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory`

![image.png](image%2012.png)

## Q12: A failed credential dumping attempt triggered security alerts. What is the **`ProcessId`** of the process that performed this failed action?

Splunk query: 

`index=* EventCode=1 "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory,host`

![image.png](image%2013.png)

Splunk query: 

`index=* EventCode=1 "WindowsUpdate.dll"  CommandLine="C:\\Windows\\system32\\cmd.exe /C ntdsutil \"activate instance ntds\" \"ifm\" \"create full C:\\temp_l0gs\" q q”`

<img width="1898" height="469" alt="image" src="https://github.com/user-attachments/assets/479a0c20-2e46-479e-9b55-5ddaa75fdf51" />


## Q13: To restrict access to the remote session, the attacker configured a password. What password was set for the remote tool?

Splunk query: 

`index=* EventCode=1 host="WS3" "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory`

<img width="1899" height="865" alt="image" src="https://github.com/user-attachments/assets/7fea6314-1ec4-4357-a48d-8e18c973f398" />


# **Lateral Movement & Command and Control (C2)**

## Q14: During lateral movement, the attacker used a service-based technique to execute commands on remote systems. What MITRE sub-technique did they use?

Splunk query: Like Q13

![image.png](image%2016.png)

## **Q15: To establish ongoing access, a command and control beacon was deployed. What is the IP address of the C2 server the system communicated with?**

Splunk query: `index=* EventCode=3`

![image.png](image%2017.png)

Splunk query: `index=* EventCode=3 DestinationIp="3.70.203.137”`

![image.png](image%2018.png)

## Q16: A remote access tool was dropped on the system, allowing full remote control. What is the name of this tool?

Splunk query: 

`index=* EventCode=1 host="WS3" "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory`

![image.png](image%2019.png)

## Q17: After establishing the remote access session, the attacker issued a command to retrieve system-specific identifiers. What argument was passed to the tool?

Splunk query: 

`index=* EventCode=1 host="WS3" "AnyDesk"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory` 

![image.png](image%2020.png)

# **Exfiltration**

## Q18: Sensitive documents were collected and saved in a public directory. What is the full file path of the text file used to store this staged data?

Splunk query: 

`index=* EventCode=1 host="DC01"  "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory`

![image.png](image%2021.png)

## Q19: The attacker compressed the collected data into a single archive file for extraction. What is the name of the archive file?

Splunk query: 

`index=* EventCode=1 host="DC01"  "WindowsUpdate.dll"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, CurrentDirectory`

![image.png](image%2022.png)

![image.png](image%2023.png)

# **Impact**

## Q20: A ransomware payload was deployed to cause maximum damage. What is the name of the malicious executable launched during the final stage of the attack?

Splunk query: 

`index=* EventCode=29 host="DC01"
| table _time, TargetFilename`

![image.png](image%2024.png)

<img width="1846" height="603" alt="image" src="https://github.com/user-attachments/assets/a94e0728-a5d9-4482-85a1-7c62f74b082b" />


## Q21: Instead of dropping a typical ransom note, the attacker left behind a uniquely named file. What is the name of the note that was dropped?

Splunk query: `index=* EventCode=11 host="DC01”`

<img width="738" height="351" alt="image" src="https://github.com/user-attachments/assets/74c6feb8-55e4-4cdb-adac-5935b04e85bc" />


## Q22: After compromising the domain controller, the attacker stored tools in a sensitive location. What is the full path of the directory used for staging their tools?

![image.png](image%2027.png)
