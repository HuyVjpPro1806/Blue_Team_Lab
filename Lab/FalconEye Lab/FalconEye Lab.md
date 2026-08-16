# FalconEye Lab

## **Scenario**

As a SOC analyst, you aim to investigate a security breach in an Active Directory network using Splunk SIEM solution to uncover the attacker's steps and techniques while creating a timeline of their activities. The investigation begins with network enumeration to identify potential vulnerabilities. Using a specialized privilege escalation tool, the attacker exploited an unquoted service path vulnerability in a specific process.

Once the attacker had elevated access, the attacker launched a DCsync attack to extract sensitive data from the Active Directory domain controller, compromising user accounts. The attacker employed evasion techniques to avoid detection and utilized a pass-the-hash (pth) attack to gain unauthorized access to user accounts. Pivoting through the network, the attacker explored different systems and established persistence.

Throughout the investigation, tracking the attacker's activities and creating a comprehensive timeline is crucial. This will provide valuable insights into the attack and aid in identifying potential gaps in the network's security.

![](https://download.cyberdefenders.org/BlueYard/misc/c85-topology.png)

### Question:

### Q1: What is the name of the compromised account?

![image.png](images/image.png)

Splunk query: 

```jsx
index="folks" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 "mimikatz"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, host
```

![image.png](images/image%201.png)

```jsx
index="folks" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 "mimikatz"  CommandLine="\"C:\\Users\\HelpDesk\\fun.exe\" \"lsadump::dcsync /user:Abdullah-work\\Administrator\"”
```

![image.png](images/image%202.png)

Answer: Abdullah-work\HelpDesk

### Q2: What is the name of the compromised machine?

Answer: Client02

### Q3: What tool did the attacker use to enumerate the environment?

![image.png](images/image%203.png)

Splunk query:

```jsx
index="folks" EventCode=4104 host="CLIENT02" bloodhound
```

![image.png](images/image%204.png)

Answer: bloodhound

### Q4: The attacker used an Unquoted Service Path to escalate privileges. What is the name of the vulnerable service?

![image.png](images/image%205.png)

Splunk query: 

```jsx
index="folks" host="CLIENT02" "program.exe" EventCode=1
| table _time, Image, CommandLine
```

![image.png](images/image%206.png)

Answer: Automate-Basic-Monitoring.exe

### Q5: What is the SHA256 of the executable that escalates the attacker's privileges?

Splunk query: 

```jsx
index="folks" host="CLIENT02" "program.exe" EventCode=1
| table _time, Image, CommandLine, Hashes
```

![image.png](images/image%207.png)

Answer: 8ACC5D98CFFE8FE7D85DE218971B18D49166922D079676729055939463555BD2

### Q6: When did the attacker download **fun.exe**?

Splunk query:

```jsx
index="folks" host="CLIENT02" "fun.exe" EventCode=11

```

![image.png](images/image%208.png)

Answer: 2023-05-10 05:08

### Q7: What is the command line used to launch the DCSync attack

Splunk query: 

```jsx
index="folks" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 "mimikatz"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, host
```

![image.png](images/image%201.png)

Answer: "C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator”

### Q8: What is the original name of **fun.exe**?

![image.png](images/image%202.png)

Answer: Mimikatz.exe

### Q9: The attacker performed the Over-Pass-The-Hash technique. What is the AES256 hash of the account he attacked?

Splunk query:

```jsx
index="folks" EventCode=1 "*aes256*"
| table _time, Image, CommandLine, host
```

![image.png](images/image%209.png)

Answer: facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379

### Q10: What service did the attacker abuse to access the Client03 machine as Administrator?

Splunk query:

```jsx
index="folks" host="CLIENT02" EventCode=1 Image = "C:\\Users\\HelpDesk\\*.exe" client03
| table _time, Image, CommandLine
```

![image.png](images/image%2010.png)

Answer: http/Client03

### Q11: The Client03 machine spawned a new process when the attacker logged on remotely. What is the process name?

splunk query

```jsx
index="folks"  EventCode=1 host="CLIENT03" NOT "splunk*"
| table _time ParentImage ParentCommandLine Image CommandLine
```

![image.png](images/image%2011.png)

Answer: wsmprovhost.exe

### Q12: What ticket name did the attacker generate to access the parent DC as Administrator?

Splunk query:

```jsx
index="folks"  EventCode=1 host="CLIENT02" Image="C:\\Users\\HelpDesk\\*.exe" "*admin*" "ticket"
| table _time, Image, CommandLine
```

![image.png](images/image%2012.png)

Answer: trust-test2.kirbi
