🛡️ Windows Internal Security Lab — SOC Investigation Report
📌 Project Overview

This hands-on Windows 10 security lab was conducted in a Microsoft Azure virtual machine to simulate real Security Operations Center (SOC) investigation workflows. The objective was to analyze Windows internals, review system protections, investigate authentication events, and validate built-in endpoint security controls from a defensive cybersecurity perspective.This project demonstrates Windows troubleshooting, system administration, and endpoint security analysis skills relevant to Help Desk and SOC analyst roles.

The lab focused on process inspection, NTFS permissions, user privilege management, network visibility, registry persistence mechanisms, event log analysis, and system security policy review.

🎯 Objectives

Investigate Windows system processes using Sysinternals tools

Analyze NTFS permissions and Access Control Entries (ACEs)

Evaluate user privileges and administrative elevation behavior

Review active processes, resource usage, and service configurations

Identify persistence mechanisms within the Windows Registry

Analyze networking configuration and active connections

Perform PowerShell-based system enumeration

Investigate authentication activity within Windows Event Logs

Validate built-in Windows security controls and policies

🧪 Lab Environment

Platform: Microsoft Azure Virtual Machine

Operating System: Windows 10

Tools Used:

Process Explorer (Sysinternals)

Task Manager & Resource Monitor

Event Viewer

Windows Defender Antivirus

Windows Defender Firewall

Local Security Policy

PowerShell

Command Prompt

Registry Editor

🔎 Investigation Tasks & Findings

✅ Task 1 — Process Inspection (Sysinternals)

Inspected explorer.exe using Process Explorer

Reviewed DLL dependencies and process properties

Validated executable path and parent process relationships

SOC Relevance: Identifying malicious process injection or suspicious execution paths.

🔐 Task 2 — NTFS & ACL Investigation

Navigated to C:\Windows\System32

Reviewed ownership and permissions

Confirmed TrustedInstaller as system owner

Analyzed Access Control Entries (ACEs)

Observed restricted write access for standard users

SOC Relevance: Detecting privilege abuse and unauthorized file modification attempts.

👤 Task 3 — User & Privilege Management

Created local user account student123

Added account to Remote Desktop Users and Administrators groups

Verified group memberships

Tested elevation via software installation (UAC prompt observed)

SOC Relevance: Understanding privilege escalation and administrative access behavior.

⚙️ Task 4 — Running Process & Resource Analysis

Analyzed CPU and memory usage in Task Manager

Identified high-resource processes

Observed system utilization trends

Investigated disk I/O activity in Resource Monitor

SOC Relevance: Detecting abnormal resource consumption patterns associated with malware.

🔧 Task 5 — Windows Services Inspection

Reviewed Windows Update, Defender Firewall, and DHCP Client services

Stopped and restarted Print Spooler to observe service state changes

Monitored process lifecycle by terminating Notepad

SOC Relevance: Understanding service abuse and monitoring process termination behavior.

🧠 Task 6 — Registry & Startup Persistence

Reviewed startup entries in:

HKLM Run

HKCU Run

Identified SecurityHealth and OneDrive startup entries

Created and removed a temporary registry value

SOC Relevance: Recognizing registry-based persistence techniques used by malware.

🌐 Task 7 — Networking Configuration Analysis

Commands executed:

ipconfig /all
arp -a
netstat -ano
route print


Findings:

Verified IP configuration and DNS settings

Observed listening ports (135, 445, 3389)

Identified outbound HTTPS connections

Confirmed default route configuration

SOC Relevance: Network-based threat hunting and port/PID correlation.

💻 Task 8 — PowerShell Administration & Enumeration

Commands executed:

Get-Process
Get-Service
Get-LocalUser
Get-EventLog -LogName System -Newest 20
Get-Service | Where-Object { $_.Name -like "Win*" }


Enumerated processes, services, and user accounts

Reviewed recent system events

Exported process data to CSV

SOC Relevance: Using PowerShell for system visibility and incident investigation.

📋 Task 9 — Windows Event Log Investigation

Opened Event Viewer

Filtered Security logs for Event ID 4624 (Successful Logon)

Reviewed logon details and elevated token information

SOC Relevance: Monitoring authentication activity and detecting suspicious logins.

🛡️ Task 10 — Built-In Windows Security Controls

Executed Microsoft Defender Quick Scan (0 threats detected)

Reviewed Firewall profile configurations

Analyzed Local Security Policy:

Password Policy

Account Lockout Policy

Advanced Audit Policy

SOC Relevance: Validating endpoint protection posture and audit readiness.

🧠 Key Security Concepts Demonstrated

Privilege escalation awareness

Process monitoring and analysis

Registry persistence detection

Event log investigation

Network visibility and port analysis

Endpoint protection validation

Windows security policy auditing

🚨 SOC Analyst Skills Demonstrated

Threat hunting fundamentals

Log analysis

Host-based investigation

System hardening review

Security control validation

PowerShell enumeration

Windows internals analysis

📷 Screenshots

All investigation steps and findings are documented within the /images directory.

⭐ Author

Ashley McGee
Aspiring SOC Analyst | Cybersecurity Student

GitHub: https://github.com/akmcgee
