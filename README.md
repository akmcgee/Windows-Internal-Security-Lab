# Windows-Internal-Security-Lab
Hands-on Windows 10 security lab in Azure analyzing processes, NTFS permissions, user privileges, and system protections from a SOC perspective.

## 🖥️ Lab Environment

- Platform: Microsoft Azure
- OS: Windows 10
- Remote Access: RDP (FreeRDP)
- Tools Used:
  - Sysinternals Process Explorer
  - Command Prompt
  - PowerShell
  - Windows Event Viewer
  - Services Console
  - Registry Editor
 
---

## 🔍 Key Activities Performed

### Task 1 – Process & System Analysis
- Deployed Windows 10 VM in Azure
- Configured RDP access
- Installed and analyzed processes using Process Explorer
- Identified parent-child process relationships
- Reviewed loaded DLLs
- Analyzed LSASS as a protected system process

### Task 2 – NTFS & ACL Investigation
- Navigated to `C:\Windows\System32`
- Reviewed NTFS permissions and ownership
- Identified TrustedInstaller as owner
- Analyzed Access Control Entries (ACEs)
- Observed write restrictions for standard users

### Task 3 – User & Privilege Management
-Created standard user account student123
-Verified account creation using net user student123
-Added student123 to Remote Desktop Users group
-Added student123 to Administrators group
-Verified group membership using net localgroup administrators
-Logged in as student123 via RDP
-Attempted software installation (7-Zip)
-Observed UAC behavior before and after administrative group membership
-Confirmed privilege escalation by successful software installation

---
