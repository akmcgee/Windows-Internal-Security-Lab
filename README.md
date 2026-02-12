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
- Created local user account `student123` using `net user student123 /add`
- Verified account creation using `net user student123`
- Added `student123` to `Remote Desktop Users` group using `net localgroup "Remote Desktop Users" student123 /add`
- Added `student123` to `Administrators` group using `net localgroup administrators student123 /add`
- Verified group membership using `net localgroup administrators` and `net localgroup "Remote Desktop Users"`
- Logged in as `student123` via RDP
- Attempted 7-Zip software installation to test privilege level
- Observed UAC prompt requesting elevation
- Confirmed elevated privileges by successful software installation


### Task 4 – Running Process & Resource Analysis

- Opened Task Manager and analyzed active processes
- Identified top CPU-consuming processes:
  - News and interests (14) – 28.1%
  - System – 13.0%
  - Task Manager – 2.1%
  - Antimalware Service Executable – 1.8%
  - Service Host: Local System – 1.7%

- Identified top memory-consuming processes:
  - Antimalware Service Executable – 47.7 MB
  - Service Host: Network Service – 29.0 MB
  - Runtime Broker (7) – 21.2 MB
  - Microsoft Edge – 16.3 MB
  - Task Manager – 13.5 MB

- Observed overall system utilization:
  - CPU usage ranged between 10–14%
  - Memory usage ranged between 90–92%
  - Disk usage peaked at 7%
  - Network utilization remained minimal (0–136 Kbps)

- Opened Resource Monitor and analyzed:
  - Active Disk I/O activity (pagefile.sys and System processes)
 
### Task 5 – Inspect & Control Windows Services

- Opened Services Console using `services.msc`

- Located Windows Update service
- Observed:
  - Startup Type: Manual (Trigger Start)
  - Status: Running
  - Log On As: Local System
  - Description: "Enables the detection, download, and installation of updates for Windows and other programs. If this service is disabled, users of this computer will not be able to use Windows Update or its automatic updating feature, and programs will not be able to use the Windows Update Agent (WUA) API."

- Located Windows Defender Firewall service
- Observed:
  - Startup Type: Automatic
  - Status: Running
  - Log On As: Local Service
  - Description: "Windows Defender Firewall helps protect your computer by preventing unauthorized users from gaining access to your computer through the Internet or a network."

- Located DHCP Client service
- Observed:
  - Startup Type: Automatic
  - Status: Running
  - Log On As: Local Service
  - Description: "Registers and updates IP addresses and DNS records for this computer. If this service is stopped, this computer will not receive dynamic IP addresses and DNS updates. If this service is disabled, any services that explicitly depend on it will fail to start."

- Stopped and restarted a non-critical service (Print Spooler)
- Observed service state transition from Running → Stopped → Running
- Validated how service configuration impacts system functionality and network availability

  - Network connections from svchost.exe and Windows Azure Guest Agent
  - Background service communication to external and internal cloud endpoints

- Launched Notepad and terminated the process via Task Manager
- Confirmed immediate process removal and resource release
- Observed real-time process lifecycle behavior from a SOC monitoring perspective


### Task 6 – Explore Windows Registry & Startup Entries

- Opened Registry Editor using `regedit`

- Navigated to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- Observed:
  - Entry Name: `SecurityHealth`
  - Type: REG_EXPAND_SZ
  - Data: `%windir%\system32\SecurityHealthSystray.exe`
  - Purpose: Windows Security notification icon at startup

- Navigated to `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- Observed:
  - Entry Name: `OneDrive`
  - Type: REG_SZ
  - Data: `C:\Users\Katana\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background`
  - Purpose: Launches OneDrive in background at user logon
 - Created temporary string value `TestEntry` (REG_SZ) under HKCU Run key
- Verified new startup entry appeared in registry list
- Deleted `TestEntry` to restore original configuration

- Identified how `Run` registry keys can be leveraged for persistence mechanisms
- Reinforced awareness of registry-based startup abuse in malware investigations
 
### Task 7 – Examine Windows Networking Configuration

- Executed `ipconfig /all` to review full network configuration
- Identified:
  - IPv4 Address: 172.16.0.4
  - Subnet Mask: 255.255.255.0
  - Default Gateway: 172.16.0.1
  - DNS Server: 168.63.129.16
  - DHCP Enabled: Yes
  - Network Adapter: Microsoft Hyper-V Network Adapter

- Executed `arp -a` to review ARP table mappings
- Observed dynamic and static ARP entries for local subnet (172.16.0.x)

- Executed `netstat -ano` to review active connections and listening ports
- Identified:
  - Port 135 (RPC) listening – PID 972
  - Port 445 (SMB) listening – PID 4 (System)
  - Port 3389 (RDP) listening – PID 724
  - Multiple outbound HTTPS (443) connections in ESTABLISHED state
  - Several high ephemeral ports (49xxx–50xxx range)

- Executed `route print` to review routing table
- Confirmed default route via 172.16.0.1

- Observed no local web service actively listening on port 80
- Identified multiple outbound connections using port 443 (HTTPS)

- Demonstrated understanding of:
  - IP configuration analysis
  - ARP resolution
  - Port and PID correlation
  - Network-based process identification
  - SOC-level network visibility investigation


### Task 8 – Basic Administration Using PowerShell

- Executed `Get-Process` to enumerate all running processes
- Observed:
  - System processes including `csrss`, `lsass`, `svchost`, and `MsMpEng`
  - User processes including `powershell`, `msedgewebview2`, and `OneDrive`
  - Resource metrics such as CPU time, memory usage, and process IDs

- Executed `Get-Service` to enumerate all system services
- Identified running and stopped services including:
  - AppInfo (Application Information)
  - BITS (Background Intelligent Transfer Service)
  - DcomLaunch
  - CryptSvc

- Executed `Get-LocalUser` to enumerate local accounts
- Observed:
  - DefaultAccount (Disabled)
  - Guest (Disabled)
  - Katana (Enabled – Built-in Administrator)
  - student123 (Enabled – Standard user)
  - WDAGUtilityAccount (Disabled)

- Executed `Get-EventLog -LogName System -Newest 20`
- Reviewed recent system events including:
  - Windows Update installation events
  - DHCP client service start events
  - TPM provisioning messages
  - DCOM warning entries

- Filtered services using:
  - `Get-Service | Where-Object { $_.Name -like "Win*" }`
- Identified services beginning with “Win” including:
  - WinDefend (Microsoft Defender Antivirus Service)
  - WindowsAzureGuestAgent
  - WinHttpAutoProxySvc
  - Winmgmt
  - WinRM

- Exported process data using:
  - `Get-Process | Export-Csv processes.csv`
- Verified successful creation of `processes.csv` in user directory

- Demonstrated:
  - PowerShell object-based enumeration
  - Administrative visibility into processes, services, users, and logs
  - Data export for incident documentation and forensic review

