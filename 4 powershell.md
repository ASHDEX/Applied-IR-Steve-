### ✅ **1. Active Directory Cmdlets**

#### `Get-ADComputer`

- **Purpose**: Retrieves information about a computer object from Active Directory.
    
- **Example Use**: Identify computers in a specific OU, check last logon time, OS version, or description.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-ADComputer -Filter * -Property LastLogonDate,OperatingSystem`
    

#### `Get-ADUser`

- **Purpose**: Fetches domain user account info (logon info, groups, password policies).
    
- **Example Use**: Investigating account lockouts, privilege escalations, or anomalous logons.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-ADUser -Identity "jdoe" -Properties LastLogonDate, MemberOf`
    

> 🔒 Note: These cmdlets are part of the **ActiveDirectory module**, available in RSAT.

---

### 📁 **2. File System and Registry Cmdlets**

#### `Get-ChildItem`

- **Purpose**: Lists files, folders, or registry keys in a path.
    
- **Example Use**: Identify suspicious scripts or unauthorized files.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-ChildItem -Path C:\Users\Public\Scripts\ -Recurse`
    

#### `Get-Content`

- **Purpose**: Reads contents of a file (log, config, or script).
    
- **Example Use**: Review PowerShell logs, suspicious scripts, or dumped credentials.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-Content -Path C:\Windows\System32\LogFiles\some.log`
    

#### `Get-ItemProperty`

- **Purpose**: Reads values from registry or file attributes.
    
- **Example Use**: Extract Run keys to find persistence mechanisms.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"`
    

#### `Get-LocalUser`

- **Purpose**: Lists local user accounts on a machine.
    
- **Example Use**: Detect rogue or newly created users.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-LocalUser`
    

---

### 🌐 **3. Network Cmdlets**

#### `Get-NetTCPConnection`

- **Purpose**: Shows active TCP connections, with ports, states, and IPs.
    
- **Example Use**: Check for backdoors, remote shells, or connections to C2 servers.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}`
    

#### `Get-NetUDPEndpoint`

- **Purpose**: Displays active UDP listening endpoints.
    
- **Example Use**: Identify apps using UDP (e.g., DNS tunneling).
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-NetUDPEndpoint`
    

---

### 🧠 **4. Process and Service Cmdlets**

#### `Get-Process`

- **Purpose**: Lists running processes.
    
- **Example Use**: Spot unauthorized or malicious processes (e.g., Mimikatz, encoded PowerShell).
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-Process | Sort-Object CPU -Descending`
    

#### `Get-Service`

- **Purpose**: Lists Windows services and their status.
    
- **Example Use**: Look for suspicious services (often used for persistence).
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-Service | Where-Object {$_.Status -eq "Running"}`
    

---

### 🧾 **5. Event Log Access**

#### `Get-EventLog`

- **Purpose**: Legacy cmdlet to query logs (Application, System, Security).
    
- **Limitation**: Cannot access modern log sources or XML queries.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-EventLog -LogName Security -Newest 50`
    

#### `Get-WinEvent`

- **Purpose**: Preferred, modern method for querying logs.
    
- **Example Use**: Investigate 4624 (logon), 4670 (permissions), or PowerShell logs (4104).
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624} -MaxEvents 10`
    

---

### ⚙️ **6. WMI / CIM Cmdlets**

#### `Get-WmiObject`

- **Purpose**: Legacy cmdlet for accessing WMI data (processes, BIOS, etc.).
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-WmiObject -Class Win32_BIOS`
    

#### `Get-CimInstance` _(Recommended)_

- **Purpose**: Modern replacement using WSMan; better performance and compatibility.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-CimInstance -ClassName Win32_LogicalDisk`
    

> ⚠️ Tip: Avoid `Get-WmiObject` on newer systems unless absolutely required.

---

### 🔁 **7. Looping and Automation**

#### `ForEach-Object`

- **Purpose**: Loops through items in a pipeline.
    
- **Example Use**: Run a command for every user or file.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Get-LocalUser | ForEach-Object { $_.Name }`
    

---

### 📜 **8. Session Recording**

#### `Start-Transcript` / `Stop-Transcript`

- **Purpose**: Records all console activity into a log file.
    
- **Example Use**: Document forensic steps during IR.
    
- **Usage**:
    
    powershell
    
    CopyEdit
    
    `Start-Transcript -Path "C:\IR-Logs\Session1.txt" # ... run commands ... Stop-Transcript`
    

---

### 🎯 Summary Table

| **Cmdlet**             | **Category**       | **Common Use Case**                     |
| ---------------------- | ------------------ | --------------------------------------- |
| `Get-ADComputer`       | AD Query           | List & analyze computer accounts        |
| `Get-ADUser`           | AD Query           | Investigate user accounts               |
| `Get-ChildItem`        | File System        | Enumerate files/dirs/registry keys      |
| `Get-Content`          | File Access        | Read logs, config, scripts              |
| `Get-ItemProperty`     | Registry           | Analyze startup persistence             |
| `Get-LocalUser`        | User Accounts      | Detect suspicious local users           |
| `Get-NetTCPConnection` | Network            | View active TCP connections             |
| `Get-NetUDPEndpoint`   | Network            | View UDP listeners                      |
| `Get-Process`          | Processes          | Detect suspicious or unknown processes  |
| `Get-Service`          | Services           | Check for malicious/persistent services |
| `Get-EventLog`         | Event Log (Legacy) | Basic log inspection                    |
| `Get-WinEvent`         | Event Log (Modern) | Detailed log inspection                 |
| `Get-WmiObject`        | System Info        | Legacy system info queries              |
| `Get-CimInstance`      | System Info        | Modern, preferred system info queries   |
| `ForEach-Object`       | Scripting          | Loop through multiple objects           |
| `Start-Transcript`     | Logging            | Record command activity for reports     |
### 💻 **PowerShell Remoting and WinRM – Explained**

---

#### 🔧 **What is WinRM?**

- **WinRM (Windows Remote Management)** is Microsoft's implementation of the **WS-Management** protocol — an open standard by the **DMTF (Distributed Management Task Force)**.
    
- It enables **remote management of Windows systems** via command-line tools, especially **PowerShell Remoting**.
    

---

#### 🌐 **Underlying Protocol**

- WinRM communicates using **SOAP (Simple Object Access Protocol)**, a messaging protocol for exchanging structured data in web services.
    
- It wraps SOAP messages in HTTP or HTTPS for transport.
    

---

### 🔐 **Ports Used by WinRM**

|**Protocol**|**Transport**|**Default Port**|**When to Use**|
|---|---|---|---|
|HTTP|Unencrypted transport, but encrypted payload|`TCP 5985`|Default in **domain environments** with **Kerberos**|
|HTTPS|Encrypted transport (TLS/SSL)|`TCP 5986`|Use in **non-domain environments** with **TLS certs**|

> ❗Note: Port 5895 and 5896 are **incorrect**; the correct WinRM ports are:
> 
> - `5985` for HTTP
>     
> - `5986` for HTTPS
>     

Steve Anson likely meant these standard ports, as Microsoft officially documents them.

---

### 🔐 **Encryption Details**

- Even when using **HTTP (`5985`)**, **PowerShell Remoting encrypts** the session using **Kerberos**, **NTLM**, or **Negotiate** authentication protocols.
    
- With **HTTPS (`5986`)**, **TLS encryption** is applied on top, ideal for systems **outside a domain**.
    

---

### 🏢 **Domain vs. Non-Domain Scenarios**

|**Scenario**|**Recommended Transport**|**Authentication**|**Reason**|
|---|---|---|---|
|Domain-joined machines|HTTP over TCP 5985|Kerberos|Kerberos ensures mutual trust and encryption|
|Non-domain (e.g., workgroup)|HTTPS over TCP 5986|Certificate-based|Kerberos not available; TLS cert needed for secure identity validation|

---

### 🔄 **How PowerShell Remoting Works**

1. Client sends a connection request via WinRM using either HTTP or HTTPS.
    
2. Mutual authentication happens:
    
    - **Kerberos** (if in a domain)
        
    - **Certificate** or **NTLM** (if outside domain)
        
3. SOAP messages are exchanged over the session.
    
4. Commands are executed remotely, and encrypted responses are sent back.
    

---

### ✅ **Useful PowerShell Remoting Commands**

powershell

CopyEdit

`# Enable PowerShell Remoting (run as admin) Enable-PSRemoting -Force  # Test if a remote machine is accepting WinRM connections Test-WSMan -ComputerName targetHost  # Run a command on a remote computer Invoke-Command -ComputerName targetHost -ScriptBlock { Get-Process }  # Start an interactive session Enter-PSSession -ComputerName targetHost`

---

### 🔒 Security Note

Even with HTTP (`5985`), data is **encrypted** (but not the initial transport handshake), which is why **HTTPS (`5986`) is preferred** outside of trusted environments