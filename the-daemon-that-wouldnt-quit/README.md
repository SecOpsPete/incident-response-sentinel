# 🛡️ UnInstDaemon.exe High CPU Event

**Date Identified:** July 19, 2025  
**Analyst:** Peter Van Rossum  
**System:** Windows 11 Pro (User: `peter`)  

---

## 🧩 Incident Summary

A suspicious process named `UnInstDaemon.exe` was discovered consuming over **2,000 seconds of CPU time**. It was located in a temporary directory:

```
C:\Users\peter\AppData\Local\Temp\bwpce2d3397-4295-4a09-89aa-bba6e45110d5\UnInstDaemon.exe
```

The filename, CPU behavior, and location initially raised concerns about malware.

---

## 🧪 Investigation Timeline

### 🔹 Initial Discovery

- Observed abnormal CPU usage using PowerShell:
  ```powershell
  Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
  ```
- `UnInstDaemon.exe` was at the top with over 2,000 seconds of CPU time.

### 🔹 File Path Inspection

- Located the executable:
  ```powershell
  Get-Process -Name UnInstDaemon | Select-Object Path, Id
  ```

- Path revealed it was running from the `%TEMP%` directory, a suspicious location for a long-running binary.

### 🔹 Signature Verification

- Validated the digital signature:
  ```powershell
  Get-AuthenticodeSignature -FilePath "C:\Users\peter\AppData\Local\Temp\bwpce2d3397-4295-4a09-89aa-bba6e45110d5\UnInstDaemon.exe"
  ```

- Output confirmed it was **signed by Microsoft Corporation** with a valid certificate chain.

### 🔹 VirusTotal Analysis

- Uploaded the file to [VirusTotal](https://virustotal.com)
- **Result:** 0/72 detections, confirming no antivirus engines flagged it

---

## 🧩 Triage & System Correlation

### 🔹 Application Install Review

- Reviewed recently installed/upgraded apps via GUI:
  - **Settings → Apps → Installed Apps**
  - Sorted by **Install Date**

- Identified `Microsoft Update Health Tools` was installed on **July 16, 2025** — matching the file signature and likely source of the temp executable.

### 🔹 Reliability Monitor Review

- Opened Reliability Monitor:
  ```shell
  perfmon /rel
  ```

- Checked for anomalies around July 16–19, 2025
- Confirmed that:
  - `Microsoft Update Health Tools` was recently installed
  - No application crashes were directly tied to `UnInstDaemon.exe`
  - Windows Updates occurred July 19, suggesting a correlation to servicing stack cleanup behavior

---

## 🧼 Remediation Actions Taken

### 🔸 1. Kill the Process

```powershell
Stop-Process -Name UnInstDaemon -Force
```

### 🔸 2. Delete the Executable and Parent Folder

```powershell
Remove-Item -Path "C:\Users\peter\AppData\Local\Temp\bwpce2d3397-4295-4a09-89aa-bba6e45110d5" -Recurse -Force
```

### 🔸 3. Check for Persistence Mechanisms

#### Registry `Run` Keys

```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |
  Where-Object { $_.PSObject.Properties.Name -match "UnInstDaemon" }

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" |
  Where-Object { $_.PSObject.Properties.Name -match "UnInstDaemon" }
```

#### Scheduled Tasks

```powershell
Get-ScheduledTask | Where-Object { $_.TaskName -match "UnInstDaemon" }
```

#### Startup Folder

```powershell
Test-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\UnInstDaemon.lnk"
```

### 🔸 4. Final Process Check

```powershell
Get-Process -Name UnInstDaemon -ErrorAction SilentlyContinue
```

### 🔸 5. Final File Check

```powershell
Test-Path "C:\Users\peter\AppData\Local\Temp\bwpce2d3397-4295-4a09-89aa-bba6e45110d5\UnInstDaemon.exe"
```

> Both checks returned no results — confirmed clean.

---

## 📅 Correlated Activity Timeline

| Date        | Event Type         | Details |
|-------------|--------------------|---------|
| July 16, 2025 | App Installed      | **Microsoft Update Health Tools** (likely dropped the file) |
| July 16, 2025 | Defender Update    | Security Intelligence Update applied |
| July 19, 2025 | Windows Updates    | Multiple system updates applied |
| July 19, 2025 | Reliability Monitor | Detected Acrobat install warning (unrelated) |

---

## 🧠 Root Cause Analysis

### 🔍 Leading Theory: **Windows Update Health Tools**

- This tool is designed to prep systems for major updates and often drops cleanup executables in Temp.
- The file was **Microsoft-signed**, located in `%TEMP%`, and matched the **Update Health Tools** install date.
- The process likely failed to exit cleanly after a patch cycle or component servicing event, causing CPU resource exhaustion.

---

## ✅ Conclusion

While `UnInstDaemon.exe` initially appeared suspicious due to its high CPU usage and TEMP folder location, further investigation confirmed it was a **legitimate Microsoft-signed binary**, likely deployed by **Microsoft Update Health Tools** or a **Servicing Stack Update**.

The process was safely terminated, the file removed, and all persistence checks came back clean.

**Status:** Closed  
**Root Cause:** Microsoft cleanup utility failed to exit  
**Severity:** Low  
**Impact:** High CPU usage  
**Action Taken:** Manual termination and validation  
