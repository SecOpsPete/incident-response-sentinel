# 🧠 Incident Response Labs

This repository contains hands-on labs and detection engineering projects designed to simulate incident response workflows using Microsoft Sentinel. Each lab focuses on a specific threat scenario and aligns with the NIST 800-61 incident handling lifecycle, including preparation, detection, analysis, containment, and remediation.

> 🔎 Tools featured include Kusto Query Language (KQL), Azure Log Analytics, and Microsoft Sentinel Analytics Rules.

---

## 📂 Labs


- 🌍 **[Impossible Travel Detection with Microsoft Sentinel](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/impossible-travel-detection-sentinel)**  
  Identifies suspicious sign-ins from geographically distant locations within short timeframes, suggesting potential credential compromise. Includes Sentinel rule creation, KQL investigation, and full incident response aligned with NIST 800-61.

- ⚡ **[PowerShell Suspicious Web Request Detection](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/ps-suspicious-web-request)**  
  Simulates malicious use of PowerShell to download remote payloads using `Invoke-WebRequest`. Walks through Sentinel detection, incident investigation, and response using MDE and NIST 800-61 lifecycle.

- 🔐 **[Brute Force Detection with Microsoft Sentinel](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/brute-force-detection-sentinel)**  
  Detects repeated failed login attempts from the same remote IP address using KQL and Sentinel scheduled analytics rules, mapped to MITRE ATT&CK T1110 (Brute Force).

- 🗺️ **[Log Visualizations with Microsoft Sentinel](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/log-visualizations)**  
  Geolocates authentication failures, malicious traffic, and unauthorized resource creation using custom KQL queries, IP enrichment with a geoip watchlist, and Sentinel workbook heatmaps. Supports visual threat analysis and correlation of log data across Entra ID and Azure infrastructure.

- 🧠 **[UnInstDaemon.exe High CPU Incident Response](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/the-daemon-that-wouldnt-quit)**  
  Investigates a suspicious Microsoft-signed executable (`UnInstDaemon.exe`) running from the Temp directory with excessive CPU usage. Walks through process triage, signature validation, VirusTotal analysis, Windows update correlation, and forensic cleanup. A complete Windows IR drill with tooling, registry and persistence checks, and lessons learned — aligned with real-world SOC response        practices.


---

## 🧭 Incident Response Lifecycle Reference

These labs are structured around the [NIST SP 800-61 Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) guidelines, simulating real-world detection and response processes:

1. **Preparation** – Establish detection rules and telemetry
2. **Detection & Analysis** – Query log data and generate alerts
3. **Containment, Eradication & Recovery** – Simulated or real investigation actions
4. **Post-Incident Activity** – Documentation, closure, and learning

---

> More labs coming soon: Insider Threats, Beaconing, Credential Dumping, and Data Exfiltration scenarios.
