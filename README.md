# 🧠 Incident Response with Microsoft Sentinel

This repository contains hands-on labs and detection engineering projects designed to simulate incident response workflows using Microsoft Sentinel. Each lab focuses on a specific threat scenario and aligns with the NIST 800-61 incident handling lifecycle, including preparation, detection, analysis, containment, and remediation.

> 🔎 Tools featured include Kusto Query Language (KQL), Azure Log Analytics, and Microsoft Sentinel Analytics Rules.

---

## 📂 Labs

- 🔐 **[Brute Force Detection with Microsoft Sentinel](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/brute-force-detection-sentinel)**  
  Detects repeated failed login attempts from the same remote IP address using KQL and Sentinel scheduled analytics rules, mapped to MITRE ATT&CK T1110 (Brute Force).


---

## 🧭 Incident Response Lifecycle Reference

These labs are structured around the [NIST SP 800-61 Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) guidelines, simulating real-world detection and response processes:

1. **Preparation** – Establish detection rules and telemetry
2. **Detection & Analysis** – Query log data and generate alerts
3. **Containment, Eradication & Recovery** – Simulated or real investigation actions
4. **Post-Incident Activity** – Documentation, closure, and learning

---

> More labs coming soon: Insider Threats, Beaconing, Credential Dumping, and Data Exfiltration scenarios.
