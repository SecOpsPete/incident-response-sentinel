# 📍 Microsoft Sentinel Log Visualizations & Attack Maps

This project demonstrates how Microsoft Sentinel — a cloud-native SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation, and Response) solution — can be used to create real-time threat intelligence maps using custom KQL queries and geolocation data.

Each workbook in this lab visualizes a different type of security event such as failed logins, malicious flows, or unauthorized resource creation. Custom queries were executed in Microsoft Sentinel’s *Advanced Editor* within Workbooks and validated using the Log Analytics workspace. Location-based data was enriched using a custom IP geolocation watchlist (`geoip`) and rendered using heatmap-style attack maps.

---

## 🎯 Project Goals

- Showcase Sentinel's visual capabilities for incident response and threat detection
- Learn how to build interactive workbook maps using real telemetry
- Practice KQL-based query building and geolocation enrichment
- Correlate log data to visualize network or identity-based threats

---

## 🧠 Understanding Sentinel’s Role

Microsoft Sentinel provides unified visibility across your cloud and on-premise environments. It ingests logs through Data Connectors and stores them in a Log Analytics workspace where you can:

- Run **KQL queries** against structured security tables (e.g., `SigninLogs`, `AzureActivity`, `SecurityEvent`)
- Create **Workbooks** to visualize trends, map telemetry, and track threats
- Trigger **Analytics Rules** to generate alerts and orchestrate SOAR playbooks

---

## 🛠️ Lab Workflow

### Step-by-Step

1. **Log into Microsoft Sentinel**
   - Navigate to your chosen workspace
   - Ensure connectors (Azure AD, NSG, Security Events) are sending logs

2. **Prepare the Workbook**
   - Go to *Workbooks* → *Add Workbook*
   - Select **Advanced Editor**
   - Paste the KQL query (see `.kql` files)

3. **Enable Map Visualization**
   - Change Visualization to `Map`
   - Configure location using:
     - Latitude / Longitude (from watchlist or log field)
     - Labels for readability
     - Heatmap for visual intensity

4. **Add Geolocation Enrichment**
   - Upload a watchlist called `geoip` with IP, latitude, longitude, and location metadata
   - Use `ipv4_lookup()` to match incoming IPs

5. **Validate in Log Analytics**
   - Run query directly in *Log Analytics* to confirm outputs and test filters

---

## 🌍 Attack Maps & Query Summaries

### 🔴 Azure Authentication Failures (`AzureAuthFailures.kql`)

📌 **Query Summary**:
Uses `DeviceLogonEvents` where `ActionType == "LogonFailed"`, enriched with GeoIP watchlist to show failed logins by city/country.

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP, City = cityname, Country = countryname, 
          friendly_location = strcat(cityname, " (", countryname, ")"), Latitude = latitude, Longitude = longitude;
```

🖼️ **Screenshot**:  
![AzureAuthFailures](log-visualizations/AzureAuthFailures.png)

---

### 🟢 Azure Authentication Successes (`AzureAuthSuccess.kql`)

📌 **Query Summary**:
Visualizes successful logins from `SigninLogs`, grouped by user and geolocation using built-in `LocationDetails`.

```kql
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity, 
          Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), 
          Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), 
          City = tostring(LocationDetails["city"]), 
          Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, 
         friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

🖼️ **Screenshot**:  
![AzureAuthSuccess](log-visualizations/AzureAuthSuccess.png)

---

### ⚠️ Malicious Traffic Flows (`MaliciousTrafficFlow.kql`)

📌 **Query Summary**:
Parses `AzureNetworkAnalytics_CL` for `FlowType_s == "MaliciousFlow"` and applies `ipv4_lookup()` to locate attacker IPs.

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows = AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow"
| order by TimeGenerated desc
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, 
          DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, 
          Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, 
          NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, 
          friendly_location = strcat(cityname, " (", countryname, ")")
```

🖼️ **Screenshot**:  
![MaliciousTrafficFlow](log-visualizations/Malicious-Traffic.png)

---

### 🏗️ Resource Creation Activity (`ResourceCreation.kql`)

📌 **Query Summary**:
Detects successful resource creation operations by filtering `AzureActivity`, then geolocates IPs via watchlist.

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F\-]{36}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller, CallerPrefix = split(Caller, "@")[0], CallerIpAddress, ResouceCreationCount, 
          Country = countryname, Latitude = latitude, Longitude = longitude, 
          friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)
```

🖼️ **Screenshot**:  
![ResourceCreation](log-visualizations/ResourceCreation.png)

---

### 🔐 VM Authentication Failures (`VMAuthenticationFailures.kql`)

📌 **Query Summary**:
Filters `SigninLogs` for failed logins excluding service principals, then groups and maps identity sources.

```kql
SigninLogs
| where ResultType != 0 and Identity !contains "-"
| summarize LoginCount = count() by Identity, 
          Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), 
          Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), 
          City = tostring(LocationDetails["city"]), 
          Country = tostring(LocationDetails["countryOrRegion"])
| order by LoginCount desc
| project Identity, Latitude, Longitude, City, Country, LoginCount, 
         friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

🖼️ **Screenshot**:  
![VMAuthenticationFailures](log-visualizations/VMAuthentication-Failures.png)

---

## 🧪 Future Enhancements

- Integrate **Analytics Rules** to alert on thresholds or patterns
- Enrich with **Threat Intelligence** indicators
- Use **Notebooks** to conduct post-incident forensic analysis
- Map detections to **MITRE ATT&CK** techniques

---

## ✅ Summary

This lab highlights how Microsoft Sentinel transforms raw telemetry into geolocation-driven insights. By leveraging the power of KQL, watchlists, and workbook visualizations, defenders can more easily identify threats, monitor behavior, and respond proactively.

> 📍 Every map here was built from real or simulated logs using Microsoft-native tools — no third-party ingestion required.

---

## 👤 Author

**Peter Van Rossum**  
Cybersecurity Analyst | GitHub: [@SecOpsPete](https://github.com/SecOpsPete)

---

## 📝 License

MIT License – free to use, modify, and share with credit.

