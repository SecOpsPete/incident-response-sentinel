# 🌍 Impossible Travel Detection with Microsoft Sentinel

This lab simulates the detection and investigation of **impossible travel events**—instances where a user logs in from geographically distant locations within a short timeframe, violating realistic physical travel capabilities. It follows the **NIST 800-61 Incident Response Lifecycle** and leverages **Microsoft Sentinel** and **Log Analytics** to identify and triage potentially compromised accounts.

---

## 🎯 Objective

- Detect anomalous logon behavior such as impossible travel using Microsoft Sentinel  
- Build a KQL query and scheduled analytics rule to automate detection  
- Investigate suspicious activity in Microsoft Sentinel  
- Contain potential threats and validate outcomes  
- Document findings and follow NIST-aligned response steps  

---

## 1. 🧰 Preparation (NIST IR Step 1)

Organizations often prohibit:
- Logging in from outside approved geographic regions  
- Account sharing  
- Use of personal or non-corporate VPNs  

These policies reduce the likelihood of account compromise and unauthorized access. In this lab, we simulate a user account logging in from **Virginia** and **California** within a **43-minute window**, which is physically impossible and strongly indicative of account misuse or credential compromise.

Azure sign-in data is collected in the `SigninLogs` table and sent to **Log Analytics**, where **Microsoft Sentinel** consumes it to generate incidents via scheduled query rules.

---

## 2. 🔎 Detection and Analysis (NIST IR Step 2)

### 🔍 Initial Log Review in Log Analytics

To begin, I reviewed logon patterns for unusual geographic activity. A simple KQL query helps visualize where and when users authenticated:

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| summarize Count = count() by UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
```
<br>

![WhereAndWhen](images/WhereAndWhen.png)

---

Then I developed (using ChatGPT) the full query to:
- Look at sign-in events within the past 7 days,
- Group the sign-ins by user and location,
- Keep only the relevant fields (summarize),
- and finally count how many distinct locations each user logged in from.
<br>

```kusto
let TimePeriodThreshold = timespan(7d); 
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

![Login Data](images/LoginData1.png)

---

### ⚙️ Sentinel Scheduled Analytics Rule

Next I defined a rule that triggers if a user logs in from more than two distinct locations within a 7-day period:



![Query Rule](images/QueryRule2.png)

Once implemented, this rule generated an incident for further investigation.

---

### 📥 Incident Alert in Sentinel

After detection, Microsoft Sentinel generated an incident based on our scheduled rule. The alert includes user identity, timestamps, and geolocation metadata. Then following steps were taken in Sentinel:
- Incident Automatically Created
- Incident assigned to self
- Status Active
- Invesitage designation started

![Incident Details](images/IncidentDetails3.png)<br><br>

---

### 🎯 Flagged Users Visualization

I then created a visualization using Microsoft Sentinel to see the relationships of flagged results.

![Incident Map](images/IncidentMap3.png)

---

### 🔎 Focused User Review

40 accounts were flagged by the detection logic. One of particular interest was:

**User:** `8c9531dd55d5d979611a18cec5947654ff7d25aa403fe8bf026dddbdb801aace@lognpacific.com`

Further analysis was required to make the determination the locations where each individual account had been logging in from to determine whether the alert results were indeed concerning. I ran the following query (using ChatGPT) to assess logins for each suspect account:

```kusto
let TimePeriodThreshold = timespan(7d); 
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "8c9531dd55d5d979611a18cec5947654ff7d25aa403fe8bf026dddbdb801aace@lognpacific.com"
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

**Findings:**

It was determined there was one user account that met the criteria for a TRUE POSITIVE:

| Timestamp                  | Location       |
|----------------------------|----------------|
| 6/5/2025, 1:41:47 AM       | Los Angeles, CA, US |
| 6/5/2025, 12:58:40 AM      | Boydton, VA, US     |

![Impossible Travel](images/ImpossibleTravel4.png)

✅ **Conclusion**: 43 minutes between logins in California and Virginia confirms impossible travel.

---

## 3. 🚨 Containment, Eradication, and Recovery (NIST IR Step 3)

### 🛡️ Incident Response Actions

- **User account disabled** in Entra ID  
- Labeled as a **True Positive** incident  
- No signs of lateral movement found
<br>

To further contain possible malicious follow-up behavior, I queried related Azure activity:

```kusto
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "c5a45653-9ba5-4679-8d26-cb73cbbd7307"
```

![Other User Activity](images/OtherUserActivity5.png)

### ✅ No suspicious or unauthorized activity was identified beyond the initial anomaly
<br>

### Commenting, Documentation and Incident Closing

Following containment and eradication, all incident lifecycle findings were documented in the Incident report in Sentinel. Response actions and outcome were also fully documented. Once fully investigated, the incident categorized as TRUE POSITIVE and was closed with a detailed INCIDENT ACTIVITY LOG in Sentinel, marking the completion of the investigation lifecycle.

---

### 📋 Post-Incident Activity (NIST IR Step 4)  
🛠️ **Lessons Learned & Recommendations**

**Policy Considerations:**  
While geo-fencing cannot be enabled in the current environment, it’s highly recommended in enterprise deployments to restrict authentication by country or region. This reduces the risk of credential misuse from high-risk geographies.

**Logging Enhancements:**  
Consider building a dashboard to continuously monitor anomalous travel patterns using enriched sign-in data. Incorporate logic to correlate sign-ins across cities, timestamps, and known infrastructure to help prioritize high-fidelity alerts.

**VPN Usage – Analyst Considerations:**  
VPNs and cloud proxies can obscure a user’s true location, frequently causing false positives in impossible travel alerts. Analysts should take the following steps to reduce noise and improve detection accuracy:
- **Tag known corporate VPN exit nodes** using IP watchlists and enrich sign-in logs accordingly.
- **Cross-reference sign-ins by session ID, device ID, or user agent**—if the same session appears in two distant locations within a short time, it’s likely a VPN, not a breach.
- **Flag commercial VPN or anonymizer IPs** using threat intelligence feeds or Microsoft’s location context enrichment (if available).
- **Consider behavior continuity**—smooth, uninterrupted sign-ins across locations often indicate VPN use rather than credential theft.
- **Document known false positive patterns** and refine KQL queries or analytics rules to exclude these where appropriate.

These techniques help ensure analysts focus on true positives and reduce alert fatigue in geo-based anomaly detection.

---

## ✅ Closure

- Reviewed and confirmed incident as a **True Positive**  
- No additional risk detected post-isolation  
- Final classification: **Benign Positive**  
- Case was documented and closed in Sentinel  
- All required NIST IR lifecycle steps were followed

---

*This lab demonstrates how to detect and investigate suspicious authentication behavior using Microsoft Sentinel and KQL, following the structured NIST Incident Response framework to guide investigation, containment, and resolution.*
