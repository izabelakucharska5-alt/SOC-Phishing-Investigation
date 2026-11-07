# SOC Investigation — Microsoft 365 Phishing Campaign

**Investigation type:** Phishing and suspected account compromise  
**Role:** SOC Analyst L1  
**Environment:** Splunk  
**Dataset:** `simulated_logs_fixed.csv`  
**Investigation date:** 5 November 2026  
**Status:** Investigation completed — suspected account compromise identified  
**Priority:** High

---

## 1. Investigation Overview

The objective of this investigation was to identify a suspected phishing campaign, determine its impact on employees, investigate suspicious authentication activity and assess whether an employee account may have been compromised.

The investigation was conducted in Splunk using synthetic email gateway, proxy and authentication logs.

The analysis followed these stages:

1. Initial event overview.
2. Identification of phishing URL clicks.
3. Review of authentication activity.
4. Correlation of phishing interactions with sign-in events.
5. Email authentication analysis.
6. Identification of phishing campaign recipients.
7. Assessment of recipient impact.
8. Identification of account compromise indicators.
9. Investigation of anomalous authentication.
10. Reconstruction of the affected user's event timeline.
11. Review of activity following the suspicious sign-in.

## 2. Investigation Steps

### 2.1. Initial Event Overview

**Objective:** Establish the scope of available security events and identify the main event categories.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv"
| stats count by event_type
| sort - count
```

**Results:**

- 12 `email_received` events.
- 3 `signin` events.
- 3 `url_click` events.

**Analysis:**

The dataset contains 12 email delivery events, three authentication events and three recorded visits to suspicious URLs.

The event distribution established the initial scope of the investigation and indicated that further analysis of the phishing campaign and authentication activity was necessary.

**Evidence:**

![Initial Event Overview](Screenshots/02-event-overview.png)

---

### 2.2. Identification of Phishing URL Clicks

**Objective:** Identify employees who interacted with the suspicious URL.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" event_type="url_click"
| stats count by user
| sort - count
```

**Results:**

Three employees were identified:

- Anna Kowalska
- Piotr Nowak
- Marta Zielińska

Each employee generated one URL click event.

**Analysis:**

Three out of twelve recipients interacted with the suspicious link.

These employees were identified as potentially affected users and selected for further investigation.

The logs confirm URL visits but do not establish whether credentials were submitted.

**Evidence:**

![Phishing URL Clicks](Screenshots/03-phishing-url-clicks.png)

---

### 2.3. Sign-in Activity Review

**Objective:** Examine authentication activity and establish the normal sign-in pattern for the investigated user.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska" event_type="signin"
| table _time user src_ip src_location device_id action result mfa risk details
| sort 0 _time
```

**Results:**

Anna's authentication history showed:

- Two successful sign-ins from `198.51.100.10`.
- Both sign-ins originated from Warsaw, Poland.
- Both used the known device `ANN-LAPTOP-01`.
- Both were classified as Low risk.
- A third successful sign-in originated from a different IP and location.

**Analysis:**

The first two authentication events established a consistent sign-in pattern.

The third event represented a significant deviation from the previously observed activity and required further investigation.

**Evidence:**

![Sign-in Activity](Screenshots/04-signin-activity.png)

---

### 2.4. Correlation of Phishing and Authentication Events

**Objective:** Correlate phishing URL visits with authentication activity to identify potentially related security events.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska"
| search event_type="url_click" OR event_type="signin"
| table _time event_type user src_ip src_location device_id action result mfa risk url
| sort 0 _time
```

**Results:**

Five relevant events were identified in Anna's activity:

- Two earlier successful sign-ins from Warsaw.
- One phishing URL visit.
- One suspicious successful sign-in from Berlin.
- The corresponding email delivery event in the investigation timeline.

The critical timestamps were:

- 09:15 — Anna visited the suspicious URL.
- 09:18 — A successful sign-in occurred from Berlin.

**Analysis:**

The suspicious authentication occurred three minutes after Anna visited the phishing URL.

This temporal correlation increased the priority of the investigation.

The timing alone does not prove that the phishing interaction directly caused the suspicious authentication.

**Evidence:**

![Anna Event Correlation](Screenshots/05-anna-event-correlation.png)

---

### 2.5. Email Authentication Analysis

**Objective:** Investigate the suspicious email and examine its sender domain and email authentication results.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" event_type="email_received"
| stats count values(sender) as senders values(domain) as domains values(spf) as spf values(dkim) as dkim values(dmarc) as dmarc by subject
```

**Results:**

The search returned 12 email events associated with the same subject.

Identified indicators:

- Sender: `no-reply@micros0ft365.example`
- Domain: `micros0ft365.example`
- Subject: `[Action required] Your mailbox will be suspended in 24 hours`
- SPF: `fail`
- DKIM: `none`
- DMARC: `fail`

**Analysis:**

The message impersonated Microsoft 365 and used an urgent mailbox suspension warning to encourage recipients to interact with the link.

The sender domain used a zero instead of the letter 'o'.

The authentication results provided additional indicators of a suspicious message.

**Assessment:** Malicious phishing email.

**Evidence:**

![Email Authentication Analysis](Screenshots/06-email-authentication.png)

---

### 2.6. Phishing Campaign Recipient Identification

**Objective:** Identify all recipients of the suspicious email and verify the campaign's distribution scope.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" event_type="email_received"
| stats count by recipient sender source_ip domain
| sort recipient
```

**Results:**

The search returned 12 recipients.

All messages were associated with:

- The same sender.
- The same source IP: `203.0.113.45`.
- The same sender domain: `micros0ft365.example`.

Each recipient had one recorded delivery event.

**Analysis:**

The results indicate a single phishing campaign distributed to 12 employees.

This information established the initial scope for identifying potentially affected accounts.

**Evidence:**

![Phishing Campaign Recipients](Screenshots/07-phishing-campaign-recipients.png)

---

### 2.7. Recipient Impact Assessment

**Objective:** Determine which employees interacted with the phishing email and compare their activity with the total recipient population.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv"
| eval account=if(event_type="email_received",replace(recipient,"@company.example",""),user)
| stats count(eval(event_type="url_click")) as clicks count(eval(event_type="signin")) as signins values(eval(if(event_type="signin",src_ip,null()))) as signin_ips values(eval(if(event_type="signin",risk,null()))) as risk_levels by account
| where clicks>0
```

**Results:**

Three accounts were returned:

| Account | Clicks | Sign-ins |
|---|---:|---:|
| anna.kowalska | 1 | 3 |
| marta.zielinska | 1 | 0 |
| piotr.nowak | 1 | 0 |

Anna's account had three recorded sign-in events and two observed risk levels: Low and High.

**Analysis:**

All three employees who clicked the phishing URL were identified.

Anna's account required additional investigation because its authentication history contained a high-risk event.

This search connected the phishing campaign with the identity-related investigation.

**Evidence:**

![Recipient Impact](Screenshots/08-recipient-impact.png)

---

### 2.8. Identification of Account Compromise Indicators

**Objective:** Isolate suspicious authentication events associated with Anna's account.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska" event_type="signin"
| where risk="high" OR device_id="unknown" OR src_location="Berlin, Germany"
| table _time user src_ip src_location device_id result mfa risk details
| sort 0 _time
```

**Results:**

One event matched the investigation criteria.

| Field | Observed value |
|---|---|
| Timestamp | 2026-11-05 09:18:00 |
| User | anna.kowalska |
| Source IP | 203.0.113.77 |
| Location | Berlin, Germany |
| Device ID | unknown |
| Result | success |
| MFA | success |
| Risk | high |
| Device compliance | unknown |

**Analysis:**

The event differed significantly from Anna's established authentication pattern.

The combination of an unfamiliar IP, unusual geographic location, unknown device and High risk classification represents strong evidence of suspicious account activity.

Anna also denied performing this authentication.

**Assessment:** High-priority suspected account compromise.

**Evidence:**

![Account Compromise Indicators](Screenshots/09-account-compromise-indicators.png)

---

### 2.9. Detailed Analysis of the Anomalous Sign-in

**Objective:** Examine the suspicious authentication event and compare its attributes with previously observed activity.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska" event_type="signin"
| table _time src_ip src_location device_id result mfa risk details
| sort 0 _time
```

**Results:**

The suspicious event was recorded on 5 November 2026 at 09:18.

Compared with previous authentication activity:

- The source IP changed from `198.51.100.10` to `203.0.113.77`.
- The approximate location changed from Warsaw to Berlin.
- The device changed from `ANN-LAPTOP-01` to `unknown`.
- The risk classification changed from Low to High.

Authentication and MFA were both reported as successful.

**Analysis:**

Successful MFA does not establish that the legitimate account owner performed the authentication.

Further investigation would require identity-provider authentication details, session records and MFA approval history.

**Evidence:**

![Anomalous Sign-in Details](Screenshots/10-anomalous-signin-details.png)

---

### 2.10. Reconstruction of Anna's Event Timeline

**Objective:** Reconstruct the sequence of events affecting Anna's account and establish the chronological relationship between the phishing campaign and suspicious authentication.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska"
| table _time event_type src_ip src_location device_id action result mfa risk details
| sort 0 _time
```

**Results:**

| Time | Event |
|---|---|
| 08:10 | Successful sign-in from Warsaw using the known device. |
| 08:42 | Phishing email delivered. |
| 09:15 | Anna visits the suspicious URL. |
| 09:18 | Successful High-risk sign-in from Berlin using an unknown device. |

**Analysis:**

The reconstructed timeline establishes that the suspicious authentication occurred three minutes after the phishing URL visit.

Combined with the authentication anomalies and Anna's denial, the timeline supports treating the incident as a suspected account compromise.

The exact relationship between the phishing interaction and the authentication event remains unconfirmed.

**Evidence:**

![Anna Event Timeline](Screenshots/11-anna-event-timeline.png)

---

### 2.11. Post-Compromise Activity Review

**Objective:** Examine whether additional events were recorded for Anna after the suspicious authentication.

**Splunk SPL:**

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska"
| where _time >= strptime("2026-11-05 09:18:00", "%Y-%m-%d %H:%M:%S")
| table _time event_type src_ip src_location device_id action result mfa risk details
| sort 0 _time
```

**Results:**

The search returned one event: the suspicious High-risk sign-in at 09:18.

No subsequent events were present in the supplied dataset.

**Analysis:**

No additional post-authentication activity could be established from the available logs.

This does not prove that the account was not accessed further. The dataset does not contain mailbox audit records, endpoint telemetry or detailed identity-provider session activity.

Further investigation would be required to determine whether the suspicious actor accessed mailbox content, modified account settings or accessed other resources.

**Evidence:**

![Post-Compromise Activity Check](Screenshots/12-post-compromise-activity-check.png)

---

## 3. Consolidated Investigation Findings

| Finding | Result |
|---|---|
| Phishing emails delivered | 12 |
| Unique recipients | 12 |
| Employees who clicked the link | 3 |
| Suspicious email authentication | SPF fail, DKIM none, DMARC fail |
| Suspicious account | Anna Kowalska |
| Suspicious authentication | 5 November 2026, 09:18 |
| Geographic deviation | Warsaw → Berlin |
| Device deviation | Known device → Unknown |
| Sign-in risk | High |
| MFA result | Success |
| Time between URL click and suspicious sign-in | 3 minutes |

## 4. Incident Assessment

**Incident classification:** Phishing campaign with suspected account compromise.

**Affected account:** Anna Kowalska.

**Priority:** High.

The investigation identified multiple indicators consistent with unauthorized account access.

The most significant evidence includes the suspicious authentication occurring three minutes after the phishing URL visit, a change in source IP and geographic location, an unknown device, a High risk classification and the account owner's denial of the sign-in.

The available evidence supports escalation to SOC L2 / Incident Response.

However, the investigation does not establish the exact authentication method used by the attacker or prove that credentials were submitted through the phishing page.

## 5. Recommended Incident Response Actions

1. Escalate the incident to SOC L2 / Incident Response.
2. Revoke active sessions and refresh tokens associated with Anna's account.
3. Reset the account password through a trusted communication channel.
4. Review MFA registration, authentication methods and approval history.
5. Investigate mailbox access, forwarding rules, inbox rules and OAuth application permissions.
6. Review endpoint telemetry and browser activity where available.
7. Search all mailboxes for the phishing sender, subject and URL.
8. Quarantine or remove matching phishing messages.
9. Contact the other employees who clicked the suspicious URL.
10. Monitor the affected account for further suspicious authentication activity.

## 6. MITRE ATT&CK Mapping

| Technique | Name | Evidence |
|---|---|---|
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | Phishing email distributed to employees, followed by three recorded URL visits. |

No additional attack technique is confirmed by the available dataset.

## 7. Investigation Limitations

The investigation uses a limited synthetic dataset.

The available logs do not include phishing form submissions, credential capture evidence, detailed MFA prompt history, identity-provider session records, endpoint telemetry or mailbox audit events.

The investigation therefore cannot confirm how the suspicious authentication was achieved or establish the full extent of potential unauthorized access.

All IP addresses used in this exercise belong to documentation ranges reserved for examples and must not be treated as real-world malicious indicators.

## 8. Final Conclusion

This investigation demonstrates an end-to-end SOC L1 workflow, including phishing email analysis, SPL-based log investigation, user impact assessment, authentication anomaly detection, event correlation and incident escalation.

The investigation identified a phishing campaign affecting 12 employees, three recorded URL clicks and one high-priority suspected account compromise.

The evidence was sufficient to identify suspicious account activity and justify escalation to Incident Response.

Further identity, endpoint and mailbox telemetry would be necessary to confirm the attack mechanism and determine the full impact of the incident.
