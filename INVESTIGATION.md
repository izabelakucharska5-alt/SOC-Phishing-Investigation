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
- Both were
