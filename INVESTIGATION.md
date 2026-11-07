## 6. Splunk investigation — executed SPL searches

The investigation was conducted in Splunk using the synthetic dataset `simulated_logs_fixed.csv`. The following searches were executed to identify the phishing campaign, determine its impact, and investigate suspicious activity associated with Anna Kowalska's account.

### A. Event overview for Anna Kowalska

**Purpose:** Review Anna's email, URL click, and sign-in events in chronological order.

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska"
| search event_type="url_click" OR event_type="signin"
| table _time event_type user src_ip src_location device_id action result mfa risk url
| sort 0 _time
```

**Observed results:** Four events were returned: two earlier successful sign-ins from Warsaw, one URL click at 09:15, and one successful High-risk sign-in from Berlin at 09:18.

### B. Email authentication analysis

**Purpose:** Identify suspicious email authentication results and determine whether multiple messages belong to the same campaign.

```spl
index=main source="simulated_logs_fixed.csv" event_type="email_received"
| stats count values(sender) as senders values(domain) as domains values(spf) as spf values(dkim) as dkim values(dmarc) as dmarc by subject
```

**Observed results:** 12 email events were returned under the same subject: `[Action required] Your mailbox will be suspended in 24 hours`. The sender was `no-reply@micros0ft365.example`. Authentication results were SPF fail, DKIM none, and DMARC fail.

### C. Phishing campaign recipient impact

**Purpose:** Identify the recipients affected by the phishing campaign and review the sender and source IP associated with the messages.

**Observed results:** 12 unique recipients were identified. All messages came from `no-reply@micros0ft365.example`, with source IP `203.0.113.45` and domain `micros0ft365.example`.

*Note: The screenshot documents the results, but does not show the complete SPL query. The exact executed command is therefore not reproduced here.*

### D. Identify users who clicked the phishing link

**Purpose:** Compare the number of email deliveries and URL clicks for each account.

```spl
index=main source="simulated_logs_fixed.csv"
| eval account=if(event_type="email_received",replace(recipient,"@company.example",""),user)
| stats count(eval(event_type="url_click")) as clicks count(eval(event_type="signin")) as signins values(eval(if(event_type="signin",src_ip,null()))) as signin_ips values(eval(if(event_type="signin",risk,null()))) as risk_levels by account
| where clicks>0
```

**Observed results:** Three accounts had recorded phishing URL clicks:

- Anna Kowalska — 1 click, 3 sign-ins, two observed source IPs and High/Low risk levels.
- Marta Zielińska — 1 click.
- Piotr Nowak — 1 click.

Anna's activity stood out because her account had additional suspicious authentication activity.

### E. Investigate the suspicious sign-in

**Purpose:** Isolate Anna's sign-in events with a High-risk rating, unknown device, or Berlin location.

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska" event_type="signin"
| where risk="high" OR device_id="unknown" OR src_location="Berlin, Germany"
| table _time user src_ip src_location device_id result mfa risk details
| sort 0 _time
```

**Observed results:** One event was returned:

- Time: 5 November 2026, 09:18
- Source IP: `203.0.113.77`
- Location: Berlin, Germany
- Device ID: `unknown`
- Result: success
- MFA: success
- Risk: high
- Device details: Chrome, Windows 11, device compliance unknown.

This event differed significantly from Anna's earlier sign-ins.

### F. Review activity after the suspicious sign-in

**Purpose:** Check whether additional sign-in activity was recorded after the suspicious event.

```spl
index=main source="simulated_logs_fixed.csv" user="anna.kowalska"
| where _time >= strptime("2026-11-05 09:18:00", "%Y-%m-%d %H:%M:%S")
| table _time event_type src_ip src_location device_id action result mfa risk details
| sort 0 _time
```

**Observed results:** One event was returned: the successful High-risk sign-in from Berlin at 09:18. No subsequent events were present in the available dataset.

### G. Overall event distribution

**Purpose:** Establish the total number of events for each event type in the dataset.

```spl
index=main source="simulated_logs_fixed.csv"
| stats count by event_type
| sort - count
```

**Observed results:**

- `email_received` — 12 events.
- `signin` — 3 events.
- `url_click` — 3 events.

A total of 18 events were identified.

### Investigation conclusion

The executed searches identified a phishing campaign affecting 12 employees, with three recorded URL clicks. Correlation of the email, proxy, and sign-in events revealed a strong indicator of suspected account compromise involving Anna Kowalska.

The most significant finding was a successful High-risk sign-in from an unfamiliar IP and device in Berlin, occurring three minutes after Anna visited the phishing URL. This activity differed from her previous successful low-risk sign-ins from Warsaw.

The findings justify treating the incident as a suspected account compromise and escalating it to SOC L2 / Incident Response. The available logs do not establish the precise authentication method or independently prove that the phishing link caused the suspicious sign-in.
