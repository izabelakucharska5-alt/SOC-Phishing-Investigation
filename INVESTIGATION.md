# Phishing Email Investigation — SOC L1

**Project type:** Simulated Blue Team investigation  
**Status:** Initial investigation documented; SPL searches are examples and have not been executed in Splunk.  
**Dataset:** [`data/simulated_logs.csv`](data/simulated_logs.csv)

## 1. Executive summary

A phishing email impersonating Microsoft 365 was delivered to **12 employees**. The available proxy events show that **3 employees clicked** the link in the message. One of them, Anna Kowalska, was followed three minutes later by a successful sign-in from an unfamiliar device and an unusual IP geolocated to Berlin. The sign-in was marked **High risk**, and Anna denied performing it.

These indicators support treating Anna's account as **suspected compromised** and escalating the case to the incident response team. The dataset does not prove how the attacker authenticated or whether Anna submitted her credentials. A successful MFA result does not establish that the legitimate user performed the sign-in.

## 2. Incident scope and evidence

The investigation uses a fictional organization and synthetic email, proxy, and sign-in events. All names and `.example` domains are fictional. IP addresses in the documentation ranges are reserved for examples and are not real attacker infrastructure.

| Data source | What it contains |
|---|---|
| Email gateway events | Message sender, recipients, subject, delivery time, SPF/DKIM/DMARC results |
| Proxy events | Users who visited the suspicious URL and event timestamps |
| Sign-in events | User, source IP, approximate location, device, MFA result, and risk rating |

### Initial email triage

The message contains several phishing indicators:

- The sender uses `micros0ft365.example`, with a zero in place of the letter “o”.
- The subject and message create urgency by threatening mailbox suspension.
- The link points to `m365-auth.example`, not an official Microsoft domain.
- The authentication results are `SPF=fail`, `DKIM=none`, and `DMARC=fail`.

**Authentication note:** SPF is evaluated against the SMTP envelope sender domain shown in the headers (`bulk-mailer.example`), not automatically against the visible `From` domain. `DKIM=none` means no DKIM signature was reported. `DMARC=fail` means the message did not pass DMARC, which requires an aligned SPF or DKIM pass.

## 3. Investigation findings

### Phishing campaign

- **12** email delivery events were recorded.
- **3** users visited the suspicious URL: Anna Kowalska, Piotr Nowak, and Marta Zielińska.
- The available data shows URL visits, but does not show whether users entered credentials or submitted a form.

### Suspicious sign-in

Anna's sign-in history contains two earlier successful sign-ins from the same IP and device in Warsaw. On 5 November 2026 at 09:18 (UTC+01:00), a further successful sign-in was recorded with these differences:

| Field | Earlier activity | Suspicious event |
|---|---|---|
| Source IP | `198.51.100.10` | `203.0.113.77` |
| Approximate location | Warsaw, Poland | Berlin, Germany |
| Device ID | `ANN-LAPTOP-01` | `unknown` |
| MFA | Successful | Successful |
| Sign-in risk | Low | High |

Anna clicked the phishing link at **09:15**, three minutes before the suspicious sign-in. She stated that she did not perform the sign-in. The timing, unfamiliar device, different IP/location, High risk rating, and user's denial make account compromise a credible concern.

**Assessment:** suspected account compromise — **High priority for escalation**. The evidence does not establish the exact access method. Possible explanations such as stolen credentials, MFA fatigue, or session-token theft require additional telemetry and must not be presented as confirmed findings.

## 4. Event timeline

All times are from the synthetic dataset and use UTC+01:00.

| Date and time | Event |
|---|---|
| 5 Nov 2026, 08:10 | Anna signs in from her usual IP and device in Warsaw. |
| 5 Nov 2026, 08:42 | Phishing email delivered to 12 employees. |
| 5 Nov 2026, 09:15 | Anna visits the suspicious URL. |
| 5 Nov 2026, 09:18 | Successful, High-risk sign-in for Anna from an unfamiliar device and IP geolocated to Berlin; MFA reported successful. |
| 5 Nov 2026, 09:22 | Piotr visits the suspicious URL. |
| 5 Nov 2026, 09:31 | Marta visits the suspicious URL. |

## 5. Recommended response actions

1. **Escalate to SOC L2 / Incident Response.** Treat Anna's account as potentially compromised; preserve the relevant email, proxy, and identity logs.
2. **Contain the account.** Following the organization's playbook, revoke active sessions and refresh tokens, temporarily block sign-in if warranted, and reset the password through a trusted channel.
3. **Review authentication methods.** Check for newly registered MFA methods, unexpected MFA changes, and suspicious authentication activity. Re-register MFA if the investigation indicates it may have been compromised.
4. **Investigate post-compromise activity.** Review mailbox access, inbox and forwarding rules, sent items, OAuth app consent, delegated access, and other account changes.
5. **Scope the campaign.** Search all mailboxes for the sender, subject, Message-ID, and URL; quarantine or remove matching messages. Contact the other users who clicked the link.
6. **Block indicators in the correct controls.** Block the sender and message at the email security gateway; block the malicious URL/domain in applicable web proxy, DNS, or endpoint controls. A sender domain is not normally blocked solely through a network firewall.
7. **Verify recovery.** Confirm with Anna through a known, trusted channel and monitor for further suspicious sign-ins.

## 6. Example Splunk searches (SPL)

The following searches document the detection logic for the supplied CSV. **They are examples and have not been run in Splunk.** Replace `index=main` and `sourcetype=csv` with the index and sourcetype used in the environment. They assume the CSV header fields are extracted and `timestamp` is available as a field.

### A. Count delivered messages and unique recipients

```spl
index=main sourcetype=csv event_type="email_received"
| stats count as delivery_events dc(recipient) as unique_recipients values(sender) as sender by message_id
```

Expected result from this dataset: **12 delivery events and 12 unique recipients**.

### B. Identify users who clicked the URL

```spl
index=main sourcetype=csv event_type="url_click"
| stats count as clicks values(url) as visited_urls values(src_ip) as source_ips by user
| sort - clicks
```

Expected result from this dataset: **3 users** — Anna, Piotr, and Marta.

### C. Review sign-in events

```spl
index=main sourcetype=csv event_type="signin"
| table timestamp user src_ip src_location device_id result mfa risk details
| sort 0 timestamp
```

Expected result from this dataset: Anna has two earlier low-risk sign-ins from her usual device and one High-risk sign-in from an unknown device.

### D. Correlate a URL click with a sign-in within 15 minutes

```spl
index=main sourcetype=csv (event_type="url_click" OR event_type="signin")
| eval event_time=strptime(timestamp, "%Y-%m-%dT%H:%M:%S%z")
| sort 0 user event_time
| streamstats current=f last(event_type) as previous_event last(event_time) as previous_time by user
| where event_type="signin" AND previous_event="url_click" AND event_time-previous_time<=900
| eval minutes_after_click=round((event_time-previous_time)/60, 1)
| table user previous_time event_time minutes_after_click src_ip src_location device_id risk
```

Expected result from this dataset: Anna's sign-in occurred **3 minutes** after her URL visit. This is a temporal correlation, not proof that the click caused the sign-in.

## 7. MITRE ATT&CK mapping

| Technique | Name | Evidence / status |
|---|---|---|
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | A phishing email delivered a link that three users visited. Applicable to the simulated scenario. |

No additional technique is confirmed by the current dataset. In particular, the logs do not establish how the suspicious sign-in was obtained.

## 8. Limitations

The synthetic dataset is intentionally small. It does not include web form submissions, identity-provider session details, MFA prompt history, endpoint telemetry, mailbox audit events, or evidence of data access or exfiltration. Therefore, it is not possible to determine whether credentials were entered, how MFA was satisfied, or what the actor may have accessed after sign-in. These are investigation gaps, not proof that such activity did not occur.

The IP addresses `198.51.100.10`, `203.0.113.45`, and `203.0.113.77` belong to documentation ranges used in this exercise. They must not be treated as real-world malicious indicators.

## 9. Conclusion

The available evidence identifies a phishing campaign affecting 12 employees, with three recorded URL visits and one high-priority suspected account compromise. The correct SOC response is to escalate the case, contain and investigate Anna's account, determine whether other users are at risk, and preserve evidence. Further identity, endpoint, and mailbox logs are required before confirming the attacker's access method or the full impact.
