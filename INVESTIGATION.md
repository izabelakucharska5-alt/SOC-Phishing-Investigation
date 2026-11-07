# Phishing Email Investigation — SOC L1

**Project type:** Simulated Blue Team investigation  
**Status:** Investigation completed; findings documented using executed Splunk searches.  
**Dataset:** [`data/simulated_logs_fixed.csv`](data/simulated_logs_fixed.csv)

## 1. Executive summary

A phishing email impersonating Microsoft 365 was delivered to **12 employees**. The available proxy events show that **3 employees clicked** the link in the message.

One of them, Anna Kowalska, was followed three minutes later by a successful sign-in from an unfamiliar device and an unusual IP geolocated to Berlin. The sign-in was marked **High risk**, and Anna denied performing it.

The correlation between the phishing URL click and the subsequent suspicious authentication event provides strong indicators of a potential account compromise.

The investigation identified:
- 12 phishing email delivery events.
- 3 employees who visited the suspicious URL.
- 1 suspicious successful sign-in associated with Anna Kowalska.
- An unfamiliar IP address and unknown device.
- A High-risk sign-in rating.
- Successful MFA reported during the suspicious sign-in.

These indicators support treating Anna's account as **suspected compromised** and escalating the case to the incident response team.

The dataset does not prove how the attacker authenticated or whether Anna submitted her credentials. A successful MFA result does not establish that the legitimate user performed the sign-in.

## 2. Incident scope and evidence

The investigation uses a fictional organization and synthetic email, proxy, and sign-in events. All names and `.example` domains are fictional. IP addresses in the documentation ranges are reserved for examples and are not real attacker infrastructure.

| Data source | What it contains |
|---|---|
| Email gateway events | Message sender, recipients, subject, delivery time, SPF/DKIM/DMARC results |
| Proxy events | Users who visited the suspicious URL and event timestamps |
| Sign-in events | User, source IP, approximate location, device, MFA result, and risk rating |

### Initial email triage

The message contains several phishing indicators:

- The sender uses `micros0ft365.example`, with a zero in place of the letter "o".
- The subject and message create urgency by threatening mailbox suspension.
- The link points to `m365-auth.example`, not an official Microsoft domain.
- The authentication results are `SPF=fail`, `DKIM=none`, and `DMARC=fail`.

**Authentication note:** SPF is evaluated against the SMTP envelope sender domain, which may differ from the visible From domain. The available investigation screenshots do not establish the SMTP envelope sender, so its exact domain cannot be confirmed. `DKIM=none` means no DKIM signature was reported. `DMARC=fail` means the message did not pass DMARC, which requires an aligned SPF or DKIM pass.

## 3. Investigation findings

### Phishing campaign

- **12** email delivery events were recorded.
- **12** unique recipients were identified.
- All messages shared the same subject and sender.
- The sender was `no-reply@micros0ft365.example`.
- The source IP recorded for the email campaign was `203.0.113.45`.
- **3** users visited the suspicious URL: Anna Kowalska, Piotr Nowak, and Marta Zielińska.

The available data shows URL visits, but does not show whether users entered credentials or submitted a form.

### Suspicious sign-in

Anna's sign-in history contains two earlier successful sign-ins from the same IP and device in Warsaw.

On 5 November 2026 at 09:18 (UTC+01:00), a further successful sign-in was recorded with these differences:

| Field | Earlier activity | Suspicious event |
|---|---|---|
| Source IP | `198.51.100.10` | `203.0.113.77` |
| Approximate location | Warsaw, Poland | Berlin, Germany |
| Device ID | `ANN-LAPTOP-01` | `unknown` |
| MFA | Successful | Successful |
| Sign-in risk | Low | High |

Anna clicked the phishing link at **09:15**, three minutes before the suspicious sign-in. She stated that she did not perform the sign-in.

The timing, unfamiliar device, different IP/location, High-risk rating, and user's denial make account compromise a credible concern.

**Assessment:** Suspected account compromise — **High priority for escalation**.

The evidence does not establish the exact access method. Possible explanations such as stolen credentials, MFA fatigue, or session-token theft require additional telemetry and must not be presented as confirmed findings.

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
2. **Contain the account.** Following the
