# SOC-Phishing-Investigation

**Phishing Email Analysis & Incident Investigation**

![Status](https://img.shields.io/badge/Status-Completed-brightgreen) ![Project](https://img.shields.io/badge/Type-Blue%20Team-blue) ![SIEM](https://img.shields.io/badge/SIEM-Splunk-black)

A simulated **SOC L1 investigation** of a phishing campaign targeting employees of a fictional organization. The project demonstrates how Splunk and SPL can be used to investigate phishing activity, correlate security events, identify suspicious authentication behavior, and assess potential account compromise.

## Investigation Summary

A phishing email impersonating Microsoft 365 was delivered to 12 employees.

The investigation identified:

- **12** phishing emails delivered.
- **3** employees who clicked the suspicious link.
- **1** account with indicators of suspected compromise.
- **1** successful high-risk sign-in from an unfamiliar device and location.

The most significant finding involved an employee who clicked the phishing link at 09:15. Three minutes later, a successful high-risk sign-in was recorded from Berlin, Germany, using an unknown device. The employee denied performing this sign-in.

## Focus Areas

- Phishing email investigation and sender-domain analysis.
- Email authentication analysis (SPF, DKIM, DMARC).
- Security log analysis using Splunk.
- SPL search development and execution.
- Identification of phishing campaign recipients.
- Correlation of email clicks and authentication events.
- Suspicious sign-in and account compromise assessment.
- Event timeline reconstruction.
- Incident triage and response recommendations.
- MITRE ATT&CK mapping.

## Technologies & Frameworks

- **Splunk** — SIEM platform used to ingest and investigate the synthetic log dataset.
- **SPL** — Splunk Search Processing Language used to filter, correlate, aggregate, and analyze events.
- **CSV** — Structured dataset containing simulated email, URL click, and authentication events.
- **MITRE ATT&CK** — Framework used to map the observed phishing activity.

## Repository Contents

| File / Directory | Description |
|---|---|
| [`investigation.md`](investigation.md) | Full investigation report, executed SPL searches, findings, analysis, and screenshots |
| [`data/`](data/) | Synthetic security event dataset |
| [`Screenshots/`](Screenshots/) | Screenshots documenting the Splunk investigation process |

## Investigation Workflow

1. Reviewed the available security events and established the investigation scope.
2. Identified users who clicked the suspicious phishing URL.
3. Examined authentication activity and established normal sign-in patterns.
4. Analyzed email authentication results and identified campaign recipients.
5. Correlated phishing interactions with sign-in activity.
6. Investigated the anomalous authentication event and reconstructed the account timeline.
7. Assessed the potential impact and documented recommended incident response actions.

The full investigation, including the SPL commands and corresponding Splunk screenshots, is available in [`investigation.md`](investigation.md).

## Key Findings

The investigation identified a suspicious Microsoft 365 impersonation campaign using the domain `micros0ft365.example` and the URL `https://m365-auth.example/verify`.

Email authentication results indicated:
- SPF: `fail`
- DKIM: `none`
- DMARC: `fail`

Three employees visited the suspicious URL. One account showed a significant deviation from its normal authentication pattern:

- Previous sign-ins originated from Warsaw using a known device.
- A later successful sign-in originated from Berlin using an unknown device.
- The sign-in was classified as High risk.
- MFA was reported as successful.
- The employee denied performing the authentication.

**Conclusion:** The available evidence supports escalating the incident as a suspected account compromise. The exact attack mechanism and post-authentication impact could not be established from the available dataset.

## Disclaimer

This is an educational Blue Team project based on a fictional scenario and synthetic security logs.

**The SPL searches were executed in Splunk against the supplied synthetic dataset.** No production infrastructure, real employee accounts, or real security incidents were involved.

All names, domains, and events are fictional. The IP addresses used belong to documentation ranges reserved for examples and should not be treated as real malicious indicators.
