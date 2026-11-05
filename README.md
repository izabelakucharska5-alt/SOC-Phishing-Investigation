# SOC-Phishing-Investigation
Phishing e-mail analysis and investigation

![Status](https://img.shields.io/badge/Status-In%20Progress-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-brightgreen)

A hands-on SOC L1 project simulating the investigation of a phishing campaign targeting a fictional organization.

**Focus areas:**
- Phishing email analysis
- Email authentication (SPF, DKIM, DMARC)
- SIEM investigation using Splunk
- Security log analysis and event correlation
- Account compromise investigation
- Incident response

**Tools:** Splunk, Microsoft Entra ID, MITRE ATT&CK.

*Note: This project uses simulated data and fictional scenarios for educational purposes.*
3 employees clicked the malicious link.

SPF and DMARC authentication checks failed.

DKIM signature was missing.

One employee account showed suspicious login activity.

The affected user denied performing the login.

Investigation Objectives

Analyze email headers and authentication results.

Identify phishing indicators and malicious URLs.

Determine the scope of the phishing campaign.

Investigate user interactions with the malicious link.

Analyze authentication and network logs.

Detect potential account compromise.

Correlate security events using Splunk.

Recommend incident containment and remediation actions.

Tools & Technologies

Splunk Enterprise – SIEM searches and log analysis.

Microsoft Entra ID – Authentication investigation.

MITRE ATT&CK – Threat technique mapping.

VirusTotal – IOC reputation analysis.

Investigation Process

Initial email triage and header analysis.

Identification of affected users.

Phishing link investigation.

SIEM log analysis and event correlation.

Authentication investigation.

Incident assessment and escalation.

Incident response recommendations.

MITRE ATT&CK

Initial suspected technique:

T1566.002 – Spearphishing Link

Additional techniques will be identified based on investigation findings.

Disclaimer

This is an independent educational project based on a simulated security incident. All organizations, employees, domains and security logs are fictional. No real systems or user accounts are involved.
