# SOC-Phishing-Investigation
Phishing e-mail analysis and investigation
SOC Phishing Investigation

Project: Phishing Email Investigation
Role: SOC Analyst L1
Focus: Blue Team | SIEM | Threat Detection | Incident Response
Status: In Progress

Overview

This project simulates a SOC investigation into a phishing campaign targeting employees of a fictional organization.

The investigation focuses on identifying phishing indicators, analyzing email headers, investigating suspicious authentication events and assessing potential account compromise.

Incident Scenario

Employees receive a suspicious email impersonating Microsoft 365 Security, warning that their mailboxes will be suspended unless they verify their accounts.

Initial findings:

12 employees received the email.

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
