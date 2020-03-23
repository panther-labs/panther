# Home

## Overview

Panther is a cloud-native platform for detecting threats with log data, improving cloud security posture, and conducting investigations.

Security teams can use Panther for:

|         Use Case         | Description                                                                               |
| :----------------------: | ----------------------------------------------------------------------------------------- |
|  Continuous Monitoring   | Analyze logs in real-time and identify suspicious activity that could indicate a breach   |
|       Alert Triage       | Pivot across all of your security data to understand the full context of an alert         |
|      Searching IOCs      | Quickly search for matches against IOCs using standardized data fields                    |
| Securing Cloud Resources | Identify misconfigurations, achieve compliance, and model security best practices in code |

The diagram below provides a high-level architecture of Panther:

![Architecture](.gitbook/assets/high-level-diagram.png)

The three main components are:

* **Log Analysis** to centralize, parse, and analyze log data with Python
* **Historical Search** for storage and analytics on collected log data and generated alerts
* **Cloud Security** to scan AWS accounts, detect misconfigurations, and improve cloud security posture

The benefits of Panther include:

- Flexible Python-based detections
- Built on serverless technologies for high scale at low cost
- Near real-time analysis for quick alerting and remediation
- Simple deployments using infrastructure as code
- Secure, least-privilege, and encrypted infrastructure deployed within your AWS account

## Get Started!

To get set up with Panther, continue to the [Quick Start](quick-start.md) on the next page.
