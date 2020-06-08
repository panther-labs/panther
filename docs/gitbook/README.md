# What is Panther?

Panther is an open source platform designed to bring security visibility at cloud-scale. It's a modern and flexible solution to the challenges of collection, analysis, and retention of critical security data. Panther detects threats, improves cloud security posture, and powers investigations.

![Architecture](.gitbook/assets/panther_graphic_flow.jpg)

### Benefits

- Analyze TBs of data per day
- Write flexible, Python-based, real-time detections
- Bootstrap your security data lake
- Simply deploy with infrastructure as code
- Secure, least-privilege, and encrypted infrastructure

### Components

* [Log Analysis](log-analysis/log-processing/README.md) for parsing, normalizing, and analyzing security data
* [Cloud Security](policies/scanning/README.md) for identifying misconfigurations in AWS accounts
* [Data Analytics](historical-search/README.md) for queries on collected log data, generated alerts, and normalized fields

### Use Cases

|         Use Case         | Description                                                                               |
| :----------------------: | ----------------------------------------------------------------------------------------- |
|  Continuous Monitoring   | Analyze logs in real-time with Python to identify suspicious activity   |
|       Alert Triage       | Respond to alerts to get the full context         |
|      Searching IOCs      | Quickly search for matches on IOCs against all collected data                    |
| Securing Cloud Resources | Achieve compliance and model security best practices in code |

## Get Started!

To deploy Panther Community Edition, continue to the [quick start](quick-start.md) guide!

To receive a trial of Panther Enterprise, [sign up here](https://runpanther.io/request-a-demo/).

This includes access to features such as:
- Data Explorer
- SaaS Log Collection
- Role-based Access Control
- Single Sign-on
- Premium Detection Packs
- Dedicated onboarding and operational support
- Flexible Deployment such as Cloud Hosted or Cloud Premise
