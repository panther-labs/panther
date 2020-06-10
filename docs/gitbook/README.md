# What is Panther?

Panther is an open source platform designed to bring security visibility at cloud-scale. It's a modern and flexible solution to the challenges of collection, analysis, and retention of critical security data. Panther detects threats, improves cloud security posture, and powers investigations.

![Architecture](.gitbook/assets/panther_graphic_flow.jpg)

**Benefits**

- Analyze TBs of data per day
- Write flexible, Python-based, real-time detections
- Bootstrap your security data lake
- Simply deploy with infrastructure as code
- Secure, least-privilege, and encrypted infrastructure

**Components**

* [Log Analysis](log-analysis/README.md) for parsing, normalizing, and analyzing security data
* [Cloud Security](cloud-security/README.md) for identifying misconfigurations in AWS accounts
* [Data Analytics](enterprise/data-analytics/README.md) for queries on collected log data, generated alerts, and normalized fields

**Use Cases**

|         Use Case         | Description                                                                               |
| :----------------------: | ----------------------------------------------------------------------------------------- |
|  Continuous Monitoring   | Analyze logs in real-time with Python to identify suspicious activity   |
|       Alert Triage       | Respond to alerts to get the full context         |
|      Searching IOCs      | Quickly search for matches on IOCs against all collected data                    |
| Securing Cloud Resources | Achieve compliance and model security best practices in code |

## Getting Started!

To deploy Panther Community Edition, continue to the [quick start](quick-start.md) guide.

Panther also has an [Enterprise](enterprise) Edition with access to the following features:
- Data Explorer: Search your collected data, generated alerts, and threat hunt with SQL
- SaaS Log Collection: Automatically load popular SaaS logs into Panther.
- Role-based Access Control: Assign roles to your Panther users
- Single Sign-on: Integrate solutions such as Okta to streamline and manage identities.
- Premium Detection Packs: Built-in support for PCI and more advanced off the shelf rules.
- Dedicated onboarding and operational support
- Flexible Deployments with Cloud Hosted or Cloud Premise

To receive a trial of Panther Enterprise, [sign up here](https://runpanther.io/request-a-demo/)!
