# What is Panther?

#### Panther is an open source platform for detecting threats, improving cloud security posture, and powering investigations.

![Architecture](.gitbook/assets/readme-overview.png)

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

Follow the [quick start](quick-start.md) guide to deploy Panther Community. 

### Premium

Panther [Enterprise](enterprise) offers additional features for advanced teams, such as:
- Data Explorer: Search your collected data, generated alerts, and threat hunt with SQL
- SaaS Log Collection: Automatically load popular SaaS logs into Panther such as Okta, G Suite, and more.
- Role-based Access Control: Assign roles to your Panther users
- Single Sign-on: Integrate solutions such as Okta to streamline and manage identities.

To receive a trial of Panther Enterprise, [sign up here](https://runpanther.io/request-a-demo/)!
