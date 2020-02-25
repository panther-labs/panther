<p align="center">
  <a href="https://www.runpanther.io"><img src="docs/img/panther-logo-github.jpg" alt="Panther Logo"/></a>
</p>

<p align="center">
  <b>A Cloud-Native Threat Detection & Response Platform</b>
</p>

<p align="center">
  <a href="https://docs.runpanther.io">Documentation</a> |
  <a href="https://docs.runpanther.io/quick-start">Quick Start</a> |
  <a href="https://blog.runpanther.io">Technical Blog</a>
</p>

<p align="center">
  <a href="https://gitter.im/runpanther/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge"><img src="https://badges.gitter.im/runpanther/community.svg" alt="Gitter"/></a>
  <a href="https://magefile.org"><img src="https://magefile.org/badge.svg" alt="Built with Mage"/></a>
  <a href="https://circleci.com/gh/panther-labs/panther"><img src="https://circleci.com/gh/panther-labs/panther.svg?style=svg" alt="CircleCI"/></a>
  <a href="https://app.fossa.com/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther?ref=badge_shield" alt="FOSSA Status"><img src="https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther.svg?type=shield"/></a>
  <a href="https://cla-assistant.io/panther-labs/panther" alt="CLA Assistant"><img src="https://cla-assistant.io/readme/badge/panther-labs/panther"/></a>
</p>

---

## What is Panther and how does it work?

Panther enables security teams to quickly and automatically detect threats in log data and cloud infrastructure. Panther is engineered to empower security monitoring for organizations of any scale by:

- **Detecting** suspicious activities using Python Rules
- **Identifying** misconfigured AWS resources with Python Policies
- **Visualizing** alerts and creating detections with a unified web UI

## Use Cases

Panther works by analyzing security-relevant data generated by your clouds, networks, applications, and hosts to enable threat detection, cloud security, and investigations.

Panther provides flexible Python detection logic, secure and automated deployments within your AWS cloud, and support for popular security logs, commonly used for:

- **Detecting Unauthorized Access:** Analyze host-based logs to identify unauthorized access that could indicate a system breach
- **Powering Your Investigations:** Join data from various sources to determine if a potential compromise has occurred
- **Threat Hunting:** Utilize Panther's standardized data fields to quickly search your logs for matches against indicators of compromise
- **Achieving Compliance:** Use [built-in policies](https://github.com/panther-labs/panther-analysis) as controls for achieving SOC/PCI/HIPAA compliance
- **Securing Cloud Resources:** Model security best practices with Python policies and automatically fix misconfigurations with automatic remediation

_NOTE: Panther is currently in beta_

## Deployment

Follow our [Quick Start Guide](https://docs.runpanther.io/quick-start) to deploy Panther to your AWS account in a matter of minutes!

## Why Panther?

It's no longer feasible to find the needle in the security log haystack _manually_. Many security teams have struggled to solve this problem with SIEMs and traditional log analytics platforms due to their high cost, overhead, and scale.

Panther utilizes the elastic nature of serverless cloud services to provide a high-scale, performant, and flexible solution at a much lower cost. Panther also comes built-in with a rich and intuitive user interface, built-in detections, and first-class AWS support.

## Web UI

<img src="docs/img/compliance-overview.png" alt="Compliance Overview"/>
<p align="center"><i>Cloud Security Overview:</i> Harden your cloud infrastructure</p>
<br />

<img src="docs/img/rules-editor.png" alt="Rules Editor"/>
<p align="center"><i>Rules Editor:</i> Write, tune, and update detections in the browser</p>
<br />

<img src="docs/img/resource-viewer.png" alt="Resource Viewer"/>
<p align="center"><i>Resource Viewer:</i> View attributes and passed/failed policies on a per-resource basis</p>
<br />

## About Us

We are a San Francisco based [startup](https://www.crunchbase.com/organization/panther-labs) comprising security practitioners who have learned from years of building large-scale detection and response capabilities for companies such as Amazon and Airbnb. Panther was founded by the core architect of [StreamAlert](https://github.com/airbnb/streamalert/), a cloud-native solution for automated log analysis open-sourced by Airbnb.

## Contributing

We welcome all contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther/blob/master/docs/CONTRIBUTING.md) before submitting pull requests.

## License

Panther is dual-licensed under the AGPLv3 and Apache-2.0 [licenses](https://github.com/panther-labs/panther/blob/master/LICENSE).

#### FOSSA

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther?ref=badge_large)
