<p align="center">
  <a href="https://www.runpanther.io"><img src="docs/img/logo-banner.png" alt="Panther Logo"/></a>
</p>

<p align="center">
  <b>A Cloud-Native SIEM for the Modern Security Team</b>
</p>

<p align="center">
  <a href="https://docs.runpanther.io">Documentation</a> |
  <a href="https://docs.runpanther.io/quick-start">Quick Start</a> |
  <a href="https://blog.runpanther.io">Blog</a>
</p>

<p align="center">
  <a href="https://gitter.im/runpanther/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge"><img src="https://badges.gitter.im/runpanther/community.svg" alt="Gitter"/></a>
  <a href="https://magefile.org"><img src="https://magefile.org/badge.svg" alt="Built with Mage"/></a>
  <a href="https://circleci.com/gh/panther-labs/panther"><img src="https://circleci.com/gh/panther-labs/panther.svg?style=svg" alt="CircleCI"/></a>
  <a href="https://app.fossa.com/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther?ref=badge_shield" alt="FOSSA Status"><img src="https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther.svg?type=shield"/></a>
</p>

---

## About Us

We are a San Francisco based [startup](https://www.crunchbase.com/organization/panther-labs) comprised of security engineers who have spent years building large-scale detection and response for cloud-first companies such as Airbnb, Amazon, Riverbed, and more. Panther was founded by the core architect of [StreamAlert](https://github.com/airbnb/streamalert/), a project open-sourced at Airbnb to create a cloud-native solution for automated log analysis.

Panther is the next step in a journey of providing security teams with a cloud-native, scalable, modern alternative to traditional SIEMs. We designed Panther for massive scale, a rich and intuitive user experience, in-browser Python rule editors, first-class AWS support, and more.

Our mission is to build an open platform that security teams can use to effectively protect their businesses from cyber breaches.

## Product

Panther is designed to be:

- **Flexible:** Perform advanced analysis on both log data and cloud infrastructure with [Python-based detections](https://github.com/panther-labs/panther-analysis)
- **Scalable:** Allow small teams to run at a massive scale
- **Secure:** Least-privileged and encrypted infrastructure run from within your cloud environment
- **Integrated:** Support for popular security logs, analyzing high-priority cloud resources, and notifying your team with commonly used apps
- **Automated:** Fast and simple deployments with AWS CloudFormation

## Use Cases

Panther is the destination for all security data to enable threat detection, compliance, historical search, and security investigations. Panther's core features include:

- **[Log Analysis](https://runpanther.io/log-analysis):** Real-time detection of suspicious activity with Python rules
- **[Compliance](https://runpanther.io/compliance/):** Real-time monitoring and enforcement of AWS infrastructure best practices with Python policies
- **Alerting:** Send notifications to your team when new issues are identified
- **Automatic Remediation:** Correct insecure infrastructure as soon as possible

_NOTE: Panther is currently in beta._

## Deployment

Follow our [Quick Start Guide](https://docs.runpanther.io/quick-start) to deploy Panther to your AWS account in a matter of minutes!

## Screenshots

<img src="docs/img/compliance-overview.png" alt="Compliance Overview"/>
<p align="center"><i>Compliance Overview</i></p>
<br />

<img src="docs/img/rules-editor.png" alt="Rules Editor"/>
<p align="center"><i>Rules Editor</i></p>
<br />

<img src="docs/img/resource-viewer.png" alt="Resource Viewer"/>
<p align="center"><i>Resource Viewer</i></p>
<br />

## Contributing

We welcome all contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther/blob/master/docs/CONTRIBUTING.md) before submitting pull requests.

## License

Panther is dual-licensed under the AGPLv3 and Apache-2.0 [licenses](https://github.com/panther-labs/panther/blob/master/LICENSE).

#### FOSSA

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther?ref=badge_large)
