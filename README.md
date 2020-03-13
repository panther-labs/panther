<p align="center">
  <a href="https://www.runpanther.io"><img src="docs/img/panther-logo-github.jpg" alt="Panther Logo"/></a>
</p>

<p align="center">
  <b>Detect Threats with Log Data and Improve Cloud Security Posture</b>
</p>

<p align="center">
  <i>Panther is currently in beta</i>
</p>

<p align="center">
  <a href="https://docs.runpanther.io">Documentation</a> |
  <a href="https://docs.runpanther.io/quick-start">Quick Start</a> |
  <a href="https://blog.runpanther.io">Blog</a>
</p>

<p align="center">
  <a href="https://panther-labs-oss-slackin.herokuapp.com/"><img src="https://panther-labs-oss-slackin.herokuapp.com/badge.svg" alt="Slack"/></a>
  <a href="https://circleci.com/gh/panther-labs/panther"><img src="https://circleci.com/gh/panther-labs/panther.svg?style=svg" alt="CircleCI"/></a>
  <a href="https://app.fossa.com/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther?ref=badge_shield" alt="FOSSA Status"><img src="https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther.svg?type=shield"/></a>
  <a href="https://cla-assistant.io/panther-labs/panther" alt="CLA Assistant"><img src="https://cla-assistant.io/readme/badge/panther-labs/panther"/></a>
  <a href="https://magefile.org"><img src="https://magefile.org/badge.svg" alt="Built with Mage"/></a>
</p>

---

## Use Cases

Security teams can use Panther for:

|         Use Case         | Description                                                                                                        |
| :----------------------: | ------------------------------------------------------------------------------------------------------------------ |
|  Continuous Monitoring   | Analyze logs in real-time and identify suspicious activity that could indicate a breach                            |
|   Investigating Alerts   | Pivot across all security data to get the full context of an alert                                                 |
|      Searching IOCs      | Utilize standardized data fields and quickly search for matches against ip addresses, domains, usernames, and more |
| Securing Cloud Resources | Identify misconfigurations, achieve compliance, and model security best practices                                  |

## Analysis

Panther's detection logic is written in Python. Each deployment includes [150+ detections](https://github.com/panther-labs/panther-analysis/tree/master/analysis).

In the following example, [osquery](https://github.com/osquery/osquery) logs are analyzed to identify malware on a macOS laptop:

```python
from fnmatch import fnmatch

APPROVED_PATHS = {
  '/System/*', '/usr/*', '/bin/*', '/sbin/*', '/var/*'
}


def rule(event):
    if not event.get('name', '').startswith('pack_osx-attacks_'):
        return False

    if event.get('action') != 'added':
        return False

    process_path = event.get('columns', {}).get('path')
    # Alert if the process is running outside any of the approved paths
    return not any([fnmatch(process_path, p) for p in APPROVED_PATHS])
```

## Deployment

Follow our [Quick Start Guide](https://docs.runpanther.io/quick-start) to deploy Panther in your AWS account in a matter of minutes!

## Screenshots

<img src="docs/img/rule-search-new.png" alt="Rule Search"/>
<p align="center"><i>Rule Search:</i> Show running detections</p>

<img src="docs/img/rule-editor-new.png" alt="Rule Editor"/>
<p align="center"><i>Rule Editor:</i> Write and test Python detections in the UI</p>

<img src="docs/img/alert-viewer-new.png" alt="Alert Viewer"/>
<p align="center"><i>Alert Viewer:</i> Triage generated alerts</p>

<img src="docs/img/resource-viewer-new.png" alt="Resource Viewer"/>
<p align="center"><i>Resource Viewer:</i> View attributes and policy statuses</p>

## About Us

### Team

We are a San Francisco based [startup](https://www.crunchbase.com/organization/panther-labs) comprising security practitioners who have spent years building large-scale detection and response capabilities for companies such as Amazon and Airbnb. Panther was founded by the core architect of [StreamAlert](https://github.com/airbnb/streamalert/), a cloud-native solution for automated log analysis open-sourced by Airbnb.

### Why Panther?

It's no longer feasible to find the needle in the security-log-haystack _manually_. Many teams are struggling to find a solution using traditional SIEMs or log analytics platforms due to their high costs, overhead, and inability to scale. Panther was built from the ground up to leverage the elasticity of cloud services to provide a highly scalable, performant, and flexible security solution at a much lower cost.

## Contributing

We welcome all contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther/blob/master/docs/CONTRIBUTING.md) before submitting pull requests.

## License

Panther is dual-licensed under the AGPLv3 and Apache-2.0 [licenses](https://github.com/panther-labs/panther/blob/master/LICENSE).

### FOSSA Status

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther?ref=badge_large)
