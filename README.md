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

Panther analyzes security data from your clouds, networks, applications, and endpoints and detects threats, misconfigured cloud resources, and stores data for investigations.

Teams can use Panther for:

| Use Case | Description |
|:--------:|-------------|
| Continuous Monitoring         | Analyze data in real-time and identify suspicious activity that could indicate a breach             |
| Investigating Alerts         |Pivot across all security data to get the full context of an alert             |
| Search IOCs         | Utilize standardized data fields and quickly search for matches against ip addresses, domains, usernames, and more            |
| Securing Cloud Resources   | Achieve compliance by modeling security best practices and automatically fixing vulnerable cloud resources   |

## Analysis

Panther's detection logic is written in Python. Each deployment includes [100+ detection rules](https://github.com/panther-labs/panther-analysis).

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

It's no longer feasible to find the needle in the security log haystack _manually_. Many teams have struggled to solve this problem using  SIEMs and traditional log analytics platforms due to their high cost, overhead, and scale. Panther utilizes the elastic nature of cloud services to provide a high-scale, performant, and flexible solution at a much lower cost.

## Contributing

We welcome all contributions! Please read the [contributing  guidelines](https://github.com/panther-labs/panther/blob/master/docs/CONTRIBUTING.md) before submitting pull requests.

## License

Panther is dual-licensed under the AGPLv3 and Apache-2.0 [licenses](https://github.com/panther-labs/panther/blob/master/LICENSE).

### FOSSA Status

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fpanther-labs%2Fpanther?ref=badge_large)
