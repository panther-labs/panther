<p align="center">
  <a href="https://www.runpanther.io"><img src="docs/img/logo-banner.png" alt="Panther Logo"/></a>
</p>

<p align="center">
  <a href="https://docs.runpanther.io">Documentation</a> |
  <a href="https://blog.runpanther.io">Blog</a>
</p>

<p align="center">
  <h3>Panther is a flexible, scalable, cloud-native SIEM designed for the modern security team</h3>
</p>

<p align="center">
  <a href="https://gitter.im/runpanther/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge"><img src="https://badges.gitter.im/runpanther/community.svg" alt="Gitter"/></a>
  <a href="https://magefile.org"><img src="https://magefile.org/badge.svg" alt="Built with Mage"/></a>
  <a href="https://circleci.com/gh/panther-labs/panther"><img src="https://circleci.com/gh/panther-labs/panther.svg?style=svg" alt="CircleCI"/></a>
</p>

---

Developed by a [dedicated team](https://runpanther.io/about/) of cloud security practitioners, Panther is designed to be:

- **Flexible:** Python-based detections with integrations into common tools such as PagerDuty, Slack, MS Teams, and more
- **Scalable:** Built with serverless technology for cost and operational efficiency at any scale
- **Secure:** Least-privilege and encrypted infrastructure that you control
- **Integrated:** Support for many popular security logs combined with rich information about your cloud resources
- **Automated:** Fast and simple deployments with AWS CloudFormation

### Panther Use Cases

- **SIEM:** Centralize all security log data for threat detection, historical search, long-term storage, and investigations
- **[Threat Detection](https://runpanther.io/log-analysis):** Detect suspicious activity quickly and effectively with Python rules
- **Alerting:** Send notifications to your team when new issues are identified
- **[Cloud Compliance](https://runpanther.io/compliance/):** Detect and enforce AWS infrastructure best practices with Python policies
- **Automatic Remediation:** Correct insecure infrastructure as soon as new issues are identified

_NOTE: Panther is currently in beta._

## Getting Started

To deploy Panther from source:

1. Install Go 1.13+, Node 10+, and Python 3.7+
   - For mac w/ homebrew, `brew install go node python3`
2. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv1.html)
   - [Configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) your AWS region and credentials
3. Install [Mage](https://magefile.org/#installation)
   - If you run into issues, try explicitly [setting GOPATH](https://github.com/golang/go/wiki/SettingGOPATH): `export GOPATH=$HOME/go`
4. Clone the repo to `$GOPATH/src`
   - HTTPS: `git clone https://github.com/panther-labs/panther $GOPATH/src/github.com/panther-labs/panther`
   - SSH: `git clone git@github.com:panther-labs/panther $GOPATH/src/github.com/panther-labs/panther`
5. From the root of the repo, run `mage setup && npm i`
   - `pip` may show warnings about incompatible packages which are safe to ignore
6. Deploy! `mage deploy`
   - Your IAM role will need permission to create resources in Lambda, DynamoDB, S3, ECS, ELB, EC2 (security groups, subnets, VPC), SNS, SQS, SES, KMS, IAM, CloudFormation, CloudWatch, API Gateway, Cognito, and AppSync.
   - NOTE: The initial deploy will take 10-15 minutes. If your credentials timeout, you can safely redeploy to pick up where you left off.
7. Configure your initial Panther admin user
   - Near the end of the deploy command, you'll be prompted for first/last name and email
   - You will get an email from **no-reply@verificationemail.com** with your temporary password. If you don't see it, be sure to check your spam folder.
8. Sign in to Panther! The URL is listed in the welcome email and also printed at the end of the deploy command.
   - WARNING: By default, Panther generates a self-signed certificate, which will cause most browsers to present a warning page.
   - If you see a "502 Bad Gateway" error, wait a few minutes and refresh the page
9. [Onboard your AWS account(s)](https://docs.runpanther.io/quick-start) in your Panther deployment!

## Development

Since the majority of Panther is written in Go, we follow the [standard Go project layout](https://github.com/golang-standards/project-layout).

Run `mage` to see the list of available commands (`-v` for verbose mode). You can easily chain `mage` commands together, for example:

```bash
mage fmt test:ci deploy
```

### Testing

1. Run backend test suite: `mage test:ci`
2. Run frontend test suite: `npm run lint`
3. Run integration tests against a live deployment: `mage test:integration`
   - WARNING: Integration tests will erase all Panther data stores
   - To run tests for only one package: `PKG=./internal/compliance/compliance-api/main mage test:integration`

## Contributing

We welcome contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther/blob/master/docs/CONTRIBUTING.md) before submitting pull requests.

## License

Panther is dual-licensed under the AGPLv3 and Apache-2.0 [licenses](https://github.com/panther-labs/panther/blob/master/LICENSE).
