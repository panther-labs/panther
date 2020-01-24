---
description: Working with the Panther repo
---

# Development

### Mage

Panther uses [mage](https://magefile.org/), a Go tool similar to `make` , to manage the development lifecycle.

After [setup](quick-start.md#steps), run `mage` from the repo root to see the list of available commands:

```text
Targets:
  build:api           Generate Go client/models from Swagger specs in api/
  build:lambda        Compile all Lambda function source
  clean               Remove auto-generated build artifacts
  deploy              Deploy application infrastructure
  fmt                 Format source files
  setup               Install development dependencies
  test:ci             Run all required checks
  test:cover          Run Go unit tests and view test coverage in HTML
  test:integration    Run TestIntegration* for PKG (default: ./...)
  test:lint           Check code style
  test:unit           Run unit tests
```

You can easily chain `mage` commands together, for example: `mage fmt test:ci deploy`

### Testing

1. Run backend test suite: `mage test:ci`
2. Run frontend test suite: `npm run lint`
3. Run integration tests against a live deployment: `mage test:integration`
   - **WARNING**: integration tests will erase all Panther data stores
   - To run tests for only one package: `PKG=./internal/compliance/compliance-api/main mage test:integration`

### Updating

To update your deployment of Panther, follow the steps below:

1. Checkout the latest release:
   1. `git fetch origin master`
   2. `git checkout tags/v0.1.0`
2. Clean the existing build artifacts: `mage clean`
3. Deploy the latest application changes: `mage deploy`

### Repo Layout

Since the majority of Panther is written in Go, the repo follows the standard [Go project layout](https://github.com/golang-standards/project-layout):

- \*\*\*\*[**api**](https://github.com/panther-labs/panther/tree/master/api)**:** input/output models for communicating with Panther's backend APIs
- \*\*\*\*[**deployments**](https://github.com/panther-labs/panther/tree/master/deployments)**:** CloudFormation templates for deploying Panther itself or integrating the accounts you want to scan
- \*\*\*\*[**docs**](https://github.com/panther-labs/panther/tree/master/docs)**:** License headers, README images, code of conduct, etc
- \*\*\*\*[**internal**](https://github.com/panther-labs/panther/tree/master/internal)**:** Source code for all of Panther's Lambda functions
- \*\*\*\*[**pkg**](https://github.com/panther-labs/panther/tree/master/pkg)**:** Standalone Go libraries that could be directly imported by other projects
  - This folder is [licensed](https://github.com/panther-labs/panther/blob/master/LICENSE) under Apache v2
- \*\*\*\*[**tools**](https://github.com/panther-labs/panther/tree/master/tools)**:** Magefile source and other build infrastructure
- [**web**](https://github.com/panther-labs/panther/tree/master/web)**:** Source for the Panther web application
