# Test Only - Development

This test document is based on our real `development.md` doc file.
It's designed to test our CI documentation validation.

## Panther Logo

Here is an image:

![Panther Logo](.gitbook/assets/logo.png)

## Environment

To deploy from source, install [Docker](https://docs.docker.com/install/) and make sure the daemon is running in the background.

For the remaining dependencies, you can either use our development image or install development dependencies locally.

### Development Image

This is the easier option, but will also lead to much slower builds.

Simply [export your AWS credentials](#aws-credentials) as environment variables, and then run `./dev.sh`
From here, run `mage setup` and you're good to go.

### Local Dependencies

To install dependencies locally (recommended for regular contributors):

- Install [Go](https://golang.org/doc/install#install) 1.13+
- Install [Node](https://nodejs.org/en/download/) 12
- Install [Python](https://www.python.org/downloads/) 3.7
- Install [Mage](https://magefile.org/#installation)

## Repo Layout

Since the majority of Panther is written in Go, the repo follows the standard [Go project layout](https://github.com/golang-standards/project-layout):

|                                  Path                                  | Description                                                       |
| :--------------------------------------------------------------------: | ----------------------------------------------------------------- |
|   [**api**](https://github.com/panther-labs/panther/tree/master/api)   | Input/output models for communicating with Panther's backend APIs |
| [**build**](https://github.com/panther-labs/panther/tree/master/build) | Dockerfiles for CI and deployment                                 |

## Deploying

### AWS.Credentials

Configure your AWS credentials and deployment region:

```bash
export AWS_REGION=us-east-1  # Any supported region
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

{% hint style="warning" %}
Remember to follow best security practices when handling access keys

Tools like [aws-vault](https://github.com/99designs/aws-vault) can help with all the above,
check out our [blog post](https://blog.runpanther.io/secure-multi-account-aws-access/) to learn more!
{% endhint %}

### Mage Deploy

Panther relies on a number of [custom CloudFormation resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html).

### From an EC2 Instance

You can also deploy from an EC2 instance with Docker and git installed in the same region you're deploying Panther to.
Instead of exporting your AWS credentials as environment variables, you will need to attach the [deployment IAM role](quick-start.md#test-only-quick-start) to your EC2 instance profile.
We recommend at least an `m5.large` instance type, but even one as small as `t2.small` should be sufficient.

## That Image Again

This time, with no caption and embedded in the same line: ![](.gitbook/assets/logo.png)

If you need any help, [let us know](mailto:user@example.com)

```python
# This is not a header - it's python code
```
