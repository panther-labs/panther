# Security

Safety and data security is a very high priority for the Panther Labs team.

If you have discovered a security vulnerability in our application, please disclose it to us in a responsible manner. Security issues identified in any of the open-source codebases maintained by Panther Labs or any of our commercial offerings should be reported via email to [security@runpanther.io](mailto:security@runpanther.io).

Panther Labs is committed to working together with researchers and keeping them updated throughout the patching process. Researchers who responsibly report valid security issues will be publicly credited for their efforts (if they so choose).

## The Panther Threat Model

All data passed through Panther is always under your control and encrypted both in transit and at rest. Supporting AWS infrastructure is least-privilege and deployed with AWS CloudFormation.

We believe that part of establishing a strong security stance is establishing your threat model.

For Panther, the threat model includes attackers entirely external to the organization running Panther, as well as attackers within the organization that do not have access to Panther. Panther is designed be secure against malicious actors attempting to abuse or sidestep the system as long as those threats do not have access to the Panther UI or admin access to the AWS account where Panther is deployed. Any attacker that does have this access has the capability to sidestep, break, disable, or abuse the Panther deployment. In particular, **any attacker that has the ability to edit or create arbitrary policies/rules should be considered to have full access to any and all data processed by Panther.**

## Your Responsibilities

Panther has been designed to be as secure as possible while still providing the core functionality of running arbitrary Python rules and policies on all of your logs and cloud infrastructure.

The power to write arbitrary Python can easily be abused to make Panther do just about anything. It is your responsibility to ensure that the policies and rules run in your environment are trusted by you, and we recommend the following best practices to assist in this endeavor:

1. Be very careful with who you grant access to your Panther deployment. Again, any user with Panther credentials that can edit policies or rules has access to all data processed by Panther!
2. Do not share or re-use Panther credentials. Although we do our best to enforce secure logins, sharing credentials increases the chance of a malicious actor compromising these credentials and reduces your ability to audit who made what changes to the system.
3. Very carefully review any policies or rules before running them. The Panther policy/rule format is open, and anyone can write policy and rule packs and post them online. Before running any policies or rules written by someone else, review them carefully to be sure you understand what they are doing.
4. Be careful when directly accessing/modifying Panther backend services. One of the great things about Panther being open source is that you can modify any aspect of the codebase that you wish, and we highly encourage such customization! But when modifying backend services, be careful of removing controls that seem arbitrary or unnecessary as they may have been put in place to prevent non-obvious abuses of the system.

{% hint style="info" %}
When in doubt, always feel free to reach out to the Panther team via GitHub, Slack, or email with any questions!
{% endhint %}

By following these best practices and common sense security, you can use Panther to secure your environment without exposing yourself to undue risk.

## Privacy

If you opt in to error reporting, the following information will be sent to the Panther team when there is a web application exception or crash:

- The version of your Browser, OS & Panther installation
  > This helps us understand how to replicate the issue.
- The type of error, its related stack trace and the URL of the page in which it occurred.
  > This helps us identify the code associated with the issue and gaining insight on the preceding function calls. **All sensitive parameters or variables are excluded**.

The Panther team greatly benefits from understanding runtime issues that occur in installations and can enable us to resolve them quickly. You can always change your error reporting preferences through the **General Settings** page.
