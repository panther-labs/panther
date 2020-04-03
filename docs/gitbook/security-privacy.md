# Security

Safety and data security is a very high priority for the Panther Labs team. If you have discovered a security vulnerability in our codebase, we would appreciate your help in disclosing it to us in a responsible manner.

Security issues identified in any of the open-source codebases maintained by Panther Labs or any of our commercial offerings should be reported via email to [security@runpanther.io](mailto:security@runpanther.io). Panther Labs is committed to working together with researchers and keeping them updated throughout the patching process. Researchers who responsibly report valid security issues will be publicly credited for their efforts (if they so choose).

The data passed through Panther is always under your control and encrypted both in transit and at rest. All supporting AWS infrastructure is least-privilege and deployed with AWS CloudFormation.

# Your Responsibilities

Panther has been designed to be as secure as possible while still providing the core functionality of running arbitrary python rules and policies on all of your logs and cloud infrastructure. That being said, the power to write arbitrary python can easily be abused to make Panther do just about anything. Any Panther user with the ability to write policies or rules therefore has the power to access essentially any and all data processed by Panther. It is your responsibility to ensure that the policies and rules run in your environment are trusted by you, and we recommend the following best practices to assist in this endeavor:

1. Be very careful on who you grant access to your Panther deployment. Again, any user with Panther credentials that can edit policies or rules has access to all data processed by Panther!
2. Do not share or re-use Panther credentials. Although we do our best to enforce secure logins, sharing credentials increases the chance of a malicious actor compromising these credentials and reduces your ability to audit who made what changes to the system.
3. Very carefully audit any policies or rules before running them. The Panther policy/rule format is open, and anyone can write policy and rule packs and post them online. Before running any policies or rules written by someone else, review them carefully to be sure you understand what they are doing.
4. Be careful when accessing/modifying Panther backend services. One of the great things about Panther being open source is that you can modify any aspect of the codebase that you wish, and we highly encourage this customization! But when modifying backend services, be careful of removing controls that seem arbitrary or unnecessary as they may have been put in place to prevent non-obvious abuses of the system. When in doubt, always feel free to reach out to the Panther team via GitHub, Slack, or email with any questions.

By following these best practices and common sense security, you can use Panther to secure your environment without exposing yourself to undue risk.

# Privacy

If you opt in to error reporting, the following information will be sent to the Panther team when there is a web application exception or crash:

- The version of your Browser, OS & Panther installation
  > This helps us understand how to replicate the issue.
- The type of error, its related stack trace and the URL of the page in which it occurred.
  > This helps us identify the code associated with the issue and gaining insight on the preceding function calls. **All sensitive parameters or variables are excluded**.

The Panther team greatly benefits from understanding runtime issues that occur in installations and can enable us to resolve them quickly. You can always change your error reporting preferences through the **General Settings** page.
