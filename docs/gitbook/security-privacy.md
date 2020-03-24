# Security

Safety and data security is a very high priority for the Panther Labs team. If you have discovered a security vulnerability in our codebase, we would appreciate your help in disclosing it to us in a responsible manner.

Security issues identified in any of the open-source codebases maintained by Panther Labs or any of our commercial offerings should be reported via email to [security@runpanther.io](mailto:security@runpanther.io). Panther Labs is committed to working together with researchers and keeping them updated throughout the patching process. Researchers who responsibly report valid security issues will be publicly credited for their efforts (if they so choose).

The data passed through Panther is always under your control and encrypted both in transit and at rest. All supporting AWS infrastructure is least-privilege and deployed with AWS CloudFormation.

# Privacy

If you opt in to error reporting, the following information will be sent to the Panther team when there is a web application exception or crash:

- The version of your Browser, OS & Panther installation
  > This helps us understand how to replicate the issue.
- The type of error, its related stack trace and the URL of the page in which it occurred.
  > This helps us identify the code associated with the issue and gaining insight on the preceding function calls. **All sensitive parameters or variables are excluded**.

The Panther team greatly benefits from understanding runtime issues that occur in installations and can enable us to resolve them quickly. You can always change your error reporting preferences through the **General Settings** page.
