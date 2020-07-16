# SAML Integration
Panther Enterprise offers SAML integration, which allows users to login via SSO providers like OneLogin, Okta, or others.

## Guides

Follow these step-by-step guides to enable SAML integration with one of the following:

* [OneLogin](onelogin.md)
* [Okta](okta.md)
* [(Other)](generic.md)

## Terminology

* **SAML** - Security Assertion Markup Language - an open standard for exchanging authentication credentials
* **SSO** - Single Sign-On - a central hub which allows users to share one login session with multiple services - in this context, synonymous with a SAML IdP
* **IdP** - Identity Provider - the system which provides authentication credentials: OneLogin, Okta, or others
* **SP** - Service Provider - the system which receives authentication credentials: in this case, Panther Enterprise

## Features

* **SP-initiated login flow** - When SAML is enabled, Panther will show a special link on the login page which, when clicked, will redirect to the IdP for login
* **Auto-provisioning** - Panther SAML accounts are created on the first login; they do not need to be created in advance
* **Role integration** - A single [Panther Role](../rbac.md) of your choice is assigned to SAML users by default, and you can change user roles after their first login

Standard password-based logins are still supported after you enable SAML integration - users can be created and authorized in either flow.

## Limitations

Panther does not support the following:

* **IdP-initiated login flow** - Users cannot login from OneLogin or Okta directly, they must navigate to the Panther login page first
* **SCIM** - Users deleted from the IdP are not automatically deleted from Panther (they just can't login anymore)
* **Attribute mapping** - Panther roles cannot be assigned via SAML attributes

These limitations stem from Amazon Cognito, the user management service Panther is built on.
