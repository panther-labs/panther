# Generic Panther-SAML Integration
You can integrate any SAML Identity Provider with Panther Enterprise in 3 easy steps:

1. [Deploy](../../quick-start.md) Panther Enterprise
2. Add a "test" or "manual" SAML integration to your identity provider, with the following settings:
    * Audience: `urn:amazon:cognito:sp:USER_POOL_ID`
    * ACS / Consumer URL: `https://USER_POOL_HOST/saml2/idpresponse`
    * SAML Attribute Mapping:
        * `PantherEmail` -> user email
        * `PantherFirstName` -> first/given name
        * `PantherLastName` -> last/family name
    * Grant access to the appropriate users
3. From the Panther settings page, enable SAML with:
    * A default [Panther role](../rbac.md) of your choice
    * The issuer/metadata URL from the SAML integration in your identity provider

See the [OneLogin](onelogin.md) and [Okta](okta.md) integration guides for examples.

{% hint style="info" %}
The `USER_POOL_ID` and `USER_POOL_HOST` referenced above should be replaced with the Cognito user pool ID and domain, respectively.

These will soon be shown in the Panther settings page, but can also be found in the Cognito AWS console or the `panther-bootstrap` stack outputs.
{% endhint %}
