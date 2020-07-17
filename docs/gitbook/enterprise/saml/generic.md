# Generic SAML IdP Integration
Integrate any SAML Identity Provider (IdP) with Panther Enterprise in three easy steps:

1. [Deploy](../../quick-start.md) Panther Enterprise and navigate to the General Settings page. Note the values shown for "Audience" and "ACS URL."
2. Add a "test" or "manual" SAML integration to your IdP with the following settings:
    * Audience: `urn:amazon:cognito:sp:USER_POOL_ID` (copied from the General Settings in Panther)
    * ACS / Consumer URL: `https://USER_POOL_HOST/saml2/idpresponse` (copied from the General Settings in Panther)
    * SAML Attribute Mapping:
        * `PantherEmail` -> user email
        * `PantherFirstName` -> first/given name
        * `PantherLastName` -> last/family name
    * Grant access to the appropriate users
3. From the Panther settings page, enable SAML with:
    * A default [Panther role](../rbac.md) of your choice
    * The issuer/metadata URL from the SAML integration in your IdP

For examples, see the [OneLogin](onelogin.md) and [Okta](okta.md) integration guides.

{% hint style="info" %}
Panther screenshots coming soon!
{% endhint %}
