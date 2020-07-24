---
description: Integrating OneLogin with Panther Enterprise
title: OneLogin SAML Integration
---

# OneLogin SAML Integration

First, [deploy](../../quick-start.md) Panther Enterprise and go to the General Settings page. Note the values for "Audience" and "ACS URL":

![](../../.gitbook/assets/saml-parameters.png)

## Create OneLogin App

{% hint style="info" %}
We are in the process of registering an official Panther OneLogin app, but in the meantime follow these steps to configure a OneLogin app manually.
{% endhint %}

From the OneLogin admin console, navigate to the Applications tab.

![](../../.gitbook/assets/saml-onelogin1.png)

Click the "Add App" button at the top of the next page, and search for "saml test connector." Choose the IdP version:

![](../../.gitbook/assets/saml-onelogin2.png)

Choose a display name (e.g. "Panther Enterprise") and a logo/description, if you like. We recommend disabling
"visible in portal," since SAML logins can only be initiated from Panther. Click "Save."

Now you can edit the application configuration, filling in the "Audience" and "ACS Consumer" values you found in the Panther General Settings page a moment ago: 

![](../../.gitbook/assets/saml-onelogin3.png)

In the next tab, add Panther's custom parameters - `PantherFirstName`, `PantherLastName`, and `PantherEmail`:

![](../../.gitbook/assets/saml-onelogin4.png)

For each parameter, be sure to check "include in SAML assertion":

![](../../.gitbook/assets/saml-onelogin4-inset.png)

From the "SSO" tab, strengthen the algorithm to SHA-512 (optional) and copy the Issuer URL:

![](../../.gitbook/assets/saml-onelogin5.png)

This is the "Identity provider URL" you will need to give to Panther.

Finally, don't forget to grant access to the appropriate users / groups. Save your OneLogin application.

## Configure Panther

From the Panther settings page, enable SAML with a default [Panther role](../rbac.md) of your choice and
paste the OneLogin issuer URL you just copied:
  
![](../../.gitbook/assets/saml-panther-onelogin.png)

Click "Save" and then you're done! Now, the Panther login page will show a button to login via OneLogin:

![](../../.gitbook/assets/login-page-with-sso.png)

