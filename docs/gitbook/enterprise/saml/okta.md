---
description: Integrating Okta with Panther Enterprise
title: Okta SAML Integration
---

# Okta SAML Integration

First, [deploy](../../quick-start.md) Panther Enterprise and go to the General Settings page. Note the values for "Audience" and "ACS URL":

![](../../.gitbook/assets/enterprise/saml/panther-saml-parameters.png)

## Create Okta App

{% hint style="info" %}
We are in the process of registering an official Panther Okta app, but in the meantime follow these steps to configure an Okta app manually.
{% endhint %}

From the Okta admin console, navigate to the Applications tab

![](../../.gitbook/assets/enterprise/saml/okta1.png)

Click "Add Application"

![](../../.gitbook/assets/enterprise/saml/okta-new-app.png)

Click "Create New App" and configure "Platform: Web" app and "Sign on method: SAML 2.0"

![](../../.gitbook/assets/enterprise/saml/okta2.png)

Click "Create" and configure the General Settings however you see fit. We recommend:

![](../../.gitbook/assets/enterprise/saml/okta3.png)

Click "Next" and configure section 2A, "SAML Settings", as follows:

![](../../.gitbook/assets/enterprise/saml/okta4.png)

The "Single sign on URL" and "Audience URI" were copied from the Panther General Settings page earlier.
The "Group Attribute Statements" can be left blank (not shown here).
Click "Next" and fill out feedback for Okta, linking to this documentation page if you like. Click "Finish."

Copy the "Identity Provider metadata" link shown on the next screen, under the Settings section of the "Sign On" tab:

![](../../.gitbook/assets/enterprise/saml/okta-metadata.png)

This is the "Identity provider URL" you will need to give to Panther.

Finally, be sure to grant access to the appropriate people/groups in the "Assignments" tab.

## Configure Panther

From the Panther settings page, enable SAML with a default [Panther role](../rbac.md) of your choice and
paste the Okta metadata URL you just copied:
  
![](../../.gitbook/assets/enterprise/saml/okta-panther.png)

Click "Save" and then you're done! Now, the Panther login page will show a button to login via Okta:

![](../../.gitbook/assets/enterprise/saml/panther-login-sso.png)