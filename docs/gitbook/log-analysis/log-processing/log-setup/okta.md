# Okta Setup

Panther has the ability to fetch events from the [Okta System Log API](https://developer.okta.com/docs/reference/api/system-log/).

In order for Panther to access the API you need to create a new API token or use an existing one. Panther will use this token to pull the logs periodically (every 1 minute).

### Create a new API token

{% hint style="info" %}
To create an API token with permissions to query Okta System Logs,  you will need to be logged in as an administrator that possesses the rights to perform your API call's actions.
Please refer to [Okta documentation](https://help.okta.com/en/prod/Content/Topics/Security/Administrators.htm?Highlight=administrators) for information on managing Admin roles and their rights.  
{% endhint %}

1. Log in as Okta administrator
1. In the Okta Admin Console, navigate to **Security > API**
1. Click **Create Token**
1. Enter a name for your token, e.g. `Panther API token`
1. Document the **Token value** from the screen that appears.
   **Important**: be sure to document and store the API token value carefully, as it cannot be retrieved later and can present a security risk if used in an unauthorized fashion

### Create a new Okta source in Panther

1. Login to your Panther account
1. Click **Log analysis** on the sidebar menu
1. Click **Sources**
1. Click **Add Source**
1. Select **Okta** from the list of available types
1. Enter a friendly name for the source (e.g. `My Okta logs`)
1. Add your Okta subdomain
1. Paste the API Token value that you saved earlier. 
1. Save the source!
