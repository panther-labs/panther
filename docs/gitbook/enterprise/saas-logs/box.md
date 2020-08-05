# Box Setup

Panther has the ability to fetch events from the [Box Events API](https://developer.box.com/reference/get-events/).

In order for Panther to access the API you need to create a new 'Box App' and provide the app credentials to Panther.
Panther will use this 'Box App' and the app credentials to pull the logs periodically (every 1 minute).

{% hint style="info" %}
 To be able to read events for the entire enterprise account, the Box user performing the following steps
 *must* have [admin priviledges on the enterprise account](https://developer.box.com/guides/authentication/user-types/managed-users//#admin--co-admin-roles).
 Otherwise only events from the user creating the App will be accessible.
{% endhint %}


### Create a new Box Source in Panther


1. Login to your Panther account
1. Click **Log analysis** on the sidebar menu
1. Click **Sources**
1. Click **Add Source**
1. Select **Box** from the list of available types
1. Enter a name for the source (e.g. `box-events`)
1. Copy the Redirect URL

### Create a new Box App

1. In a new tab login to [Box developer console](https://app.box.com/developers/console)
1. Click **Create New App**
1. Select **Enterprise Integration** and click **Next**
1. Select **Standard OAuth 2.0** and click **Next**
1. Insert a name for your app (e.g. `panther`) and click **Create App**
1. Click **View your App** to configure your new application
1. Scroll down to the **OAuth 2.0 Redirect URI** section and paste the redirect URL 
copied from Panther
1. On the **Application Scopes** section make sure **Manage enterprise properties** is selected
1. Click **Save Changes** to store the app configuration

###  Copy Box App credentials and authorize Panther

1. Copy **Client ID** and **Client Secret** credentials from Box Developer Console over to Panther in the
respective fields.
1. Click **Next**
1. Click **Save Source**
1. Click **Authorize** (you will be redirected to Box)
1. Click **Grant access to Box** (you will be redirected back to Panther)
1. Your new Box Source should be healthy and ready to fetch events from Box!


