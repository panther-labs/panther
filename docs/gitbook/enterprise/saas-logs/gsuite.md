# G Suite Setup

In order for Panther to access the Reports of your organization, you will need to create a new G Suite application with the necessary permissions.

Panther will use this application to pull the logs periodically (every 1 minute).

## Creating a G Suite Application

{% hint style="info" %}
The steps below can only be performed if your G Suite user has permissions to see your organization's Reports. If your user doesn't have such permissions, you can follow the steps [here](https://support.google.com/a/answer/2406043) in order to create a new role with Reports access and assign the role to your user.
{% endhint %}

### Create a Google API project
1. Go to [Google API Console](https://console.developers.google.com/project)
1. Click **Create Project**
1. Enter a project name e.g. `Panther`
1. Click **Create**. It will take a few seconds to create the project. Once created, you will get an on-screen notification.
 You can click **View** to see the details of the project.

### Enable access
1. Select the option to **Enable APIs**
1. Select the **Admin SDK** and click **Enable**
1. Select **Credentials** and **Configure Consent Screen**
1. Click on **Internal** and **Create**
1. Enter an **Application Name** e.g. `Panther` and click **Save**

### Create Credentials
1. Click on **Create Credentials** > **OAuth client ID**
1. Select **Desktop app** as **Application Type** . You can give it a name e.g. `Panther`
1. Click on **Create**

{% hint style="info" %}
Keep note of the ClientID and Client Secret! You will need to provide them in the Panther UI to pull your reports.
{% endhint %}
