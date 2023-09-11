---
title: Configure a Directory Service account | Microsoft Defender for Identity
description: Learn how to configure the Directory Service account (DSA) to work with Microsoft Defender for Identity.
ms.date: 08/27/2023
ms.topic: how-to
---

# Configure a Directory Service account for Microsoft Defender for Identity

This article describes how to create and configure a Defender for Identity Directory Service account (DSA).

Defender for Identity's sensor uses a DSA to do the following:

- Connect to the domain controller at startup using the configured DSA option
- Query the domain controller for data on entities seen in network traffic, monitored events, and monitored ETW activities
- Request member lists for local administrator groups from devices seen in network traffic, events and ETQ activities via a [SAM-R call](remote-calls-sam.md) made to the device. Collected data is used to calculate potential lateral movement paths.

One sensor in each domain is defined as the *domain synchronizer*, and is responsible for tracking changes to the entities in the domain, like objects created, entity attributes tracked by Defender for Identity and so on.

If a sensor detects activities in other domains, it queries the other domain via LDAP for more details.

>[!NOTE]
>By default, Defender for Identity supports up to 30 credentials. To add more credentials, contact Defender for Identity support.

## Supported DSA account options

Defender for Identity supports the following DSA options:

- **gMSA** (Recommended). Provides a more secure deployment and password management. Active Directory manages the creation and rotation of the account's password, just like a computer account's password, and you can control how often the account's password is changed.

    gMSA requires extra setup steps.

- **Regular user account**. Easy to use when getting started, and simpler to configure read permissions between trusted forests, but requires extra overhead for password management.

    A regular user account is less secure, as it requires you to create and manage passwords, and can lead to downtime if the password expires and isn't updated for both the user and the DSA.

## DSA entry usage

This section describes how to understand how many DSA entries are used and how the sensor selects the DSA entry to use in any given scenario.

Defender for Identity requires at least one DSA entry, with read permissions to all the domains in the forests. In an untrusted, multi-forest environment, a DSA account is required for each forest.

Defender for IoT gets a list of DSA entries configured for Defender for Identity, and selects an entry to use.

### Single DSA entry

When only one DSA entry is configured, the sensor attempts to use the configured DSA entry in the following scenarios:

- At start up, as a reaction to a new domain contacting the domain controller
- Each time a SAM-R query is made
- Whenever a connection needs to be recreated

Sensor attempts differ, depending on the type of DSA entry:

|Type  |Description  |
|---------|---------|
|**gMSA account**     | The sensor attempts to retrieve the gMSA account password from Active Directory, and then sign into the domain.        |
|**Regular user account**     |   The sensor attempts to sign into the domain controller using the configured username and password.      |

### Multiple DSA entries

When there are multiple DSA entries configured, the following logic is applied:

1. The sensor looks for an entry with an exact match of the domain name for the target domain. If an exact match is found, the sensor attempts to authenticate using the credentials in that entry.

1. If there isn't an exact match, or if the authentication failed, the sensor searches the list for an entry to the parent domain using DNS FQDN, and attempts to authenticate using the credentials in the parent entry instead.

1. If there isn't an entry for the parent domain, or if the authentication failed, the sensor searches the list for an sibling domain entry, using the DNS FQDN, and attempts to authenticate using the credentials in the sibling entry instead.

1. If there isn't an entry for the sibling domain, or if the authentication failed, the sensor reviews the list again and tries to authenticate again with each entry until it succeeds. DSA gMSA entries have higher priority than regular DSA entries.

For example, the sensor tries the DSA entries in the following order:

1.	The sensor looks for a match between the DNS domain name of the target domain, such as `emea.contoso.com` and the DSA gMSA entry, such as `emea.contoso.com`.

1. The sensor looks for a match between the DNS domain name of the target domain, such as `emea.contoso.com` and the DSA regular entry DSA, such as `emea.contoso.com`

1. The sensor looks for a match in the root DNS name of the target domain, such as `emea.contoso.com` and the DSA gMSA entry domain name, such as `contoso.com`.

1. The sensor looks for a match in the root DNS name of the target domain, such as `emea.contoso.com` and the DSA regular entry domain name, such as `contoso.com`.

1. The sensor looks for the target domain name for a sibling domain, such as `emea.contoso.com` and the DSA gMSA entry domain name, such as `apac.contoso.com`.

1. The sensor looks for the target domain name for a sibling domain, such as `emea.contoso.com` and the DSA regular entry domain name, such as `apac.contoso.com`.

1. The sensor runs a round robin of all DSA gMSA entries.

1. The sensor runs a round robin of all DSA regular entries.

For another example, if the DSA entires configured are as follows:

- `DSA1.northamerica.contoso.com`
- `DSA2.EMEA.contoso.com DSA3.fabrikam.com`

Then the following table lists the sensors and the DSA entry that's used first:

| Domain controller FQDN | DSA entry used |
| --------------------------- | -------------------------------- |
| `DC01.contoso.com`        | Round robin                      |
| `DC02.fabrikam.com`       | `DSA3.fabrikam.com`                |
| `DC03.emea.contoso.com`   | `DSA2.emea.contoso.com`            |
| `DC04.contoso.com`        | Round robin                      |

>[!IMPORTANT]
>If a sensor isn't able to successfully authenticate via LDAP to the Active Directory domain at startup, the sensor won't enter a running state and a health issue is generated. For more information, see [Defender for Identity health issues](../health-alerts.md).

## Create a gMSA account for use with Defender for Identity

This section describes how to create a gMSA account for use as a Defender for Identity DSA entry. For more information, see [Getting started with Group Managed Service Accounts](/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts).
  
>[!TIP]
>In multi-forest, multi-domain environments, we recommend creating the gMSAs with a unique name for each forest or domain. Also, create a universal group in each domain, containing all sensors' computer accounts so that all sensors can retrieve the gMSAs' passwords, and perform the cross-domain authentications.

### Grant permissions to retrieve the gMSA account's password

Before you create the gMSA account, consider how to assign permissions to retrieve the account's password.

When using a gMSA entry, the sensor needs to retrieve the gMSA's password from Active Directory. This can be done either by assigning to each of the sensors or by using a group.

- **In a single-forest, single-domain deployment**, if you aren't planning to install the sensor on any AD FS servers, you can use the built-in Domain Controllers security group.

- **In a forest with multiple domains**, when using a single DSA account, we recommend creating a universal group and adding each of the domain controllers and AD FS / AD CS servers to the universal group.
 
If you add a computer account to the universal group after the computer received its Kerberos ticket, it won't be able to retrieve the gMSA's password until it receives a new Kerberos ticket. The Kerberos ticket has a list of groups that an entity is a member of when the ticket is issued.

In such scenarios, do one of the following:

- **Wait for new Kerberos ticket to be issued**. Kerberos tickets are normally valid for 10 hours.

- **Reboot the server**. When the server is rebooted, a new Kerberos ticket is requested with the new group membership.

- **Purge the existing Kerberos tickets**. This forces the domain controller to request a new Kerberos ticket. 

    To purge the tickets, from an administrator command prompt on the domain controller, run the following command: `klist purge -li 0x3e7`

### Create the gMSA account

This section describes how to create a specific group that can retrieve the account's password, create a gMSA account, and then test that the account is ready to use.

Run the following PowerShell commands as an administrator:

```powershell
# Set the variables: 
$gMSA_AccountName = 'mdiSvc01' 
$gMSA_HostsGroupName = 'mdiSvc01Group' 
$gMSA_HostNames = 'DC1', 'DC2', 'DC3', 'DC4', 'DC5', 'DC6', 'ADFS1', 'ADFS2', 'ADCS1',
# Import the required PowerShell module: 
Import-Module ActiveDirectory 
# Create the group and add the members 
$gMSA_HostsGroup = New-ADGroup -Name $gMSA_HostsGroupName -GroupScope Global -PassThru 
$gMSA_HostNames | ForEach-Object { Get-ADComputer -Identity $_ } | 
    ForEach-Object { Add-ADGroupMember -Identity $gMSA_HostsGroupName Members $_ } 
# Or, use the built-in 'Domain Controllers' group if the environment is a single forest, and will contain only domain controller sensors 
# $gMSA_HostsGroup = Get-ADGroup -Identity 'Domain Controllers'    
# Create the gMSA: 
New-ADServiceAccount -Name $gMSA_AccountName -DNSHostName 
"$gMSA_AccountName.$env:USERDNSDOMAIN" ` 
-PrincipalsAllowedToRetrieveManagedPassword $gMSA_HostsGroupName 
```

### Grant required DSA permissions

The DSA requires read permissions on all objects in Active Directory, including the **Deleted Objects** container.

The read-only permissions on the **Deleted Objects** container allows Defender for Identity to detect user deletions from your Active Directory.

Use the following code sample to help you grant the required read permissions on the **Deleted Objects** container:

```powershell
# Declare the *user* or *group* that needs to have read access to the deleted objects container 
# Note that if the identity you want to grant the permissions to is a Group 
Managed Service Account (gMSA),  
# you need first to create a security group, add the gMSA as a member and list that group as the identity below $Identity = 'CONTOSO\mdisvc' 
# Get the deleted objects container's distinguished name: 
$distinguishedName = ([adsi]'').distinguishedName.Value 
$deletedObjectsDN = 'CN=Deleted Objects,{0}' -f $distinguishedName 
# Take ownership on the deleted objects container: $params = @("$deletedObjectsDN", '/takeOwnership') 
C:\Windows\System32\dsacls.exe $params 
# Grant the 'List Contents' and 'Read Property' permissions to the user or group: 
$params = @("$deletedObjectsDN", '/G', "$($Identity):LCRP") 
C:\Windows\System32\dsacls.exe $params 
# To remove the permissions, uncomment the next 2 lines and run them instead of the two prior ones:
# $params = @("$deletedObjectsDN", '/R', $Identity)
# C:\Windows\System32\dsacls.exe $params
```

For more information, see [Changing permissions on a deleted object container](/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc816824(v=ws.10)).

### Install the gMSA account

To install the gMSA account, run the following commands as an administrator, locally on each of the servers:

```powershell
# Import the required PowerShell module:
Import-Module ActiveDirectory

# Install the gMSA account
Install-ADServiceAccount -Identity 'mdiSvc01'
```

### Validate that the domain controller can retrieve the gMSA's password

To validate that the server has the required permissions to retrieve the gMSA's password, run the following PowerShell command:

```powershell
Test-ADServiceAccount -Identity 'mdiSvc01'
```

If it has the permissions, the command will return a **True** message.

>[!NOTE]
>If you get an error message when running Test-ADServiceAccount, either restart the server or run `klist purge -li 0x3e7` and try again.

### Verify that the gMSA account has the required rights

The Defender for Identity sensor service, *Azure Advanced Threat Protection Sensor*, runs as a *LocalService* and performs impersonation of the DSA account. The impersonation will fail if the *Log on as a service* policy is configured but the permission hasn't been granted to the gMSA account. In such cases, you'll see the following health issue: **Directory services user credentials are incorrect.**

If you see this alert, we recommend checking to see if the *Log on as a service policy* is configured. If you need to configure the *Log on as a service* policy, do so either in a Group Policy setting or in a Local Security Policy.

- **To check the Local Policy**, run `secpol.msc` and select **Local Policies**. Under **User Rights Assignment**, go to the **Log on as a service policy** setting. For example:

    :::image type="content" source="../media/log-on-as-a-service.png" alt-text="Screenshot of the log on as a service properties.":::

    If the policy is enabled, add the gMSA account to the list of accounts that can log on as a service.

- **To check if the setting is configured in a Group Policy**: Run `rsop.msc` and see if the **Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> Log on as a service** policy is selected. For example:
    
    :::image type="content" source="../media/log-on-as-a-service-gpmc.png" alt-text="Screenshot of the Log on as a service policy in the Group Policy Management Editor." lightbox="../media/log-on-as-a-service-gpmc.png":::

    If the setting is configured, add the gMSA account to the list of accounts that can log on as a service in the Group Policy Management Editor.

> [!NOTE]
> If you use the Group Policy Management Editor to configure the **Log on as a service** setting, make sure you add both **NT Service\All Services** and the gMSA account you created.

## Configure a Directory Service account in Microsoft 365 Defender

To connect your sensors with your Active Directory domains, you'll need to configure Directory Service accounts in Microsoft 365 Defender.

1. In [Microsoft 365 Defender](https://security.microsoft.com/), go to **Settings > Identities**. For example:

    [![Screenshot of the Identities settings in Microsoft 365 Defender.](../media/settings-identities.png)](../media/settings-identities.png#lightbox)

1. Select **Directory Service accounts**. You'll see which accounts are associated with which domains. For example:

    [![Screenshot of the Directory Service accounts page.](../media/directory-service-accounts.png)](../media/directory-service-accounts.png#lightbox)

1. To add Directory Service account credentials, select **Add credentials** and enter the **Account name**, **Domain**, and **Password** of the account you created earlier. You can also choose if it's a **Group managed service account** (gMSA), and if it belongs to a **Single label domain**. For example:

    [![Screenshot of the add credentials pane.](../media/new-directory-service-account.png)](../media/new-directory-service-account.png#lightbox)

    |Field|Comments|
    |---|---|
    |**Account name** (required)|Enter the read-only AD username. For example: **DefenderForIdentityUser**. <br><br>- You must use a **standard** AD user or gMSA account. <br>- **Don't** use the UPN format for your username. <br>- When using a gMSA, the user string should end with the `$` sign. For example: `mdisvc$`<br /><br>**NOTE:** We recommend that you avoid using accounts assigned to specific users.|
    |**Password** (required for standard AD user accounts)|For AD user accounts only, generate a strong password for the read-only user. For example: `PePR!BZ&}Y54UpC3aB`.|
    |**Group managed service account** (required for gMSA accounts)|For gMSA accounts only, select **Group managed service account**.|
    |**Domain** (required)|Enter the domain for the read-only user. For example: **contoso.com**. <br><br>It's important that you enter the complete FQDN of the domain where the user is located. For example, if the user's account is in domain corp.contoso.com, you need to enter `corp.contoso.com` not `contoso.com`. <br><br>For more information, see [Microsoft support for Single Label Domains](/troubleshoot/windows-server/networking/single-label-domains-support-policy).|

1. Select **Save**.
1. (Optional) If you select an account, a details pane will open with the settings for that account. For example:

    [![Screenshot of an account details pane.](../media/account-settings.png)](../media/account-settings.png#lightbox)

> [!NOTE]
> You can use this same procedure to change the password for standard Active Directory user accounts. There is no password set for gMSA accounts.

### Troubleshooting

See [Sensor failed to retrieve the gMSA credentials](../troubleshooting-known-issues.md#sensor-failed-to-retrieve-group-managed-service-account-gmsa-credentials).

## Next step

> [!div class="step-by-step"]
> [Configure SAM-R to enable lateral movement path detection in Microsoft Defender for Identity »](remote-calls-sam.md)