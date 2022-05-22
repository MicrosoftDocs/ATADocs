---
title: Directory Service account recommendations
description: Learn how to configure the Directory Service account (DSA) to work with Microsoft Defender for Identity.
ms.date: 12/22/2021
ms.topic: how-to
---

# Microsoft Defender for Identity Directory Service account recommendations

Learn how to create a Directory Service account (DSA), and configure it to work with Microsoft Defender for Identity.

## Introduction

The Directory Service account (DSA) in Defender for Identity is used by the sensor to perform the following functions:

- At startup, the sensor connects to the domain controller using LDAP with the DSA account credentials.

- The sensor queries the domain controller for information on entities seen in network traffic, monitored events, and monitored ETW activities.

- One sensor in each domain will be set as the "domain synchronizer" and is responsible for tracking changes to the entities in the domain, like objects created, entity attributes tracked by Defender for Identity, and so on.

- If the sensor sees activities from entities in other domains, it will query that domain via LDAP for information on the entity.

- Defender for Identity requests the list of members of the local administrator group from devices seen in network traffic, events, and ETW activities. This is done by making a [SAM-R](install-step8-samr.md) call to the device. This information is used to calculate potential lateral movement paths.

>[!NOTE]
>By default, Defender for Identity supports up to 30 credentials. If you want to add more credentials, contact Defender for Identity support.

## Permissions required for the DSA

The DSA requires read permissions on all the objects in Active Directory, including the Deleted Objects Container.

>[!NOTE]
>**Deleted Objects** container recommendation: The DSA should have read-only permissions on the Deleted Objects container. Read-only permissions on this container allow [!INCLUDE [Product short](includes/product-short.md)] to detect user deletions from your Active Directory. For information about configuring read-only permissions on the Deleted Objects container, see the **Changing permissions on a deleted object container** section of the [View or Set Permissions on a Directory Object](/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc816824(v=ws.10)) article.

## Types of DSA accounts

There are two types of DSA that can be used:

- Group Managed Service Account (gMSA) – **recommended**

- Regular user account in Active Directory

| Type of DSA           | Pros                                                         | Cons                                                         |
| --------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| gMSA                  | <li>    More secure deployment since Active Directory manages the creation and rotation of the account's password like a computer account's password.  <li> You can control how often the account's password is changed. | <li> Requires additional setup  steps. |
| Regular user  account | <li> Supports all operating system versions the sensor supports.  <li> Easy to create and start working with.  <li> Easy to configure read  permissions between trusted forests. | <li> Less secure since it  requires the creation and management of passwords.   <li> Can lead to downtime if the password expires and password isn't updated (both at the user and DSA configuration). |

## Number of DSA entries

### How many DSA entries are required?

A minimum of one DSA entry is required by Defender for Identity. It should have read permissions to all the domains in the forests.

In an untrusted multi-forest environment, a DSA account will be required for each forest.

### How does the sensor pick which DSA entity to use?

When the sensor starts, it will get a list of DSA entries configured in Defender for Identity.

#### One DSA entry is configured

The sensor will attempt to use the DSA entry configured during start-up, as a reaction to a new domain contacting the domain controller, each time a SAM-R query is made, or whenever such a connection needs to be recreated.

- **Regular account**: the sensor will attempt to sign in to the domain controller using the username and password configured.

- **gMSA account**: – the sensor will attempt to retrieve the password for the gMSA account from Active Directory (AD). After retrieving the password, the sensor will attempt to sign in to the domain.

#### Two or more DSA entries are configured

When there are two or more DSA entries, the sensor will try the DSA entries in the following order:

1. Match between the DNS domain name of the target domain (for example, emea.contoso.com) and the domain of DSA gMSA entry (for example, emea.contoso.com).
2. Match between the DNS domain name of the target domain (for example, emea.contoso.com) and the domain of DSA regular entry (for example, emea.contoso.com).
3. Match in the root DNS name of the target domain (for example, emea.contoso.com) and the domain name of DSA gMSA entry (for example, contoso.com)
4. Match in the root DNS name of the target domain (for example, emea.contoso.com) and the domain name of DSA regular entry (for example, contoso.com)
5. Look for a "sibling domain" - target domain name (for example, emea.contoso.com) and DSA gMSA entry domain name (for example, apac.contoso.com).
6. Look for a "sibling domain" - target domain name (for example, emea.contoso.com) and DSA regular entry domain name (for example, apac.contoso.com).
7. Round robin all other DSA gMSA entries
8. Round robin all other DSA regular entries

- The sensor will look for a DSA entry with an exact match of the domain name of the target domain.  If an exact match is found, the sensor will attempt to sign in to the domain with the DSA entry settings.

- If there isn't an exact match of the domain name or the exact match entry failed to authenticate, the sensor will traverse the list via round robin.

For example, if these are the DSA entries configured:

- DSA1.northamerica.contoso.com
- DSA2.EMEA.contoso.com
- DSA3.fabrikam.com

Then these are the sensors, and which DSA entry will be used first:

| Domain controller FQDN | DSA entry that  will be used |
| --------------------------- | -------------------------------- |
| **DC01.contoso.com**        | Round robin                      |
| **DC02.Fabrikam.com**       | DSA3.fabrikam.com                |
| **DC03.EMEA.contoso.com**   | DSA2.emea.contoso.com            |
| **DC04.contoso.com**        | Round robin                      |

>[!NOTE]
>
> - In a multi-domain forest, it's recommended that the DSA account be created in the domain with the largest number of domain controllers.
> - In multi-forest multi-domain environments, consider creating a DSA entry for each domain in the environment to avoid failed authentications from being recorded due to the round robin method.

>[!IMPORTANT]
>If a sensor isn't able to successfully authenticate via LDAP to the Active Directory domain at startup using any of the configured DSA accounts, the sensor won't enter a running state and a health alert will be created. For more information, see [Defender for Identity health alerts](health-alerts.md).

## How to create a gMSA account for use with Defender for Identity

The following steps can be followed to create a gMSA account to be used as the DSA entry for Defender for Identity. This doesn't provide full guidance on gMSA accounts. For additional information, review [Getting started with Group Managed Service Accounts](/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts).
  

>[!NOTE]
>
>- In a multi-forest environment, we recommend creating the gMSAs with a unique name for each forest or domain.

## Granting the permissions to retrieve the gMSA account's password

Before you create the gMSA account, consider how to assign permissions to retrieve the account's password.

When using a gMSA entry, the sensor needs to retrieve the gMSA's password from Active Directory. This can be done either by assigning to each of the sensors or by using a group.

- In a single-forest, single-domain deployment, if you aren't planning to install the sensor on any AD FS servers, you can use the built-in **Domain Controllers** security group.

- In a forest with multiple domains, when using a single DSA account, it's recommended to create a universal group and add each of the domain controllers (and AD FS servers) to the universal group.

  >[!NOTE]
  >If you add a computer account to the universal group after the computer has received it’s Kerberos ticket, it will not be able to retrieve the gMSA’s password, until it requests a new Kerberos ticket. The Kerberos ticket has a list of groups that an entity is part a member of when the ticket is issued. In this case you can:
  >
  > - Wait for new Kerberos ticket to be issued. (Kerberos tickets are normally valid for 10 hours)
  > - Reboot the server, when the server is rebooted, a new Kerberos ticket will be requested with the new group membership.
  > - Purge the existing Kerberos tickets. This will force the domain controller to request a new Kerberos ticket. From an administrator command prompt on the domain controller, run the following command: `klist purge -li 0x3e7`

## Create a gMSA account

In the following steps you'll create a specific group that can retrieve the account's password, create a gMSA account, and then test that the account is ready to use.

Run the following PowerShell commands as an administrator:

```powershell
# Set the variables:
$gMSA_AccountName = 'mdiSvc01'
$gMSA_HostsGroupName = 'mdiSvc01Group'
$gMSA_HostNames = 'DC1', 'DC2', 'DC3', 'DC4', 'DC5', 'DC6', 'ADFS1', 'ADFS2'

# Install the required PowerShell module:
Install-Module ActiveDirectory

# Create the group and add the members
$gMSA_HostsGroup = New-ADGroup -Name $gMSA_HostsGroupName -GroupScope Global -PassThru
$gMSA_HostNames | ForEach-Object { Get-ADComputer -Identity $_ } |
    ForEach-Object { Add-ADGroupMember -Identity $gMSA_HostsGroupName -Members $_ }

# Create the gMSA:
New-ADServiceAccount -Name $gMSA_AccountName -DNSHostName "$gMSA_AccountName.$env:USERDNSDOMAIN" `
-PrincipalsAllowedToRetrieveManagedPassword $gMSA_HostsGroup.Name
```

## Install the gMSA account

To install the gMSA account, run locally (as an administrator) on each of the servers, the following command:

```powershell
# Install the required PowerShell module:
Install-Module ActiveDirectory

# Install the gMSA account
Install-ADServiceAccount -Identity 'mdiSvc01'
```

## How to validate that the domain controller can retrieve the gMSA's password

To validate that the server has the required permissions to retrieve the gMSA's password, run the following PowerShell command:

```powershell
Test-ADServiceAccount -Identity 'mdiSvc01'
```

If it has the permissions, the command will return a **True** message.

>[!NOTE]
>If you get an error message when running Test-ADServiceAccount, either restart the server or run `klist purge -li 0x3e7` and try again.

## Verify that the gMSA account has the required rights (if needed)

The sensor (Azure Advanced Threat Protection Sensor) service runs as **LocalService** and performs impersonation of the DSA account. The impersonation will fail if the **Log on as a service** policy is configured but the permission hasn't been granted to the gMSA account, and you'll receive a health alert: **Directory services user credentials are incorrect**.

If you receive the alert, you should check if the **Log on as a service** policy is configured.

The **Log on as a service** policy can be configured either in a Group Policy setting or in a Local Security Policy.

- To check the Local Policy, run **secpol.msc** and select **Local Policies**. Under **User Rights Assignment**, go to the **Log on as a service** policy setting. If the policy is enabled, add the gMSA account to the list of accounts that can log on as a service.

- To check if the setting is set in Group Policy, run **rsop.msc** and see if the setting **Computer Configuration**  -> **Windows Settings** -> **Security Settings** -> **Local Policies** -> **User Rights Assignment** -> **Log on as a service** is set. If the setting is configured, add the gMSA account to the list of accounts that can log on as a service in the Group Policy Management Editor.

![Log on as a service in GPMC.](media/log-on-as-a-service-gpmc.png)

![Log on as a service properties.](media/log-on-as-a-service.png)

## Configure Directory Service account in Microsoft 365 Defender

To connect your sensors with your Active Directory domains, you'll need to configure Directory Service accounts in Microsoft 365 Defender.

1. In [Microsoft 365 Defender](https://security.microsoft.com/), go to **Settings** and then **Identities**.

    ![Go to Settings, then Identities.](media/settings-identities.png)

1. Select **Directory Service accounts**. You'll see which accounts are associated with which domains.

    ![Directory Service accounts.](media/directory-service-accounts.png)

1. If you select an account, a pane will open with the settings for that account.

    ![Account settings.](media/account-settings.png)

1. To add Directory Service account credentials, select **Add credentials** and fill in the **Account name**, **Domain**, and **Password** of the account you created earlier. You can also choose if it's a **Group managed service account** (gMSA), and if it belongs to a **Single label domain**.

    ![Add credentials.](media/new-directory-service-account.png)

    |Field|Comments|
    |---|---|
    |**Account name** (required)|Enter the read-only AD username. For example: **DefenderForIdentityUser**. You must use a **standard** AD user or gMSA account. **Don't** use the UPN format for your username. When using a gMSA, the user string should end with the '$' sign. For example: mdisvc$<br />**NOTE:** We recommend that you avoid using accounts assigned to specific users.|
    |**Password** (required for standard AD user accounts)|For AD user accounts only, enter the password for the read-only user. For example: *Pencil1*.|
    |**Group managed service account** (required for gMSA accounts)|For gMSA accounts only, select **Group managed service account**.|
    |**Domain** (required)|Enter the domain for the read-only user. For example: **contoso.com**. It's important that you enter the complete FQDN of the domain where the user is located. For example, if the user's account is in domain corp.contoso.com, you need to enter `corp.contoso.com` not contoso.com. For information on **Single Label Domains**, see [Microsoft support for Single Label Domains](/troubleshoot/windows-server/networking/single-label-domains-support-policy).|

1. Select **Save**.

> [!NOTE]
> You can use this same procedure to change the password for standard Active Directory user accounts. There is no password set for gMSA accounts.

## Troubleshooting

- [Sensor failed to retrieve the gMSA credentials](troubleshooting-known-issues.md#sensor-failed-to-retrieve-group-managed-service-account-gmsa-credentials)

## Next steps

> [!div class="step-by-step"]
> [« Configure Windows Event collection](configure-windows-event-collection.md)
> [Role groups »](role-groups.md)
