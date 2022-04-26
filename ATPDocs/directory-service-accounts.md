---
title: Directory Service Account recommendations
description: Learn how to configure the Directory Service Account (DSA) to work with Microsoft Defender for Identity.
ms.date: 12/22/2021
ms.topic: how-to
---

# Microsoft Defender for Identity Directory Service Account recommendations

## Introduction

The Directory Services Account (DSA) in Defender for Identity is used by the sensor to perform the following functions:

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
| gMSA                  | <li>    More secure deployment since Active Directory manages the creation and rotation of the account's password like a computer account's password.  <li> You can control how often the account's password is changed. | <li> Requires additional setup  steps. <li> Doesn't support cross-forest authentication  |
| Regular user  account | <li> Supports all operating system versions  the sensor supports.  <li> Easy to create and start working with.  <li> Easy to configure read  permissions between trusted forests. | <li> Less secure since it  requires the creation and management of passwords.   <li> Can lead to downtime if the password expires and password isn't updated (both at the user and DSA configuration). |

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

When there are two or more DSA entries, the sensor will try DSA entries in the following order:

1. Match between the DNS domain name of the target domain (emea.contoso.com) and the domain of DSA gMSA entry (emea.consoso.com).
2. Match between the DNS domain name of the target domain (emea.contoso.com) and the domain of DSA regular entry (emea.consoso.com).
3. Match in the root DNS name of the target domain (emea.constoso.com) and the domain name of DSA gMSA entry (contoso.com)
4. Match in the root DNS name of the target domain (emea.constoso.com) and the domain name of DSA regular entry (contoso.com)
5. Look for a "sibling domain" - target domain name emea.consoto.com and DSA gMSA entry domain name, apac.contoso.com.
6. Look for a "sibling domain" - target domain name emea.consoto.com and DSA regular entry domain name, apac.contoso.com.
7. Round robin all other DSA gMSA entries
8. Round robin all other DSA regular entries


>[!NOTE]
>
> - In a forest with a single DNS name space it is recommeded to create the DSA entry in root domain. You must give this account read permissions to all of the sub domains.
>- In a forest with more than one name space tt is recommended to create the DSA entry in the root domain of each name space.

>[!IMPORTANT]
>If a sensor isn't able to successfully authenticate via LDAP to the Active Directory domain at startup using any of the configured DSA accounts, the sensor won't enter a running state and a health alert will be created. For more information, see [Defender for Identity health alerts](health-alerts.md).

## How to create a gMSA account for use with Defender for Identity

The following steps can be followed to create a gMSA account to be used as the DSA entry for Defender for Identity. This doesn't provide full guidance on gMSA accounts. For additional information, review [Getting started with Group Managed Service Accounts](/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts).

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

The sensor (Azure Advanced Threat Protection Sensor) service runs as **LocalService** and performs impersonation of the DSA account. The impersonation will fail if the **Log on as a service** policy is configured but the permission hasn't been granted to the gMSA account, and you will receive a health alert: **Directory services user credentials are incorrect**.

If you receive the alert, you should check if the **Log on as a service** policy is configured.

The **Log on as a service** policy can be configured either in a Group Policy setting or in a Local Security Policy.

- To check the Local Policy, run **secpol.msc** and select **Local Policies**. Under **User Rights Assignment**, go to the **Log on as a service** policy setting. If the policy is enabled, add the gMSA account to the list of accounts that can log on as a service.

- To check if the setting is set in Group Policy, run **rsop.msc** and see if the setting **Computer Configuration**  -> **Windows Settings** -> **Security Settings** -> **Local Policies** -> **User Rights Assignment** -> **Log on as a service** is set. If the setting is configured, add the gMSA account to the list of accounts that can log on as a service in the Group Policy Management Editor.

![Log on as a service in GPMC.](media/log-on-as-a-service-gpmc.png)

![Log on as a service properties.](media/log-on-as-a-service.png)

## See also

- [Connect to your Active Directory Forest](install-step2.md)
- [Sensor failed to retrieve the gMSA credentials](troubleshooting-known-issues.md#sensor-failed-to-retrieve-group-managed-service-account-gmsa-credentials)
