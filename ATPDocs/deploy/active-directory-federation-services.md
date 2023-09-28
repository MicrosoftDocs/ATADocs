---
title: Configuring sensors for AD FS and AD CS | Microsoft Defender for Identity
description: Learn how to configure Microsoft Defender for Identity on Active Directory Federation Services (AD FS) 
ms.date: 01/30/2023
ms.topic: how-to
---

# Configuring sensors for AD FS and AD CS

Install Defender for Identity sensors on Active Directory Federation Services (AD FS) and Active Directory Certificate Services (AD CS) servers to protect them from on-premises attacks.

This article describes the steps required when installing Defender for Identity sensors on AD FS or AD CS servers.

> [!NOTE]
> For AD FS environments, the Defender for Identity sensor is supported only on the federation servers, and isn't required on the Web Application Proxy (WAP) servers. For AD CS environments, you don't need to install the sensor on any AD CS servers that are offline.
>

## Prerequisites

Prerequisites for installing Defender for Identity sensors on AD FS or AD CS servers are the same as for installing sensors on domain controllers. For more information, see [Microsoft Defender for Identity prerequisites](prerequisites.md).

## Configure Verbose logging for AD FS event logs

Sensors running on AD FS servers must have the auditing level set to **Verbose** for relevant events. For example, use the following command to configure the auditing level to **Verbose**::

```powershell
Set-AdfsProperties -AuditLevel Verbose
```
For more information, see [Event auditing information for AD FS](/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-logging#event-auditing-information-for-ad-fs-on-windows-server-2016). 

For more information, see:

- [Supported AD FS events](event-collection-overview.md#supported-ad-fs-events)
- [Enable auditing on an AD FS object](configure-windows-event-collection.md#enable-auditing-on-an-ad-fs-object)

## Configure event collection for AD FS and AD CS logs

If you're working with AD FS / AD CS servers, make sure that you've configured auditing as needed. For more information, see:

- **AD FS**:

    - [Supported Active Directory Federation Services (AD FS) events](event-collection-overview.md#supported-active-directory-federation-services-ad-fs-events)
    - [Enable auditing on an Active Directory Federation Services (AD FS) object](configure-windows-event-collection.md#enable-auditing-on-an-active-directory-federation-services-ad-fs-object)

- **AD CS**: 

    - [Supported Active Directory Certificate Services (AD CS) events](event-collection-overview.md#supported-active-directory-certificate-services-ad-cs-events)
    - [Configure auditing for Active Directory Certificate Services (AD CS)](configure-windows-event-collection.md#configure-auditing-for-active-directory-certificate-services-ad-cs)

## Configure read permissions for the AD FS database

For sensors running on AD FS servers to have access to the AD FS database, you need to grant read (*db_datareader*) permissions for the relevant [Directory Services Account](directory-service-accounts.md) configured.

If you have more than one AD FS server, make sure to grant this permission across all of them since database permissions are not replicated across servers.

> [!NOTE]
> If the AD FS database runs on a dedicated SQL server instead of the local AD FS server, and you're using a group-managed service account (gMSA) as the [Directory Services Account (DSA)](directory-service-accounts.md), make sure that you grant the SQL server the [required permissions](directory-service-accounts.md#grant-permissions-to-retrieve-the-gmsa-accounts-password) to retrieve the gMSA's password. 

### Grant access to the AD FS database

Grant access to the database using SQL Server Management Studio, TSQL, or PowerShell.

For example, the commands listed below might be helpful if you're using the Windows Internal Database (WID) or an external SQL server.

In these sample codes:

- **[DOMAIN1\triservice]** is the directory services user of the workspace
- **AdfsConfigurationV4** is an example of an AD FS database name, and may vary
- **server=\.\pipe\MICROSOFT##WID\tsql\query** - is the connection string to the database if you are using WID

> [!TIP]
> If you don't know your connection string, follow the steps in the [Windows server documentation](/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-sql#to-acquire-the-sql-connection-string).
>

**To grant the sensor access to the AD FS database using TSQL**:

```tsql
USE [master]
CREATE LOGIN [DOMAIN1\triservice] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
USE [AdfsConfigurationV4]
CREATE USER [DOMAIN1\triservice] FOR LOGIN [DOMAIN1\triservice]
ALTER ROLE [db_datareader] ADD MEMBER [DOMAIN1\triservice]
GRANT CONNECT TO [DOMAIN1\triservice]
GRANT SELECT TO [DOMAIN1\triservice]
GO
```

**To grant the sensor access to the AD FS database using PowerShell**:

```powershell
$ConnectionString = 'server=\\.\pipe\MICROSOFT##WID\tsql\querydatabase=AdfsConfigurationV4;trusted_connection=true;'
$SQLConnection= New-Object System.Data.SQLClient.SQLConnection($ConnectionString)
$SQLConnection.Open()
$SQLCommand = $SQLConnection.CreateCommand()
$SQLCommand.CommandText = @"
USE [master]; 
CREATE LOGIN [DOMAIN1\triservice] FROM WINDOWS WITH DEFAULT_DATABASE=[master];
USE [AdfsConfigurationV4]; 
CREATE USER [DOMAIN1\triservice] FOR LOGIN [DOMAIN1\triservice]; 
ALTER ROLE [db_datareader] ADD MEMBER [DOMAIN1\triservice]; 
GRANT CONNECT TO [DOMAIN1\triservice]; 
GRANT SELECT TO [DOMAIN1\triservice];
"@
$SqlDataReader = $SQLCommand.ExecuteReader()
$SQLConnection.Close()
```

## SQL server permissions for AD FS servers

For sensor installations on AD FS servers, configure the SQL server to allow *Directory service* account with the following permissions to the **AdfsConfiguration** database:

- *connect*
- *log in*
- *read*
- *select*

## Validate successful deployment on an AD FS / AD CS server

To validate that the Defender for Identity sensor has been successfully deployed on an AD FS server:

1. Check that the **Azure Advanced Threat Protection sensor** service is running. After you save the Defender for Identity sensor settings, it might take a few seconds for the service to start.

1. If the service doesn't start, review the `Microsoft.Tri.sensor-Errors.log` file, located by default at: `%programfiles%\Azure Advanced Threat Protection sensor\Version X\Logs`

1. Use AD FS or AD CS to authenticate a user to any application, and then verify that the authentication was observed by Defender for Identity. 

   For example, select **Hunting** > **Advanced Hunting**. In the **Query** pane, enter and run one of the following queries:

   **For AD FS**: 

   ```query
   IdentityLogonEvents | where Protocol contains 'Adfs'
   ```

<!--need better code and results or remove this-->
   **For AD CS**:

   ```query
   IdentityDirectoryEvents | where Protocol == "Adcs"
   ```

   The results pane should include a list of events with a **LogonType** of **Logon with ADFS authentication** or **Logon with ADCS authentication**.

   Select a specific row to see additional details in the **Inspect Record** left pane. For example:

   :::image type="content" source="../media/adfs-logon-advanced-hunting.png" alt-text="Screenshot of the results of an AD FS logon advanced hunting query." lightbox="../media/adfs-logon-advanced-hunting.png":::

<!--validate this for adcs-->

## Post-installation steps for AD FS / AD CS servers (Optional)

Installing the sensor on an AD FS / AD CS server automatically selects the closest domain controller. Use the following steps to check or modify the selected domain controller.

1. In [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings**  > **Identities** > **Sensors** to view all of your Defender for Identity sensors.

1. Locate and select the sensor you installed on an AD FS / AD CS server.

1. In the pane that opens, in the **Domain Controller (FQDN)** field, enter the FQDN of the resolver domain controllers. Select **+ Add** to add the FQDN, and then select **Save**.   For example:

    ![Defender for Identity configure AD FS sensor resolver](../media/sensor-config-adfs-resolver.png)

Initializing the sensor may take a couple of minutes, at which time the AD FS / AD CS sensor service status should change from **stopped** to **running**.

## Related content

For more information, see:

- [Microsoft Defender for Identity prerequisites](prerequisites.md)
- [Install the Microsoft Defender for Identity sensor](install-sensor.md)
- [Configure a Directory Service account for Microsoft Defender for Identity](directory-service-accounts.md)
