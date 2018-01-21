---
# required metadata

title: What's new in ATA version 1.9 | Microsoft Docs
description: Lists what was new in ATA version 1.9 along with known issues
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 1/21/2018
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 51de491c-49ba-4aff-aded-cc133a8ccf0b

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: 
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# What's new in ATA version 1.9

The latest update version of ATA can be [downloaded from the Download Center](https://www.microsoft.com/download/details.aspx?id=55536)  or the full version can be downloaded from the [Eval center](http://www.microsoft.com/evalcenter/evaluate-microsoft-advanced-threat-analytics).

These release notes provide information about updates, new features, bug fixes and known issues in this version of Advanced Threat Analytics.



## New & updated detections

-  **Suspicious service creation** – Attackers attempt to use run suspicious services on your network. ATA now raises an alert when it identifies that someone on a specific computer runs a new service that seems suspicious. This detection is based on events (not network traffic) and is detected on any endpoint in your network forwarding event 7045. For more information see the [Suspicious activity guide](suspicious-activity-guide.md).


## Improved investigation

-  ATA 1.9 includes a new and improved [entity profile](user-profiles.md). The entity profile provides you with a dashboard designed for full deep-dive investigation of users, the resources they accessed and their history. The entity profile also enables you to identify sensitive users who are accessible via lateral movement paths. 

-	ATA 1.9 enables you to [manually tag groups](tag-sensitive-accounts.md) or accounts as sensitive to enhance detections. This tagging impacts many ATA detections, such as sensitive group modification detection and lateral movement path, rely on which groups and accounts are considered sensitive.

## New reports to help you investigate 

-	The [**Passwords exposed in cleartext**](reports.md) enables you to detect when services send account credentials in plain text. This allows you to investigate services and improve your network security level. This report replaces the cleartext suspicious activity alerts.

- The [**Lateral movement paths to sensitive accounts**](reports.md) lists the sensitive accounts that are exposed via lateral movement paths. This enables you to mitigate these paths and harden your network to minimize the attack surface risk. This enables you to prevent lateral movement so that attackers can't move across your network between users and computers until they hit the virtual security jackpot: your sensitive admin account credentials.


## Performance improvements

- The ATA Center infrastructure was improved for performance: the aggregated view of the traffic enables optimization of CPU and packet pipeline, and reuses sockets to the domain controllers to minimize SSL sessions to the DC. 



## Additional changes

- After a new version of ATA is installed, the [**What's new**](working-with-ata-console.md) icon appears in the toolbar to let you know what was changed in the latest version. It also provides you with a link to the in-depth version changelog.


## Removed and deprecated features

- The **Broken trust suspicious activity** alert was removed.
- The passwords exposed in clear text suspicious activity was removed. It was replaced by the [**Passwords exposed in clear text report**](reports.md).

## Known issues

### ATA Gateway on Windows Server Core

**Symptoms**: Upgrading an ATA Gateway to 1.9 on Windows Server 2012R2 Core with .Net framework 4.7 may fail with the error: *Microsoft Advanced Threat Analytics Gateway has stopped working*. 

![Gateway core error](./media/gateway-core-error.png)

On Windows Server 2016 Core you may not see the error, but the process will fail when you try to install, and events 1000 and 1001 (process crash) will be logged in the application Event Log on the server.

**Description**: There is a problem with the .NET framework 4.7 that causes applications that uses WPF technology (such as ATA) to fail to load. [See KB 4034015](https://support.microsoft.com/help/4034015/wpf-window-can-t-be-loaded-after-you-install-the-net-framework-4-7-on) for more information. 

**Workaround**: Uninstall .Net 4.7 [See KB 3186497](https://support.microsoft.com/help/3186497/the-net-framework-4-7-offline-installer-for-windows) to revert the .NET version to .NET 4.6.2 and then update your ATA Gateway to version 1.9. After the upgrade of ATA you can reinstall .NET 4.7.  There will be an update to correct this problem in a future release.

### Lightweight Gateway event log permissions

**Symptoms**: When you upgrade ATA to version 1.9, apps or services that were previously granted permissions to access the Security Event Log may lose the permissions. 

**Description**: In order to make ATA easier to deploy, ATA 1.9 accesses your Security Event Log directly, without necessitating Windows Event Forwarding configuration. At the same time, ATA runs as a low-permission local service to maintain tighter security. In order to provide access for ATA to read the events, the ATA service grants itself permissions to the Security Event Log. When this happens, permissions previously set for other services may be disabled.

**Workaround**: Run the following Windows PowerShell script. This removes the incorrectly added permissions in the registry from ATA, and adds them via a different API. This may restore permissions for other apps. If it does not, they will need to be restored manually. There will be an update to correct this problem in a future release. 

       $ATADaclEntry = "(A;;0x1;;;S-1-5-80-1717699148-1527177629-2874996750-2971184233-2178472682)"
        try {
	    $SecurityDescriptor = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security -Name CustomSD
	    $ATASddl = "O:BAG:SYD:" + $ATADaclEntry 
	    if($SecurityDescriptor.CustomSD -eq $ATASddl) {
		Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security -Name CustomSD
	    }
    }
    catch
    {
    # registry key does not exist
    }

    $EventLogConfiguration = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogConfiguration("Security")
    $EventLogConfiguration.SecurityDescriptor = $EventLogConfiguration.SecurityDescriptor + $ATADaclEntry

### Proxy interference

**Symptoms**: After upgrading to ATA 1.9 the ATA Gateway service may fail to start. In the ATA error log you may see the following exception:
*System.Net.Http.HttpRequestException: An error occurred while sending the request. ---> System.Net.WebException: The remote server returned an error: (407) Proxy Authentication Required.*

**Description**: Starting from ATA 1.9, the ATA Gateway communicates with the ATA Center using the http protocol. If the machine on which you installed the ATA Gateway uses a proxy server to connect to the ATA Center, it can break this communication. 

**Workaround**: Disable the use of a proxy server on the ATA Gateway service account. There will be an update to correct this problem in a future release.

### Report settings reset

**Symptoms**: Any settings that were made to the scheduled reports are cleared when you update to 1.9 update 1.

**Description**: Updating to 1.9 update 1 from 1.9 resets the reports schedule settings.

**Workaround**: Before updating to 1.9 update 1, make a copy of the report settings and reenter them, this can also be done via a script, for more information, see [Export and Import the ATA Configuration](ata-configuration-file.md).


## See Also
[Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)

[Update ATA to version 1.9 - migration guide](ata-update-1.9-migration-guide.md)

