---
# required metadata

title: Understanding the Azure Advanced Threat Protection workspace portal | Microsoft Docs
description: Describes how to log into the Azure ATP workspace portal and the components of the workspace portal
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/14/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 4ba46d60-3a74-480e-8f0f-9a082d62f343

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*



# Working with the Azure ATP workspace portal

Use the Azure ATP workspace portal to monitor and respond to suspicious activity detected by ATP.

Typing the `?` key provides keyboard shortcuts for Azure ATP workspace portal accessibility. 

## Enabling access to the Azure ATP workspace portal
To successfully log in to the Azure ATP workspace portal, you have to log in with a user who was assigned the proper Azure Active Directory security group to access the Azure ATP workspace portal. 
For more information about role-based access control (RBAC) in Azure ATP, see [Working with Azure ATP role groups](atp-role-groups.md).

## Logging into the Azure ATP workspace portal

1. You can enter the workspace portal either by logging in to the workspace management portal [https://portal.atp.azure.com](https://portal.atp.azure.com) and then selecting the relevant workspace, or browsing to the workspace URL: [https://*workspacename*.atp.azure.com](https://*workspacename*.atp.azure.com).


2.  If the computer on which the Azure ATP cloud service is installed and the computer from which you are trying to access the Azure ATP workspace portal are both domain joined, Azure ATP supports single sign-on integrated with Windows authentication - if you've already logged on to your computer, Azure ATP uses that token to log you into the Azure ATP workspace portal. You can also log in using a smartcard. Your permissions in Azure ATP correspond with your [administrator role](atp-role-groups.md).

 > [!NOTE]
 > Make sure to log on to the computer from which you want to access the Azure ATP workspace portal using your Azure ATP admin username and password. Alternatively, you can run your browser as a different user or log out of Windows and log on with your Azure ATP admin user. To prompt the Azure ATP workspace portal to ask for credentials, access the workspace portal using an IP address and you are prompted to enter credentials.

3. To log in using SSO, make sure the Azure ATP workspace portal site is defined as a local intranet site in your browser and that you access it using a shortname or a localhost.

> [!NOTE]
> In addition to logging each suspicious activity and health alert, every configuration change you make in the Azure ATP workspace portal is audited in the Windows Event Log on the Azure ATP cloud service machine, under **Applications and services log** and then **Microsoft ATP**. Each login to the Azure ATP workspace portal is audited as well.<br></br>  Configuration affecting the Azure ATP Standalone Sensor is also logged in the Windows Event Log of the Azure ATP Standalone Sensor machine. 



## The Azure ATP workspace portal

The Azure ATP workspace portal provides you a quick view of all suspicious activities in chronological order. It enables you to drill into details of any activity and perform actions based on those activities. The workspace portal also displays alerts and notifications to highlight problems with the Azure ATP network or new activities that are deemed suspicious.

These are the key elements of the Azure ATP workspace portal.


### Attack time line

This is the default landing page you are taken to when you log in to the Azure ATP workspace portal. By default, all open suspicious activities are shown on the attack time line. You can filter the attack time line to show All, Open, Dismissed or Suppressed suspicious activities. You can also see the severity assigned to each activity.

![Azure ATP attack timeline image](media/atp-sa-timeline.png)

For more information, see [Working with suspicious activities](working-with-suspicious-activities.md).

### What's new

After a new version of Azure ATP is released, the **What's new** window appears in the top right to let you know what was added in the latest version. It also provides you with a link to the version download.

### Filtering panel

You can filter which suspicious activities are displayed in the attack time line or displayed in the entity profile suspicious activities tab based on Status and Severity.

### Search bar

In the top menu, you can find a search bar. You can search for a specific user, computer, or groups in Azure ATP. To give it a try, just start typing.

![Azure ATP workspace portal search image](media/atp-workspace-portal-search.png)

### Health center

The Health center provides you with alerts when something isn't working properly in your Azure ATP workspace.

![Azure ATP health center image](media/atp-health-issue.png)

Any time your system encounters a problem, such as a connectivity error or a disconnected Azure ATP Standalone Sensor, the Health Center icon lets you know by displaying a red dot. 

![Azure ATP health center red dot image](media/atp-health-bar.png)

### Sensitive groups

For information on sensitive groups in ATP, see [Working with sensitive groups](tag-sensitive-accounts.md).

### Mini profile

If you hover your mouse over an entity, anywhere in the workspace portal where there is a single entity presented, such as a user, or a computer, a mini profile automatically opens displaying the following information if available:

![Azure ATP mini profile image](media/atp-mini-profile.png)

-   Name

-   Picture

-   Email

-   Telephone

-   Number of suspicious activities by severity



## See Also

- [Creating Azure ATP workspaces](atp-workspaces.md)