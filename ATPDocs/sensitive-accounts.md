---
# required metadata

title: Tag sensitive accounts with Azure ATP | Microsoft Docs
description: Describes how to tag sensitive accounts using Azure Advanced Threat Protection (ATP) 
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 10/04/2018
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 43e57f87-ca85-4922-8ed0-9830139fe7cb

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---



# Working with sensitive accounts

## Sensitive groups

The following list of groups are considered Sensitive by Azure ATP. Any entity that is a member of these groups is considered sensitive:

- Administrators
- Power Users
- Account Operators
- Server Operators
- Print Operators
- Backup Operators
- Replicators
- Network Configuration Operators 
- Incoming Forest Trust Builders
- Domain Admins
- Domain Controllers
- Group Policy Creator Owners 
- read-only Domain Controllers 
- Enterprise Read-only Domain Controllers 
- Schema Admins 
- Enterprise Admins

  > [!NOTE]
  > Until September, 2018, Remote Desktop Users were also automatically considered Sensitive by Azure ATP. Remote Desktop entities or groups added after this date are no longer automatically marked as sensitive while Remote Desktop entities or groups added before this date may remain marked as Sensitive. This Sensitive setting can now be changed manually.  

## Tagging sensitive accounts

In addition to these groups, you can manually tag groups or accounts as sensitive to enhance detections. This is important because Some Azure ATP detections, such as sensitive group modification detection and lateral movement path, rely on which groups and accounts are considered sensitive. You can manually tag other users or groups as sensitive, such as board members, company executives, director of sales, etc., and Azure ATP considers them sensitive.

1.  In the Azure ATP portal, click the **Configuration** cog in the menu bar.

2.  Under **Detection** click **Entity tags**.

    ![Azure ATP entity tags](media/entity-tags.png)

3.  In the **Sensitive** section, type the name of the **Sensitive accounts** and **Sensitive groups** and then click **+** sign to add them.

    ![Azure ATP sensitive account sample](media/sensitive-account-sample.png)

4. Click **Save**.

    
## See also

- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
