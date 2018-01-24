---
# required metadata

title: Working with multiple ATP workspaces | Microsoft Docs
description: Describes how to work with and create ATP workspaces
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 1/24/2018
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 732a3dff-53a2-4b26-87a0-bf5b62ecc235

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Threat Protection*



# Working with the ATP workspaces

In ATP you have the ability to manage and monitor multiple workspaces. This is especially helpul if you want to create a demo workspace and a test workspace in which you can POC ATP before rolling it out to your whole organization.

## Create a workspace

To successfully log in to ATP, you have to log in with a user who was assigned the proper ATP role to access the ATP Console. 
For more information about role-based access control (RBAC) in ATP, see [Working with ATP role groups](ata-role-groups.md).

1. Log into [portal.atp.azure.com](portal.atp.azure.com).

2. Click **Create workspace**.

3. In the **Create new workspace** dialog, name your workspace, decide whether it's your primary workspace or not, and select a **Geolocation** for your data center.

    ![ATP create workspace](media/create-workspace.png)

4. Click on the name of the new workspace access the ATP console for that workspace.

    ![ATP workspaces](media/atp-workspaces.png)

5. You can click the **Manage Azure ATP user roles** link to directly access the [Azure Active Directory admin center](https://docs.microsoft.com/azure/active-directory/active-directory-assign-admin-roles-azure-portal) and manage your role groups.




## See Also
[Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
