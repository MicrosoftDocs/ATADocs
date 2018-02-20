---
# required metadata

title: Working with multiple Azure ATP workspaces | Microsoft Docs
description: Describes how to work with and create Azure ATP workspaces
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/20/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
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

*Applies to: Azure Advanced Threat Protection*



# Working with the Azure ATP workspaces

In Azure ATP you have the ability to manage and monitor multiple workspaces. This is especially helpful if you want to create a demo workspace and a test workspace in which you can POC Azure ATP before rolling it out to your whole organization. This is also needed to support deployments with multiple forests. A single workspace can only monitor multiple domains from a single forest.

## Create a workspace

1. Log into [portal.atp.azure.com](https://portal.atp.azure.com).

2. Click **Create workspace**.

3. In the **Create new workspace** dialog, name your workspace, decide whether it's your primary workspace or not, and select a **Geolocation** for your data center.
 > [!NOTE]
 > After you select a Geolocation, you cannot modify it.
 
    ![Azure ATP create workspace](media/create-workspace.png)

4. Click on the name of the new workspace access the Azure ATP workspace portal for that workspace.

    ![Azure ATP workspaces](media/atp-workspaces.png)

5. You can click the **Manage Azure ATP user roles** link to directly access the [Azure Active Directory admin center](https://docs.microsoft.com/azure/active-directory/active-directory-assign-admin-roles-azure-portal) and manage your role groups.

To successfully log in to Azure ATP, you have to log in with a user who was assigned the proper Azure ATP role to access the Azure ATP workspace portal. 
For more information about role-based access control (RBAC) in Azure ATP, see [Working with Azure ATP role groups](atp-role-groups.md).

Only the Primary workspace can be edited (Primary on-off)
-	Configure integration – on-off
-	Delete – integrated/primary ws can not be deleted. The flow is first turn off the primary/integration and then delete.

Also, worth mentioning data retention – deleted workspaces do not appear in the UI however their data is retained according to Microsft policy for a period of time (I think a year, need to check with Ophir). And add a support link to contact about data retention questions.

## See Also

- [ATP suspicious activity guide](suspicious-activity-guide.md)
- [Working with sensitive accounts](tag-sensitive-accounts.md)