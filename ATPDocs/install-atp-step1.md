---
# required metadata

title: Install Azure Advanced Threat Protection | Microsoft Docs
description: First step to install Azure ATP involves creating the instance for your Azure ATP deployment.
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 10/4/2018
ms.topic: conceptual
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 15ee7d0b-9a0c-46b9-bc71-98d0b4619ed0

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*


# Creating your Azure ATP instance in the portal - Step 1

> [!div class="step-by-step"]
> [Step 2 »](install-atp-step2.md)

This installation procedure provides instructions for creating and managing your Azure ATP instance or workspace. For information on Azure ATP architecture, see [Azure ATP architecture](atp-architecture.md).

In Azure ATP, you'll have a single instance or workspace enabling you to manage multiple forests from a single pane of glass. 

> [!NOTE]
> Currently, Azure ATP data centers are deployed in Europe, North America/Central America/Caribbean and Asia.

## Step 1. Enter the Azure ATP portal

After you verified that your network meets the requirements of the sensor, you can proceed with the creation of the Azure ATP workspace.

> [!NOTE]
>In order to access the management portal, you need to be a global administrator or security administrator on that tenant.


1.  Enter [the Azure ATP portal](https://portal.atp.azure.com).

2.  Log in with your Azure Active Directory user account.

## Step 2. Create your workspace

1. Click **Create workspace**.

2. In the **Create new workspace** dialog, name your workspace, and select a **Geolocation** for your data center. Your workspace is **Primary** by default. 
 > [!NOTE]
 > After you select a Geolocation, you cannot modify it.
    ![Azure ATP workspace](media/create-workspace.png)

3. You can click the **Manage Azure ATP user roles** link to directly access the [Azure Active Directory admin center](https://docs.microsoft.com/azure/active-directory/active-directory-assign-admin-roles-azure-portal) and manage your role groups.

 > [!NOTE]
 > To successfully log in to Azure ATP, you have to log in with a user who was assigned the proper Azure ATP role to access the Azure ATP portal. For more information about role-based access control (RBAC) in Azure ATP, see [Working with Azure ATP role groups](atp-role-groups.md).

4. Click on the name of your workspace to access the Azure ATP portal.

    ![Azure ATP workspaces](media/atp-workspaces.png)

- Only the Primary workspace can be edited. If you want to delete your primary workspace, you must first turn off integrations before it is able to be deleted.

- Data retention – previously deleted workspaces do not appear in the UI. For more information on Azure ATP data retention, see [Aure ATP data security and privacy](atp-privacy-compliance.md).

> [!div class="step-by-step"]
> [« Pre-install](atp-prerequisites.md)
> [Step 2 »](install-atp-step2.md)



## See Also
- [Azure ATP sizing tool](http://aka.ms/aatpsizingtool)
- [Configure event collection](configure-event-collection.md)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
