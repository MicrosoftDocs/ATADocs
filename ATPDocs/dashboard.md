---
title: Microsoft Defender for Identity dashboard
description: This article describes how to work with the identity threat detection and response (ITDR) dashboard in Microsoft 365 Defender.
ms.date: 12/27/2023
ms.topic: how-to
---

# Work with Defender for Identity's ITDR dashboard

The Microsoft Defender for Identity **Dashboard** page shows data to help you better analyze your security posture, understand how well you're protected, identify vulnerabilities, and perform recommended actions.

Use the **Dashboard** page to view critical insights and real-time data about identity threat detection and response (ITDR). View graphs and widgets that showcase important information related to unauthorized access, account compromise, insider threats, and abnormal activities, and then proactively monitor and manage potential identity-related security risks.

## Prerequisites

To access this new dashboard, you need:

- A  Microsoft Defender for Identity license.
- 
- A user role with at least the [Security Reader](/azure/active-directory/roles/permissions-reference#security-reader) permissions

To view a comprehensive list of recommendations and select the recommended action links, you need the [Global Administrator](/azure/active-directory/roles/permissions-reference#global-administrator) role.

## Access the dashboard

To access the dashboard, sign into Microsoft 365 Defender and select **Identities > Dashboard**. <!--For example TBD screenshot-->.

### View top action cards

The following cards at the top of the page are intended to help you configure your environment, increase your security posture, and Secure Score:

- **Sensitive accounts identified in a lateral movement path**. Sensitive accounts with risky lateral movement paths are windows of opportunity for attackers and can expose risks.

    We recommend that you take action on any sensitive accounts found with risky lateral movement paths to minimize your risk. For more information, see [Understand and investigate Lateral Movement Paths (LMPs) with Microsoft Defender for Identity](understand-lateral-movement-paths.md).

- **Dormant users to be removed from sensitive groups in Active Directory**. Accounts become dormant if they're left unused for at least 180 days. An easy and quiet path deep into your organization is through inactive accounts that are a part of sensitive groups, therefore we recommend removing those users from sensitive groups. For more information, see [Security assessment: Riskiest lateral movement paths (LMP)](security-assessment-riskiest-lmp.md).

For each card, select **View users** to see a list of relevant users for each item. <!--based on ppt, not staging-->

## Deployment configuration cards

The following cards provide tools for improving your security posture with deployment configurations:

|Name  |Description |
|---------|---------|
|**ITDR deployment health**     |  Lists any sensor deployment progress, any health alerts, and license availability.     |
|**Identity secure score** | The score shown represents your organization's security posture with a focus on the *identity* score, reflecting the collective security state of your identities. The score is automatically updated in real-time to reflect the data shown in graphs and recommended actions. Microsoft Secure Score updates daily with system data with new points for each recommended action take. For more information, see [Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score). |
|**Domains with unsecured configuration**     |  Lists Active Directory domains that have unsecured configuration settings. <br><br>Active Directory domains hold many security-related configurations, which, when misconfigured, can make organizations more susceptible to cyber-attacks. Make sure to configure your domains in accordance with security best practices to decrease the likelihood of identity compromise.  <br><br>For more information, see [Security assessment: Unsecure domain configurations](security-assessment-unsecure-domain-configurations.md)       |

## Identity insights

The following cards provide insights about identity entities in your organization:

|Name  |Description |
|---------|---------|
| **Identity related incidents** | Lists alerts from both Defender for Identity and [Microsoft Entra ID Protection](/azure/active-directory/identity-protection/overview-identity-protection), and any corresponding, relevant incidents from the last 30 days. |
| **Users with threat detection** | <!--TBD-->|

## Identity detections and remediations

The following cards provide insights about identity detections and remediations in your organization:

- **Top identities to investigate**. Select a user to drill down for more details and start investigating.
- **Threat categories of identity-related alerts** 
- **Identity-related open incidents**.

### Next steps

For more information, see [Microsoft Defender for Identity in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi?bc=/defender-for-identity/breadcrumb/toc.json&toc=/defender-for-identity/TOC.json).