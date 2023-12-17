---
title: Operational guide - Microsoft Defender for Identity
description: Learn about the Microsoft Defender for Identity activities that we recommend for your team on a daily, weekly, monthly, and ad-hoc basis.
ms.date: 12/17/2023
ms.topic: how-to
---

# Microsoft Defender for Identity operational guide

This article reviews the Microsoft Defender for Identity activities we recommend for your team on a daily, weekly, monthly, and ad-hoc basis.

## Daily activities

### Triage incidents by priority

**Where**: In Microsoft Defender XDR, select **Incidents & alerts**

**Persona**: SOC analysts

**When triaging incidents**:

1. In the incident dashboard, filter for the following items:

    |Filter   |Values  |
    |---------|---------|
    |**Status**     |   New, In progress      |
    |**Severity**     |  High, Medium, Low       |
    |**Service source**     |  Keep all service sources checked. This should list alerts with the most fidelity, with correlation across other Microsoft XDR workloads. Select **Defender for Identity** to view items that come specifically from Defender for Identity.       |

1. Select each incident to review all details. Review all tabs in the incident, the activity log, and advanced hunting.

1. In the incident's **Evidence and response** tab, select each evidence item. Select the options menu > **Investigate** and then select **Activity log** or **Go hunt** as needed.

1. Triage your incidents. For each incident, select **Manage incident** and then select one of the following options:

    - True positive
    - False positive
    - Informational, expected activity

    For true alerts, specify the treat type to help your security team see threat patterns and defend your organization from risk.

1. When you're ready to start your active investigation, assign the incident to a user and update the incident status to **In progress**.

1. When the incident is remediated, resolve it to resolve all linked and related active alerts.

### Investigate users with a high investigation score

<!--TBD-->

### Review Microsoft service health

**Where**: Check the following locations:

- In the Microsoft 365 admin center, select **Health > Service health**
- [Microsoft 365 Service health status](https://status.office365.com/)
- X: https://twitter.com/MSFT365status

If you're experiencing issues with a cloud service, we recommend checking service health updates to determine whether it's a known issue, with a resolution in progress, before you call support or spend time troubleshooting.

## Weekly activities

### Review Secure score recommendations

**Where**: In the Microsoft Defender XDR Portal, select **Secure score**.

**Persona**: Security and Compliance administrators, SOC analysts

Microsoft Secure score recommendations are based on the Microsoft security recommendations that are most relevant to your organization. Secure score recommendations for Defender for Identity include monitoring for on-premises identities and identity infrastructure weak points.

To view Secure Score recommendations per product, in Microsoft Defender XDR, select **Secure score > Recommended actions**, and group the list by **Product**.

### Review emerging threats/respond to emerging threats

<!--TBD-->


## Monthly activities

Review tuned alerts and adjust tuning if needed

### Track new changes in Microsoft Defender XDR

**Where**:

- In the Microsoft 365 admin center, select **Health > Message center**. For more information, see [Track new and changed features in the Microsoft 365 Message center](/microsoft-365/admin/manage/message-center).
- The [Microsoft Defender XDR monthly news](https://techcommunity.microsoft.com/t5/microsoft-defender-xdr-blog/bg-p/MicrosoftThreatProtectionBlog/label-name/Defender%20News).

**Persona**: Security administrators


## Ad-hoc activities

### Review server setup process to include sensors

### Proactively hunt


## Related information

For more information, see the Microsoft Defender XDR [Security operations overview](/security/operations/overview).