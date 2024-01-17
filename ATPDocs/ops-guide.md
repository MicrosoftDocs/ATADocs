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

1. When the incident is remediated, resolve it to resolve all linked and related active alerts and set a classification.

### Investigate users with a high investigation score

<!--TBD-->

### Review the ITDR dashboard

**Where**: In Microsoft Defender XDR, under select **Identities** > **Dashboard**.

**Persona**: SOC analysts, security administrators, identity and access management administrators

For more information, see [Work with Defender for Identity's ITDR dashboard (Preview)](dashboard.md).

### Review Microsoft service health

**Where**: Check the following locations:

- In the Microsoft 365 admin center, select **Health > Service health**
- [Microsoft 365 Service health status](https://status.office365.com/)
- X: https://twitter.com/MSFT365status

**Persona**: 

If you're experiencing issues with a cloud service, we recommend checking service health updates to determine whether it's a known issue, with a resolution in progress, before you call support or spend time troubleshooting.

### Review Defender for Identity health issues

**Where**: In Microsoft Defender XDR, select **Identities > Health issues**.

**Persona**: Security administrators, Active Directory administrators

We recommend checking the **Health Issues** page regularly to check for any problems in your Defender for Identity deployment, such as connectivity or sensor issues.

For more information, see [Microsoft Defender for Identity health issues](health-alerts.md).

## Weekly activities

### Review Secure score recommendations

**Where**: In Microsoft Defender XDR, select **Secure score**.

**Persona**: Security and Compliance administrators, SOC analysts

Microsoft Secure score recommendations are based on the Microsoft security recommendations that are most relevant to your organization. Secure score recommendations for Defender for Identity include monitoring for on-premises identities and identity infrastructure weak points.

To view Secure Score recommendations per product, in Microsoft Defender XDR, select **Secure score > Recommended actions**, and group the list by **Product**.

### Review and respond to emerging threats

**Where**: In Microsoft Defender XDR, select **Hunting > Advanced hunting**

**Persona**:

We recommend that you configure custom detections in Microsoft Defender XDR to monitor and respond to various events and system states, such as suspected breach activity and misconfigured endpoints.

Custom detection rules can automatically trigger both alerts and response actions, and are based on advanced hunting queries. Run your custom detection rules regularly to generate alerts and take relevant response actions.

For more information, see:

- [Custom detections overview](/microsoft-365/security/defender/custom-detections-overview)
- [Create and manage custom detections rules](/microsoft-365/security/defender/custom-detection-rules)

## Monthly activities

### Review tuned alerts and adjust tuning if needed

**Where**: In Microsoft Defender XDR, select **Hunting > Advanced hunting**

**Persona**:

Microsoft Defender XDR allows you to *tune* alerts, helping you reduce the number of false positives you need to triage. Tuning alerts hides or resolves alerts automatically based on your configurations and rule conditions.

We recommend reviewing your tuning configurations regularly to make sure that they're still relevant and effective. 

For more information, see [Investigate Defender for Identity security alerts in Microsoft Defender XDR](manage-security-alerts.md).

### Track new changes in Microsoft Defender XDR

**Where**:

- In the Microsoft 365 admin center, select **Health > Message center**. For more information, see [Track new and changed features in the Microsoft 365 Message center](/microsoft-365/admin/manage/message-center).

- The [Microsoft Defender XDR monthly news](https://techcommunity.microsoft.com/t5/microsoft-defender-xdr-blog/bg-p/MicrosoftThreatProtectionBlog/label-name/Defender%20News).

**Persona**: Security administrators


## Ad-hoc activities

### Review server setup process to include sensors

### Proactively hunt

**Where**: In Microsoft Defender XDR, select **Hunting > Advanced hunting**.

**Persona**:

Use Microsoft Defender XDR advanced hunting to proactively explore through the last 30 days of raw data, including Defender for Identity data correlated with data streaming from other Microsoft Defender XDR services. 

Inspect events in your network to locate threat indicators and entities, including both known and potential threats.

We recommend that beginners use guided advanced hunting, which provides a query builder. If you're comfortable using Kusto Query Language (KQL), build queries from scratch as needed for your investigations.

For more information, see [Proactively hunt for threats with advanced hunting in Microsoft Defender XDR](/microsoft-365/security/defender/advanced-hunting-overview).

### Configure tuning rules for false positive alerts

**Where**: In Microsoft Defender XDR, select **Hunting > Advanced hunting**

**Persona**:

Microsoft Defender XDR allows you to *tune* alerts, helping you reduce the number of false positives you need to triage. Tuning alerts hides or resolves alerts automatically based on your configurations and rule conditions.

We recommend creating new rules as needed as your network grows to make sure that your alert tuning remains relevant and effective.

For more information, see [Investigate Defender for Identity security alerts in Microsoft Defender XDR](manage-security-alerts.md).

## Related information

For more information, see the Microsoft Defender XDR [Security operations overview](/security/operations/overview).