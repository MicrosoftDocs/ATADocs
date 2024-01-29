---
title: Ad-hoc operational guide - Microsoft Defender for Identity
description: Learn about the Microsoft Defender for Identity activities that we recommend for your team on an ad-hoc basis.
ms.date: 01/29/2024
ms.topic: how-to
---

# Microsoft Defender for Identity operational guide

This article reviews the Microsoft Defender for Identity activities we recommend for your team on an ad-hoc basis.

## Review server setup process to include sensors

## Proactively hunt

**Where**: In Microsoft Defender XDR, select **Hunting > Advanced hunting**.

**Persona**: SOC analysts

Use Microsoft Defender XDR advanced hunting to proactively explore through the last 30 days of raw data, including Defender for Identity data correlated with data streaming from other Microsoft Defender XDR services.

Inspect events in your network to locate threat indicators and entities, including both known and potential threats.

We recommend that beginners use guided advanced hunting, which provides a query builder. If you're comfortable using Kusto Query Language (KQL), build queries from scratch as needed for your investigations.

For more information, see [Proactively hunt for threats with advanced hunting in Microsoft Defender XDR](/microsoft-365/security/defender/advanced-hunting-overview).

## Configure tuning rules for false positive alerts

**Where**: In Microsoft Defender XDR, select **Hunting > Advanced hunting**

**Persona**: Security and compliance administrators, SOC analysts

Microsoft Defender XDR allows you to *tune* alerts, helping you reduce the number of false positives you need to triage. Tuning alerts hides or resolves alerts automatically based on your configurations and rule conditions.

We recommend creating new rules as needed as your network grows to make sure that your alert tuning remains relevant and effective.

For more information, see [Investigate Defender for Identity security alerts in Microsoft Defender XDR](manage-security-alerts.md).

## Related content

For more information, see:

- [Microsoft Defender XDR Security operations overview](/security/operations/overview)
- [Microsoft Defender for Identity operational guide](ops-guide.md)
- [Daily operational guide - Microsoft Defender for Identity](ops-guide-daily.md)
- [Weekly operational guide - Microsoft Defender for Identity](ops-guide-weekly.md)
- [Monthly operational guide - Microsoft Defender for Identity](ops-guide-monthly.md)
