---
title: Deploy Defender for Identity with Microsoft 365 Defender
description: Learn how to deploy Microsoft Defender for Identity using Microsoft 365 Defender
ms.date: 03/24/2022
ms.topic: how-to
---

# Deploy Microsoft Defender for Identity with Microsoft 365 Defender

The deployment of Microsoft Defender for Identity with Microsoft 365 Defender has three phases - preparation, installation, and management.

This article will outline the steps in each phase.

## Start using Microsoft 365 Defender

To begin the deployment of Defender for Identity, sign in to the [Microsoft 365 Defender portal](https://security.microsoft.com). From the navigation menu, select any item, such as **Incidents & alerts**, **Hunting**, **Action center**, or **Threat analytics** to initiate the onboarding process.

You'll then be given the option to deploy supported services, including Microsoft Defender for Identity. When you go to the Defender for Identity settings, the required cloud components will be auto-provisioned.

For more information about these steps, see the following articles:

- [Get started with Microsoft 365 Defender](/microsoft-365/security/defender/get-started)
- [Turn on Microsoft 365 Defender](/microsoft-365/security/defender/m365d-enable)
- [Deploy supported services](/microsoft-365/security/defender/deploy-supported-services)
- [Frequently asked questions when turning on Microsoft 365 Defender](/microsoft-365/security/defender/m365d-enable-faq)

> [!IMPORTANT]
> Currently, [!INCLUDE [Product short](includes/product-short.md)] data centers are deployed in Europe, UK, North America/Central America/Caribbean and Asia. Your instance is created automatically in the data center that is geographically closest to your Azure Active Directory (Azure AD). Once created, [!INCLUDE [Product short](includes/product-short.md)] instances aren't movable.

## Preparation

1. Review the [Defender for Identity prerequisites](prerequisites.md).
1. [Plan capacity for Defender for Identity](capacity-planning.md).
1. [Configure Windows Event collection](configure-windows-event-collection.md).
1. Configure your [Directory Service accounts](directory-service-accounts.md).
1. Add users to [Defender for Identity role groups](role-groups.md).
1. [Configure endpoint proxy and Internet connectivity settings](configure-proxy.md).
1. [Configure Defender for Identity to make remote calls to SAM](remote-calls-sam.md).

## Installation

1. [Deploy Microsoft Defender for Identity with Microsoft 365 Defender](deploy-defender-identity.md).
1. [Install the Microsoft Defender for Identity sensors](install-sensor.md) on your domain controllers or AD FS servers.
1. [Configure Microsoft Defender for Identity sensor settings](configure-sensor-settings.md) to start receiving data.
1. Create [Defender for Identity action accounts](manage-action-accounts.md).

## Management

1. Review and configure the [sensor settings](settings-overview.md).
1. [Understand user and computer entity profiles](understand-entities.md).
1. Review the [Defender for Identity Security Alerts](alerts-overview.md).
1. Review [Defender for Identity's security posture assessments](security-assessment.md) and take action to improve any vulnerabilities.

## Next steps

- [Install the Microsoft Defender for Identity sensor](install-sensor.md)
