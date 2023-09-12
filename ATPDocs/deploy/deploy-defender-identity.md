---
title: Deploy Microsoft Defender for Identity
description: Learn how to deploy Microsoft Defender for Identity from the Microsoft 365 Defender portal.
ms.date: 08/27/2023
ms.topic: how-to
---

# Deploy Microsoft Defender for Identity with Microsoft 365 Defender

This article provides an overview of the full deployment process for Microsoft Defender for Identity, including steps for preparation, deployment, and extra steps for specific scenarios.

Defender for Identity is a primary component of a [Zero Trust](/security/zero-trust/zero-trust-overview) strategy and your XDR deployment with Microsoft 365 Defender. Defender for Identity uses Active Directory signals to detect sudden account changes like privilege escalation or high-risk lateral movement, and reports on easily exploited identity issues like unconstrained Kerberos delegation, for correction by the security team. <!--should we also mention itdr?-->

For a quick set of deployment highlights, see [Quick installation guide](quick-installation-guide.md).

## Prerequisites

Before you start, make sure that you have access to Microsoft 365 Defender as a Global or Security administrator, and one of the following licenses:

- Enterprise Mobility + Security E5 (EMS E5/A5)
- Microsoft 365 E5 (M365 E5/A5/G5)
- Microsoft 365 E5/A5/G5 Security
- A standalone Defender for Identity license

Acquire your licenses directly via the [Microsoft 365 portal](https://www.microsoft.com/cloud-platform/enterprise-mobility-security-pricing) or use the Cloud Solution Partner (CSP) licensing model.

For more information, see [Licensing and privacy](/defender-for-identity/technical-faq#licensing-and-privacy) and [Microsoft Defender for Identity role groups](role-groups.md).

## Start using Microsoft 365 Defender

This section describes how to start onboarding to Defender for Identity.

1. Sign in to the [Microsoft 365 Defender portal](https://security.microsoft.com). 
1. From the navigation menu, select any item, such as **Incidents & alerts**, **Hunting**, **Action center**, or **Threat analytics** to initiate the onboarding process.

You'll then be given the option to deploy supported services, including Microsoft Defender for Identity. Cloud components required for Defender for Identity are automatically added when you open the Defender for Identity settings page.

For more information, see:

- [Microsoft Defender for Identity in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi?bc=/defender-for-identity/breadcrumb/toc.json&toc=/defender-for-identity/TOC.json)
- [Get started with Microsoft 365 Defender](/microsoft-365/security/defender/get-started)
- [Turn on Microsoft 365 Defender](/microsoft-365/security/defender/m365d-enable)
- [Deploy supported services](/microsoft-365/security/defender/deploy-supported-services)
- [Frequently asked questions when turning on Microsoft 365 Defender](/microsoft-365/security/defender/m365d-enable-faq)

> [!IMPORTANT]
> Currently, Defender for Identity data centers are deployed in Europe, UK, North America/Central America/Caribbean, Australia East, and Asia. Your instance is created automatically in the Azure region closest to the geographical location of your Azure Active Directory tenant. Once created, Defender for Identity instances aren't movable.

## Plan and prepare

Use the following steps to prepare for deploying Defender for Identity:

1. Make sure that you have all [prerequisites](prerequisites.md) required.
1. [Plan your Defender for Identity capacity](capacity-planning.md).
1. [Configure Windows Event collection](configure-windows-event-collection.md).
1. Configure any [role groups](role-groups.md) you want to use for Defender for Identity.
1. [Configure remote calls to SAM](remote-calls-sam.md) as needed.

> [!TIP]
> We recommend running the *Test-MdiReadiness.ps1* script to test and see if your environment has the necessary prerequisites. For more information, see [the script's page](https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness) on GitHub.
>

## Deploy Defender for Identity

After you've prepared your system, use the following steps to deploy Defender for Identity:

1. [Download the Defender for Identity sensor](download-sensor.md).
1. [Configure a proxy](configure-proxy.md) as needed.
1. [Install the Defender for Identity sensor](install-sensor.md).
1. [Manage action accounts](manage-action-accounts.md) as needed.
1. [Configure the Defender for Identity sensor](configure-sensor-settings.md) to start receiving data.

You may have extra, or different steps in your deployment if you're working with any of the following environments:

|Scenario  |Extra steps  |
|---------|---------|
|**Installing your Defender for Identity sensor on AD FS or AD CS servers**     |   [Deploying Microsoft Defender for Identity on AD FS and AD CS servers](active-directory-federation-services.md)      |
|**Installing your Defender for Identity sensor with multiple Active Directory forests**     |  [Multi-forest support](multi-forest.md)       |
| **Create a Directory Service account (DSA) for use with Defender for Identity** | [Configure a Directory Service account](directory-service-accounts.md) |
|**Migrate from Advanced Threat Analytics (ATA)**     |   [Migrate from Advanced Threat Analytics (ATA)](migrate-from-ata-overview.md)      |
| **Installing a standalone Defender for Identity sensor** | 1. [Configure port mirroring](configure-port-mirroring.md). <br>2. [Listen for SIEM events on your Defender for Identity standalone sensor](configure-event-collection.md). <br>3. [Configure Windows event forwarding to your Defender for Identity standalone sensor](configure-event-forwarding.md).|

## Next step

> [!div class="step-by-step"]
> [Defender for Identity prerequisites »](prerequisites.md)

