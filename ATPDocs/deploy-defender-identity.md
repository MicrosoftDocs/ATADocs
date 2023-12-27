---
title: Deploy Microsoft Defender for Identity
description: Learn how to deploy Microsoft Defender for Identity from the Microsoft Defender portal.
ms.date: 08/27/2023
ms.topic: how-to
---

# Deploy Microsoft Defender for Identity with Microsoft Defender XDR

This article provides an overview of the full deployment process for Microsoft Defender for Identity, including steps for preparation, deployment, and extra steps for specific scenarios.

Defender for Identity is a primary component of a [Zero Trust](/security/zero-trust/zero-trust-overview) strategy and your identity threat detection and response (ITDR) or extended detection and response (XDR) deployment with Microsoft Defender XDR. Defender for Identity uses Active Directory signals to detect sudden account changes like privilege escalation or high-risk lateral movement, and reports on easily exploited identity issues like unconstrained Kerberos delegation, for correction by the security team.

For a quick set of deployment highlights, see [Quick installation guide](quick-installation-guide.md).

## Prerequisites

Before you start, make sure that you have access to Microsoft Defender XDR at least as a Security administrator, and you have one of the following licenses:

[!INCLUDE [licenses](includes/licenses.md)]

For more information, see [Licensing and privacy FAQs](/defender-for-identity/technical-faq#licensing-and-privacy) and [What are Defender for Identity roles and permissions?](role-groups.md)

## Start using Microsoft Defender XDR

This section describes how to start onboarding to Defender for Identity.

1. Sign in to the [Microsoft Defender portal](https://security.microsoft.com). 
1. From the navigation menu, select any item, such as **Incidents & alerts**, **Hunting**, **Action center**, or **Threat analytics** to initiate the onboarding process.

You'll then be given the option to deploy supported services, including Microsoft Defender for Identity. Cloud components required for Defender for Identity are automatically added when you open the Defender for Identity settings page.

For more information, see:

- [Microsoft Defender for Identity in Microsoft Defender XDR](/microsoft-365/security/defender/microsoft-365-security-center-mdi?bc=/defender-for-identity/breadcrumb/toc.json&toc=/defender-for-identity/TOC.json)
- [Get started with Microsoft Defender XDR](/microsoft-365/security/defender/get-started)
- [Turn on Microsoft Defender XDR](/microsoft-365/security/defender/m365d-enable)
- [Deploy supported services](/microsoft-365/security/defender/deploy-supported-services)
- [Frequently asked questions when turning on Microsoft Defender XDR](/microsoft-365/security/defender/m365d-enable-faq)

> [!IMPORTANT]
> Currently, Defender for Identity data centers are deployed in Europe, UK, North America/Central America/Caribbean, Australia East, and Asia. Your workspace (instance) is created automatically in the Azure region closest to the geographical location of your Microsoft Entra tenant. Once created, Defender for Identity workspaces aren't movable.

## Plan and prepare

Use the following steps to prepare for deploying Defender for Identity:

1. Make sure that you have all [prerequisites](prerequisites.md) required. 

1. [Plan your Defender for Identity capacity](capacity-planning.md).

> [!TIP]
> We recommend running the *Test-MdiReadiness.ps1* script to test and see if your environment has the necessary prerequisites. Download this script from the Microsoft XDR > **Identities** > **Tools** page.
> 
> For more information, see [the script's page](https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness) on GitHub.

## Deploy Defender for Identity

After you've prepared your system, use the following steps to deploy Defender for Identity:

1. [Verify connectivity to the Defender for Identity service](configure-proxy.md).
1. [Download the Defender for Identity sensor](download-sensor.md).
1. [Install the Defender for Identity sensor](install-sensor.md). 
1. [Configure the Defender for Identity sensor](configure-sensor-settings.md) to start receiving data.

## Post-deployment configuration

The following procedures help you complete the deployment process:

- **Configure Windows event collection**. For more information, see [Event collection with Microsoft Defender for Identity](deploy/event-collection-overview.md) and [Configure audit policies for Windows event logs](configure-windows-event-collection.md).

- [**Enable and configure unified role-based access control (RBAC)**](role-groups.md) for Defender for Identity.

- [**Configure a Directory Service account (DSA) for use with Defender for Identity**](directory-service-accounts.md). While a DSA is optional in some scenarios, we recommend that you configure a DSA for Defender for Identity for full security coverage.

- [**Configure remote calls to SAM**](remote-calls-sam.md) as needed. While this step is optional, we recommend that you configure remote calls to SAM-R for lateral movement path detection with Defender for Identity.

> [!IMPORTANT]
> Installing a Defender for Identity sensor on an AD FS / AD CS server requires extra steps. For more information, see [Configuring sensors for AD FS and AD CS](active-directory-federation-services.md).
> 

## Next step

> [!div class="step-by-step"]
> [Defender for Identity prerequisites »](prerequisites.md)

