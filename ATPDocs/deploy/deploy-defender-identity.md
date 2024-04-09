---
title: Deploy Microsoft Defender for Identity
description: Learn how to deploy Microsoft Defender for Identity from the Microsoft Defender portal.
ms.date: 04/08/2024
ms.topic: how-to
---

# Deploy Microsoft Defender for Identity with Microsoft Defender XDR

This article provides an overview of the full deployment process for Microsoft Defender for Identity, including steps for preparation, deployment, and extra steps for specific scenarios.

Defender for Identity is a primary component of a [Zero Trust](/security/zero-trust/zero-trust-overview) strategy and your identity threat detection and response (ITDR) or extended detection and response (XDR) deployment with Microsoft Defender XDR. Defender for Identity uses Active Directory signals to detect sudden account changes like privilege escalation or high-risk lateral movement, and reports on easily exploited identity issues like unconstrained Kerberos delegation, for correction by the security team.

For a quick set of deployment highlights, see [Quick installation guide](quick-installation-guide.md).

## Prerequisites

Before you start, make sure that you have access to Microsoft Defender XDR at least as a Security administrator, and you have one of the following licenses:

[!INCLUDE [licenses](../includes/licenses.md)]

For more information, see [Licensing and privacy FAQs](/defender-for-identity/technical-faq#licensing-and-privacy) and [What are Defender for Identity roles and permissions?](../role-groups.md)

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

Defender for Identity's default deployment supports deploying a Defender for Identity sensor on a domain controller, AD CS, or AD FS server. However, Defender for Endpoint customers can also use their Defender for Endpoint sensors as a unified sensor for both Defender for Endpoint and Defender for Identity.

Use the following steps to prepare for deploying Defender for Identity, making sure to the follow the links for a Defender for Identity or a unified sensor, as relevant for your environment.

1. Make sure that you have all prerequisites required. For more information, see:

    - [Microsoft Defender for Identity prerequisites](prerequisites.md)
    - [Unified sensor prerequisites](onboard-unified-sensor.md#prerequisites)

    <!--is there anything from the main prerequistites that we also need here?-->

1. [Plan your Defender for Identity capacity](capacity-planning.md). <!--is this also relevant for unified sensor?-->

> [!TIP]
> We recommend running the [*Test-MdiReadiness.ps1*](https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness) script to test and see if your environment has the necessary prerequisites.
>
> The link to the *Test-MdiReadiness.ps1* script is also available from Microsoft Defender XDR, on the **Identities > Tools** page (Preview).

## Deploy Defender for Identity

If you're using a unified sensor, continue directly with  [Onboard a unified Defender for Identity and Defender for Endpoint sensor (Preview)](onboard-unified-sensor.md).

If you're deploying a Defender for Identity sensor, use the following steps to deploy your sensor:

1. [Verify connectivity to the Defender for Identity service](configure-proxy.md).
1. [Download the Defender for Identity sensor](download-sensor.md).
1. [Install the Defender for Identity sensor](install-sensor.md). 
1. [Configure the Defender for Identity sensor](configure-sensor-settings.md) to start receiving data.

> [!IMPORTANT]
> Installing a Defender for Identity sensor on an AD FS / AD CS server requires extra steps. For more information, see [Configuring sensors for AD FS and AD CS](active-directory-federation-services.md).
>

## Post-deployment configuration

If you're using a Defender for Identity sensor, use the following procedures to help complete the deployment process:

<!--are any of these definately not relevant for defensor?-->

- **Configure Windows event collection**. For more information, see [Event collection with Microsoft Defender for Identity](event-collection-overview.md) and [Configure audit policies for Windows event logs](configure-windows-event-collection.md).

- [**Enable and configure unified role-based access control (RBAC)**](../role-groups.md) for Defender for Identity.

- [**Configure a Directory Service account (DSA) for use with Defender for Identity**](directory-service-accounts.md). While a DSA is optional in some scenarios, we recommend that you configure a DSA for Defender for Identity for full security coverage.

- [**Configure remote calls to SAM**](remote-calls-sam.md) as needed. While this step is optional, we recommend that you configure remote calls to SAM-R for lateral movement path detection with Defender for Identity.

If you're using a unified Defender for Endpoint and Defender for Identity sensor, only configuring Windows event collection is relevant.

## Next step

> [!div class="step-by-step"]
> [Defender for Identity prerequisites »](prerequisites.md)
