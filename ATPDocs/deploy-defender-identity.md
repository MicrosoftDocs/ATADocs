---
title: Deploying with Microsoft 365 Defender
description: Learn how to deploy Microsoft Defender for Identity using Microsoft 365 Defender
ms.date: 01/29/2023
ms.topic: how-to
---

# Deploy Microsoft Defender for Identity with Microsoft 365 Defender

The deployment of Microsoft Defender for Identity with Microsoft 365 Defender has two phases - preparation and deployment.

This article will outline the steps in each phase, and also provide instructions for special scenarios.

## Start using Microsoft 365 Defender

To begin the deployment of Defender for Identity, sign in to the [Microsoft 365 Defender portal](https://security.microsoft.com). From the navigation menu, select any item, such as **Incidents & alerts**, **Hunting**, **Action center**, or **Threat analytics** to initiate the onboarding process.

You'll then be given the option to deploy supported services, including Microsoft Defender for Identity. When you go to the Defender for Identity settings, the required cloud components will be auto-provisioned.

For more information about these steps, see the following articles:

- [Microsoft Defender for Identity in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi?bc=/defender-for-identity/breadcrumb/toc.json&toc=/defender-for-identity/TOC.json)
- [Get started with Microsoft 365 Defender](/microsoft-365/security/defender/get-started)
- [Turn on Microsoft 365 Defender](/microsoft-365/security/defender/m365d-enable)
- [Deploy supported services](/microsoft-365/security/defender/deploy-supported-services)
- [Frequently asked questions when turning on Microsoft 365 Defender](/microsoft-365/security/defender/m365d-enable-faq)

> [!IMPORTANT]
> Currently, Defender for Identity data centers are deployed in Europe, UK, North America/Central America/Caribbean, Australia East, and Asia. Your workspace is created automatically in the Azure region closest to the geographical location of your Azure Active Directory tenant. Once created, Defender for Identity instances aren't movable.

## Preparation

1. [Defender for Identity prerequisites](prerequisites.md).
1. [Plan your Defender for Identity capacity](capacity-planning.md).
1. [Configure Windows Event collection](configure-windows-event-collection.md).
1. [Directory Service accounts](directory-service-accounts.md).
1. [Role groups](role-groups.md).
1. [Configure remote calls to SAM](remote-calls-sam.md).
   

> [!Note]
> To test and see if your environment has the necessary prerequisites, you can run the Test-MdiReadiness.ps1 script. For more information, see [the script's page](https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness).
> 

## Deployment

1. [Download the Defender for Identity sensor](download-sensor.md).
1. [Proxy configuration](configure-proxy.md).
1. [Install the Defender for Identity sensor](install-sensor.md).
1. [Manage action accounts](manage-action-accounts.md).
1. [Configure the Defender for Identity sensor](configure-sensor-settings.md) to start receiving data.

## Special scenarios

1. [Installing on Active Directory Federation Services](active-directory-federation-services.md)
1. [Multi-forest support](multi-forest.md)
1. [Migrate from Advanced Threat Analytics (ATA)](migrate-from-ata-overview.md)

### Standalone sensor

If you deploy Defender for Identity standalone sensors, you'll need to do the following steps:

1. [Configure port mirroring](configure-port-mirroring.md)
1. [Validate Port Mirroring](validate-port-mirroring.md)
1. [Configure event collection](configure-event-collection.md)
1. [Configuring Windows Event Forwarding](configure-event-forwarding.md)

## Next steps

> [!div class="step-by-step"]
> [Defender for Identity prerequisites »](prerequisites.md)

