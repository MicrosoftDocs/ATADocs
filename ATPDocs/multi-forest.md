---
title: Microsoft Defender for Identity multi-forest support
description: Support for multiple Active Directory forests in Microsoft Defender for Identity.
ms.date: 11/23/2022
ms.topic: conceptual
---

# Microsoft Defender for Identity multi-forest support

> [!NOTE]
> The experience described in this page can be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender.

## Multi-forest support set up

[!INCLUDE [Product long](includes/product-long.md)] supports organizations with multiple forests, giving you the ability to easily monitor activity and profile users across forests.

Enterprise organizations typically have several Active Directory forests - often used for different purposes, including legacy infrastructure from corporate mergers and acquisitions, geographical distribution, and security boundaries (red-forests). You can protect multiple forests using [!INCLUDE [Product short](includes/product-short.md)], providing you with the ability to monitor and investigate your entire network through a single pane of glass.

The ability to support multiple Active Directory forests enables the following:

- View and investigate activities performed by users across multiple forests, from a single pane of glass.
- Improved detection and reduced false positives by providing advanced Active Directory integration and account resolution.
- Greater control and easier deployment. Improved health alerts and reporting for cross-org coverage when your domain controllers are all monitored from a single [!INCLUDE [Product short](includes/product-short.md)] console.

## Defender for Identity detection activity across multiple forests

To detect cross-forest activities, [!INCLUDE [Product short](includes/product-short.md)] sensors query domain controllers in remote forests to create profiles for all entities involved, (including users and computers from remote forests).

- [!INCLUDE [Product short](includes/product-short.md)] sensors can be installed on domain controllers in all forests, even forests with no trust.
- [Add additional credentials](directory-service-accounts.md#configure-directory-service-account-in-microsoft-365-defender) on the **Directory Service accounts** page to support any untrusted forests in your environment.
  - Only one credential is required to support all forests with a two-way trust.
  - Additional credentials are only required for each forest with non-Kerberos trust or no trust.
  - There is a default limit of 30 untrusted forests per [!INCLUDE [Product short](includes/product-short.md)] instance. Contact support if your organization has more than 30 forests.

For detailed information about how to create a Directory Service account and configure it in the Microsoft 365 Defender portal, see [Microsoft Defender for Identity Directory Service account recommendations](directory-service-accounts.md).

### Requirements

- The Directory Service account you configure must be trusted in all the other forests and must have at least read-only permission to perform LDAP queries on the domain controllers.
- If [!INCLUDE [Product short](includes/product-short.md)] standalone sensors are installed on standalone machines, rather than directly on the domain controllers, make sure the machines are allowed to communicate with all of remote forest domain controllers using LDAP.

- In order for [!INCLUDE [Product short](includes/product-short.md)] to communicate with the [!INCLUDE [Product short](includes/product-short.md)] sensors and [!INCLUDE [Product short](includes/product-short.md)] standalone sensors, open the following ports on each machine on which the [!INCLUDE [Product short](includes/product-short.md)] sensor is installed:

  |Protocol|Transport|Port|To/From|Direction|
  |----|----|----|----|----|
  |**Internet ports**||||
  |SSL (*.atp.azure.com)|TCP|443|[!INCLUDE [Product short](includes/product-short.md)] cloud service|Outbound|
  |**Internal ports**||||
  |LDAP|TCP and UDP|389|Domain controllers|Outbound|
  |Secure LDAP (LDAPS)|TCP|636|Domain controllers|Outbound|
  |LDAP to Global Catalog|TCP|3268|Domain controllers|Outbound|
  |LDAPS to Global Catalog|TCP|3269|Domain controllers|Outbound|

## Multi-forest support network traffic impact

When [!INCLUDE [Product short](includes/product-short.md)] maps your forests, it uses a process that impacts the following:

- After the [!INCLUDE [Product short](includes/product-short.md)] sensor is running, it queries the remote Active Directory forests and retrieves a list of users and machine data for profile creation.
- Every 5 minutes, each [!INCLUDE [Product short](includes/product-short.md)] sensor queries one domain controller from each domain, from each forest, to map all the forests in the network.
- Each [!INCLUDE [Product short](includes/product-short.md)] sensor maps the forests using the "trustedDomain" object in Active Directory, by logging in and checking the trust type.
- You may also see ad-hoc traffic when the [!INCLUDE [Product short](includes/product-short.md)] sensor detects cross forest activity. When this occurs, the [!INCLUDE [Product short](includes/product-short.md)] sensors will send an LDAP query to the relevant domain controllers in order to retrieve entity information.

## Known limitations

- Interactive logons performed by users in one forest to access resources in another forest are not displayed in the [!INCLUDE [Product short](includes/product-short.md)] dashboard.
- Each Defender for Identity sensor can only report to a single Defender for Identity workspace, and each Azure tenant can only host a single Defender for Identity workspace. Therefore, each sensor can only report to a single Azure tenant.

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] sizing tool](<https://aka.ms/aatpsizingtool>)
- [[!INCLUDE [Product short](includes/product-short.md)] architecture](architecture.md)
- [Install [!INCLUDE [Product short](includes/product-short.md)]](install-step1.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
