---
title: Multi-forest support | Microsoft Defender for Identity
description: Learn about how Microsoft Defender for Identity supports multiple Active Directory forests.
ms.date: 08/10/2023
ms.topic: conceptual
---

# Microsoft Defender for Identity multi-forest support

Microsoft Defender for Identity supports organizations with multiple Active Directory forests, giving you the ability to easily monitor activity and profile users across forests.

Enterprise organizations typically have several Active Directory forests - often used for different purposes, including legacy infrastructure from corporate mergers and acquisitions, geographical distribution, and security boundaries (red-forests).

Securing your multiple Active Directory forests with Defender for Identity provides the following advantages:

- View and investigate activities performed by users across multiple forests from a single location
- Gain improved detection and reduce false positives with advanced Active Directory integration and account resolution
- Gain greater control and easier deployment, with an improved set of health issues and reporting for cross-org coverage when your domain controllers are all monitored from a single Defender for Identity server

## Prerequisites

Defender for Identity requires the following to support multiple Active Directory forests:

- **A Directory Service account**: The Directory Service account you configure for each forest must:

  - Be trusted in all the other forests
  - Have at least read-only permission to perform LDAP queries on the domain controllers.

  If Defender for Identity standalone sensors are installed on standalone machines, rather than directly on the domain controllers, the machines must be allowed to communicate with all of remote forest domain controllers using LDAP.

- **Required ports**: In order for Defender for Identity to communicate with the Defender for Identity sensors, including standalone sensors, make sure the following ports are opened on any machine where a Defender for Identity sensor is installed:

  |Protocol|Transport|Port|To/From|Direction|
  |----|----|----|----|----|
  |**Internet ports**||||
  |SSL (*.atp.azure.com)|TCP|443|Defender for Identity cloud service|Outbound|
  |**Internal ports**||||
  |LDAP|TCP and UDP|389|Domain controllers|Outbound|
  |Secure LDAP (LDAPS)|TCP|636|Domain controllers|Outbound|
  |LDAP to Global Catalog|TCP|3268|Domain controllers|Outbound|
  |LDAPS to Global Catalog|TCP|3269|Domain controllers|Outbound|

<!-->
> [!NOTE]
> Each Defender for Identity sensor can only report to a single Defender for Identity workspace. <!--is this really still necessary? moved from known issues
>
-->

## Detection activity across multiple forests

To detect cross-forest activities, Defender for Identity sensors query domain controllers in remote forests to create profiles for all entities involved, including users and computers from remote forests.

- Defender for Identity sensors can be installed on domain controllers in all forests, even forests with no trust.

- [Add additional credentials](directory-service-accounts.md#configure-a-directory-service-account-in-microsoft-365-defender) on the **Directory Service accounts** page to support any untrusted forests in your environment.

  - Only one credential is required to support all forests with a two-way trust.

  - Additional credentials are only required for each forest with non-Kerberos trust or no trust.

  - There's a default limit of 30 untrusted forests per Defender for Identity instance. Contact support if your organization has more than 30 forests.

For more information, see [Microsoft Defender for Identity Directory Service account recommendations](directory-service-accounts.md).


## Multi-forest mapping process

When Defender for Identity maps your forests, it uses the following process:

1. After the Defender for Identity sensor starts running, the sensor queries the remote Active Directory forests and retrieves a list of users and machine data for profile creation.

1. Every 5 minutes, each Defender for Identity sensor queries one domain controller from each domain, from each forest, to map all the forests in the network.

    The Defender for Identity sensors map the forests using the `trustedDomain` Active Directory object, by signing in and checking the trust type.

You may see ad-hoc traffic when the Defender for Identity sensor detects cross forest activity. When this occurs, the Defender for Identity sensors will send an LDAP query to the relevant domain controllers to retrieve entity information.

> [!NOTE]
> Interactive sign-ins performed by users in one forest to access resources in another forest aren't displayed in the Defender for Identity dashboard.
>

## Next steps

- [Defender for Identity sizing tool](<https://aka.ms/aatpsizingtool>)
- [Defender for Identity architecture](../architecture.md)
- [Install Defender for Identity](/defender-for-identity/classic-install-step1)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
