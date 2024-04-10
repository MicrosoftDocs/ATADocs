---
title: Activate Microsoft Security Agent capabilites for Microsoft Defender for Identity
description: Learn about the Microsoft Security Agent capabilities for Microsoft Defender for Identity and how to activate them.
ms.date: 04/10/2024
ms.topic: how-to
---

# Activate Microsoft Security Agent capabilites for Microsoft Defender for Identity(Preview)

<!--what are we calling this? microsoft security agent-->

Microsoft Defender for Endpoint customers who already onboarded their domain controllers can activate the Microsoft security agent capabilities instead of using a [Microsoft Defender for Identity sensor](deploy-defender-identity.md).

This article describes how to active Microsoft Security Agent capabilities for Defender for Identity on your domain controller, and lists supported Defender for Identity functionality.

> [!IMPORTANT]
> Information in this article relates to a prerelease product which may be substantially modified before it's commercially released. Microsoft makes no warranties, express or implied, with respect to the information provided here.

## Prerequisites

Before activating the Microsoft Security Agent capabilites for Defender for Identity, make sure that your environment complies with the prerequisites in this section.

### Defender for Identity sensor conflicts

Make sure that you don't already have a [Defender for Identity sensor](deploy-defender-identity.md) deployed on the same domain controller as you're planning to activate Microsoft Security Agent capabilites for Defender for Identity.

### System requirements

Unified Defender for Endpoint and Defender for Identity sensors are supported on domain controllers only, using the one of the following operating systems only:

- Windows Server 2019
- Windows Server 2022

You must also have the [March 2024 Cumulative Update](https://support.microsoft.com/topic/march-12-2024-kb5035857-os-build-20348-2340-a7953024-bae2-4b1a-8fc1-74a17c68203c) installed.

> [!IMPORTANT]
>After installing the March 2024 Cumulative Update, LSASS might experience a memory leak on domain controllers when on-premises and cloud-based Active Directory Domain Controllers service Kerberos authentication requests.
>
> This issue is addressed in the out-of-band update [KB5037422](https://support.microsoft.com/en-gb/topic/march-22-2024-kb5037422-os-build-20348-2342-out-of-band-e8f5bf56-c7cb-4051-bd5c-cc35963b18f3).

### Defender for Endpoint oboarding

Your domain controller must be onboarded to Microsoft Defender for Endpoint.

For more information, see [Onboard a Windows server](/microsoft-365/security/defender-endpoint/onboard-windows-server).

### Required permissions

To access the Defender for Identity sensor onboarding page, you must either be a [Security Administrator](/entra/identity/role-based-access-control/permissions-reference), or have the following Unified RBAC permissions:

- `Authorization and settings/Security settings/Read`
- `Authorization and settings/Security settings/All permissions`
- `Authorization and settings/System settings/Read`
- `Authorization and settings/System settings/All permissions`

For more information, see [Unified role-based access control RBAC](/defender-for-identity/role-groups#unified-role-based-access-control-rbac).

### Connectivity requirements

<!--search for unified sensor-->
The Microsoft Security Agent uses Defender for Endpoint URL endpoints for communication, including simplified URLs.

For more information, see [Configure your network environment to ensure connectivity with Defender for Endpoint](/microsoft-365/security/defender-endpoint/configure-environment##enable-access-to-microsoft-defender-for-endpoint-service-urls-in-the-proxy-server).

## Configure Defender for Identity auditing

Defender for Identity detections rely on specific Windows Event Log entries to enhance detections and provide extra information about the users performing specific actions, such as NTLM sign-ins and security group modifications.

Configure Windows event collection on your domain controller to support Defender for Identity detections. For more information, see [Event collection with Microsoft Defender for Identity](event-collection-overview.md) and [Configure audit policies for Windows event logs](configure-windows-event-collection.md).

You might want to use the Defender for Identity PowerShell module to configure the required settings. For more information, see:

- [DefenderForIdentity Module](/powershell/module/defenderforidentity/)
- [Defender for Identity in the PowerShell Gallery](https://www.powershellgallery.com/packages/DefenderForIdentity/)

For example, the following command defines all settings for the domain, creates group policy objects, and links them.

```powershell
Set-MDIConfiguration -Mode Domain -Configuration All
```

## Activate Defender for Identity capabilities

After ensuring that your environment is completety configured, activate the Microsoft Security Agent's capabilities for Defender for Identity.

1. In the [Defender portal](https://security.microsoft.com), select **Settings > Identities > [Activation](https://security.microsoft.com/settings/identities?tabid=onboarding)**.

    The **Activation** page lists any detected domain controllers that are eligible for activation.

1. Select the domain controller where you want to activate the Security Agent capabilities for Defender for Identity and then select **Activate**. Confirm your selection when prompted.

When the activation is complete, a green success banner shows. In the banner, select **Click here to see the onboarded servers** to jump to the **Settings > Identities > Sensors** page, where you can check your sensor health.

The first time you activate Microsoft Security Agent capabilities on your domain controller, it may take up to an hour to show on the **Sensors** page. Subsequent activations should show within five minutes.

## Test Security Agent capabilities

Use the following procedures to test Security Agent capabilities for Defender for Identity.


### Confirm entity page details

Confirm that entites, such as domain controllers, users, and groups, are populated as expected:

- **Device entities**: In the Defender portal, select **Assets > Devices**, and select the machine for your new sensor. Defender for Identity events are shown on the device timeline.

- **User entities**. In the Defender portal, select **Assets > Users** and check for users from a newly onboarded domain. Alternately, use the global search option to search for specific users. User details pages should include **Overview**, **Observed in organization**, and **Timeline** data.

- **Group entities**: Use the global search to find a user group, or pivot from a user or device details page where group details are shown. Check for details of group membership, view group users, and group timeline data.

    If no event data is found on the group timeline, you may need to create some manually. For example, do this by adding and removing users from the group in Active Directory.

For more information, see [Investigate assets](../investigate-assets.md).

### Check the ITDR dashboard

In the Defender portal, select **Identities > Dashboard** and review the details shown.

For more information, see [Work with Defender for Identity's ITDR dashboard (Preview)](../dashboard.md).

### Test Identity Security Posture Management (ISPM) recommendations

The unified Defender for Endpoint and Defender for Identity sensor supports the following assesments:

- [**Resolve unsecure domain configurations**](security-assessment-unsecure-domain-configurations.md)
- [**Install Defender for Identity Sensor on all Domain Controllers**](../security-assessment-unmonitored-domain-controller.md)
- **Set a honeytoken account** <!--are we missing this in docs?-->

We recommend simulating risky behavior in a test environment to trigger supported assessments and verify that they appear as expected. For example:

1. Trigger a new **Resolve unsecure domain configurations** recommednation by setting your Active Directory configuration to a non-compliant state, and then returning it to a compliant state.

1. In Microsoft Secure Score, select **Recommended Actions** to check a new **Resolve unsecure domain configurations** recommendation. You might want to filter recommendations by the **Defender for Identity** product.

For more information, see [Microsoft Defender for Identity's security posture assessments](../security-assessment.md)

### Test alert functionality

The following alerts are supported by the Microsoft Security Agent:

- [Honeytoken user attributes modified](../persistence-privilege-escalation-alerts.md#honeytoken-user-attributes-modified-external-id-2427)
- [Security principal reconnaissance (LDAP)](../credential-access-alerts.md#security-principal-reconnaissance-ldap-external-id-2038)
- [Honeytoken was queried via LDAP](../reconnaissance-discovery-alerts.md#honeytoken-was-queried-via-ldap-external-id-2429)
- [Active Directory attributes Reconnaissance using LDAP](../reconnaissance-discovery-alerts.md#active-directory-attributes-reconnaissance-ldap-external-id-2210) <!--not documented-->
- [Remote code execution attempt](../other-alerts.md#remote-code-execution-attempt-external-id-2019)
- [Suspicious modification of the Resource Based Constrained Delegation attribute by a machine account](../persistence-privilege-escalation-alerts.md#suspicious-modification-of-the-resource-based-constrained-delegation-attribute-by-a-machine-account--external-id-2423)
- [Suspicious additions to sensitive groups](../persistence-privilege-escalation-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024)
- [Suspicious service creation](../other-alerts.md#suspicious-service-creation-external-id-2026)
- [Honeytoken group membership changed](../persistence-privilege-escalation-alerts.md#honeytoken-group-membership-changed-external-id-2428) 
- [Suspected DFSCoerce attack using Distributed File System Protocol](../credential-access-alerts.md#suspected-dfscoerce-attack-using-distributed-file-system-protocol-external-id-2426) 
- [Suspicious modification of a dNSHostName attribute (CVE-2022-26923)](../persistence-privilege-escalation-alerts.md#suspicious-modification-of-a-dnshostname-attribute-cve-2022-26923--external-id-2421)
- [Suspected DCShadow attack (domain controller promotion)](../other-alerts.md#suspected-dcshadow-attack-domain-controller-promotion-external-id-2028)
- [Suspicious modification of a sAMNameAccount attribute (CVE-2021-42278 and CVE-2021-42287)](../credential-access-alerts.md#suspicious-modification-of-a-samnameaccount-attribute-cve-2021-42278-and-cve-2021-42287-exploitation-external-id-2419)
- [Suspected DCShadow attack (domain controller replication request)](../other-alerts.md#suspected-dcshadow-attack-domain-controller-replication-request-external-id-2029)
- [Suspected account takeover using shadow credentials](../credential-access-alerts.md#suspected-account-takeover-using-shadow-credentials-external-id-2431)

Test alert functionality by simulating risky activity in your environment. For example:

- Tag an account as a honeytoken account, and then try signing in to the honeytoken account. 
- Create a suspicious service on your domain controller.
- Run a remote command on your domain controller as an administrator signed in from your workstation. 

For more information, see [Investigate Defender for Identity security alerts in Microsoft Defender XDR](../manage-security-alerts.md).

### Test advanced hunting tables

In the Defender portal's **Advanced hunting** page, use the following sample queries to check that data appears in relevant tables:

```kusto
IdentityDirectoryEvents
| where TargetDeviceName contains "DC_FQDN" // insert domain controller FQDN
IdentityInfo 
| where AccountDomain contains "domain" // insert domain
IdentityQueryEvents 
| where DeviceName contains "DC_FQDN" // insert domain controller FQDN
// Show users with sensitive tags
IdentityInfo
| where SourceProvider == "ActiveDirectory"
| where Tags contains "Sensitive"
// Service Creation
IdentityDirectoryEvents
| where ActionType == @"Service creation"
| extend ParsedFields=parse_json(AdditionalFields)
| project Timestamp, ActionType, TargetDeviceName, AccountName, AccountDomain, ServiceName=tostring(ParsedFields.ServiceName), ServiceCommand=tostring(ParsedFields.ServiceCommand)
| where ServiceName != @"Microsoft Monitoring Agent Azure VM Extension Heartbeat Service"
| where ServiceName != @"MOMAgentInstaller"
| where ServiceName !contains @"MpKsl"
```

For more information, see [Advanced hunting in the Microsoft Defender portal](/microsoft-365/security/defender/advanced-hunting-microsoft-defender).

### Test remediation actions

Test remediation actions on a test user. For example:

1. Go to the user details page for a test user.

1. From the options menu, select any or all of the following, one at a time:

    - Disable user in AD
    - Enable user in AD
    - Force password reset

1. Check Active Directory for the expected activity.

For more information, see [Remediation actions in Microsoft Defender for Identity](../remediation-actions.md).

## Test automatic attack disruption

For more information, see [Automatic attack disruption](/microsoft-365/security/defender/automatic-attack-disruption).

## Remove Microsoft Security Agent capabilities for Defender for Identity

If you want to remove Microsoft Security Agent capabilities for Defender for Identity from your domain controller, delete it from the **Sensors** page.

1. In the Defender portal, select **Settings > Identities > Sensors**.
1. Select the sensor, select **Delete**, and confirm your selection.

Removing Microsoft Security Agent capabilties for Defender for Identity doesn't remove the domain controller from Defender for Endpoint. For more information, see [Defender for Endpoint documentation](/microsoft-365/security/defender-endpoint/). <!--do we have a better link?-->

## Next steps

For more information, see [Manage and update Microsoft Defender for Identity sensors](../sensor-settings.md)

