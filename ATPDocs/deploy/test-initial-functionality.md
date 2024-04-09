---
title: Test initial functionality | Microsoft Defender for Identity
description: Learn how to test initial functionality after deploying a Microsoft Defender for Identity or unified sensor.
ms.date: 04/04/2024
ms.topic: how-to
---

# Test initial Microsoft Defender for Identity or unified sensor functionality

After deploying a Microsoft Defender for Identity sensor or onboarding a unified Microsoft Defender for Endpoint and Defender for Identity sensor, use the procedures in this article to test initial functionality and confirm that your sensor is performing as expected.

## Prerequisites

Make sure that you have a sensor deployed or onboarded. For more information, see:

- [Deploy Microsoft Defender for Identity with Microsoft Defender XDR](deploy-defender-identity.md)
- [Onboard a unified Defender for Identity and Defender for Endpoint sensor (Preview)](onboard-unified-sensor.md)
- [Microsoft Defender for Identity architecture](../architecture.md)

## Confirm entity page details

Confirm that entites, such as domain controllers, users, and groups, are populated as expected:

- **Device entities**: In the Defender portal, select **Assets > Devices**, and select the machine for your new sensor. Defender for Identity events are shown on the device timeline.

- **User entities**. In the Defender portal, select **Assets > Users** and check for users from a newly onboarded domain. Alternately, use the global search option to search for specific users. User details pages should include **Overview**, **Observed in organization**, and **Timeline** data.

- **Group entities**: Use the global search to find a user group, or pivot from a user or device details page where group details are shown. Check for details of group membership, view group users, and group timeline data.

    If no event data is found on the group timeline, you may need to create some manually. For example, do this by adding and removing users from the group in Active Directory.

For more information, see [Investigate assets](../investigate-assets.md).

## Check the ITDR dashboard

In the Defender portal, select **Identities > Dashboard** and review the details shown.

For more information, see [Work with Defender for Identity's ITDR dashboard (Preview)](../dashboard.md).

## Test Identity Security Posture Management (ISPM) recommendations

In Microsoft Secure Score, select **Recommended Actions** to check for security posture management recommendations provided by Defender for Identity. Filter recommendations by the **Defender for Identity** product.

For example, to trigger a new recommendation in your system:

1. Set your Active Directoy configuration to a non-compliant state, and then return it to a compliant state.
1. Check for the **Unsecure domain configurations** assessment.

For more information, see [Microsoft Defender for Identity's security posture assessments](../security-assessment.md).

## Test alert functionality

Test alert functionality by simulating risky activity in your environment. For example:

- Tag an account as a honeytoken account, and then try signing in to the honeytoken account. 
- Create a suspicious service on your domain controller.
- Run a remote command on your domain controller as an administrator signed in from your workstation. 

For more information, see [Investigate Defender for Identity security alerts in Microsoft Defender XDR](../manage-security-alerts.md).

## Test advanced hunting tables

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

## Test remediation actions

Test remediation actions on a test user. For example:

1. Go to the user details page for a test user.

1. From the options menu, select any or all of the following, one at a time:

    - Disable user in AD
    - Enable user in AD
    - Force password reset

1. Check Active Directory for the expected activity.

For more information, see [Remediation actions in Microsoft Defender for Identity](../remediation-actions.md).

## Next step

> [!div class="nextstepaction"]
> [Investigate assets](../investigate-assets.md)