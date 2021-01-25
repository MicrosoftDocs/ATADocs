---
title: Configure Windows Event collection Microsoft Defender for Identity
description: In this step of installing Microsoft Defender for Identity, you configure Windows Event collection.
ms.date: 10/26/2020
ms.topic: how-to
---

# Configure Windows Event collection

[!INCLUDE [Product long](includes/product-long.md)] detection relies on specific Windows Event log entries to enhance some detections and provide additional information on who performed specific actions such as NTLM logons, security group modifications, and similar events. For the correct events to be audited and included in the Windows Event Log, your domain controllers require accurate Advanced Audit Policy settings. Incorrect Advanced Audit Policy settings can lead to the required events not being recorded in the Event Log and result in incomplete [!INCLUDE [Product short](includes/product-short.md)] coverage.

To enhance threat detection capabilities, [!INCLUDE [Product short](includes/product-short.md)] needs the following Windows Events to be [configured](#configure-audit-policies) and [collected](#configure-event-collection) by [!INCLUDE [Product short](includes/product-short.md)]:

**For Active Directory Federation Services (AD FS) events**

- 1202 - The Federation Service validated a new credential
- 1203 - The Federation Service failed to validate a new credential
- 4624 - An account was successfully logged on
- 4625 - An account failed to log on

**For Other events**

- 4726 - User Account Deleted
- 4728 - Member Added to Global Security Group
- 4729 - Member Removed from Global Security Group
- 4730 - Global Security Group Deleted
- 4732 - Member Added to Local Security Group
- 4733 - Member Removed from Local Security Group
- 4743 - Computer Account Deleted
- 4753 - Global Distribution Group Deleted
- 4756 - Member Added to Universal Security Group
- 4757 - Member Removed from Universal Security Group
- 4758 - Universal Security Group Deleted
- 4763 - Universal Distribution Group Deleted
- 4776 - Domain Controller Attempted to Validate Credentials for an Account (NTLM)
- 7045 - New Service Installed
- 8004 - NTLM Authentication

## Configure audit policies

Modify the Advanced Audit Policies of your domain controller using the following instructions:

1. Log in to the Server as **Domain Administrator**.
1. Load the Group Policy Management Editor from **Server Manager** > **Tools** > **Group Policy Management**.
1. Expand the **Domain Controllers Organizational Units**, right-click on **Default Domain Controllers Policy**, and then select **Edit**.

    > [!NOTE]
    > You can use the Default Domain Controllers Policy or a dedicated GPO to set these policies.

    ![Edit domain controller policy](media/advanced-audit-policy-check-step-1.png)

1. From the window that opens, go to **Computer Configuration** > **Policies** > **Windows Settings** > **Security Settings** and depending on the policy you want to enable, do the following:

    **For Advanced Audit Policy Configuration**

    1. Go to **Advanced Audit Policy Configuration** > **Audit Policies**.
        ![Advanced Audit Policy Configuration](media/advanced-audit-policy-check-step-2.png)
    1. Under **Audit Policies**, edit each of the following policies and select **Configure the following audit events** for both **Success** and **Failure** events.

        | Audit policy | Subcategory | Triggers event IDs |
        | --- |---|---|
        | Account Logon | Audit Credential Validation | 4776 |
        | Account Management | Audit Computer Account Management | 4743 |
        | Account Management | Audit Distribution Group Management | 4753, 4763 |
        | Account Management | Audit Security Group Management | 4728, 4729, 4730, 4732, 4733, 4756, 4757, 4758 |
        | Account Management | Audit User Account Management | 4726 |
        | System | Audit Security System Extension | 7045 |

        For example, to configure **Audit Security Group Management**, under **Account Management**, double-click **Audit Security Group Management**, and then select **Configure the following audit events** for both **Success** and **Failure** events.

        ![Audit Security Group Management](media/advanced-audit-policy-check-step-4.png)

    <a name="ntlm-authentication-using-windows-event-8004"></a>
    **For Local Policies (Event ID: 8004)**

    > [!NOTE]
    >
    > - Domain group policies to collect Windows Event 8004 should **only** be applied to domain controllers.
    > - When Windows Event 8004 is parsed by [!INCLUDE [Product short](includes/product-short.md)] Sensor, [!INCLUDE [Product short](includes/product-short.md)] NTLM authentications activities are enriched with the server accessed data.

    1. Go to **Local Policies** > **Security Options**.
    1. Under **Security Options**, configure the specified security policies, as follows

        | Security policy setting | Value |
        |---|---|
        | Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers | Audit all |
        | Network security: Restrict NTLM: Audit NTLM authentication in this domain | Enable all |
        | Network security: Restrict NTLM: Audit Incoming NTLM Traffic | Enable auditing for all accounts |

        For example, to configure **Outgoing NTLM traffic to remote servers**, under **Security Options**, double-click **Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers**, and then select **Audit all**.

        ![Audit Outgoing NTLM traffic to remote servers](media/advanced-audit-policy-check-step-3.png)

    > [!NOTE]
    > If you choose to use a local security policy instead of using a group policy, make sure to add the **Account Logon**, **Account Management**, and **Security Options** audit logs in your local policy. If you are configuring the advanced audit policy, make sure to force the [audit policy subcategory](/windows/security/threat-protection/security-policy-settings/audit-force-audit-policy-subcategory-settings-to-override).

1. After applying via GPO, the new events are visible under your **Windows Event logs**.

<!--
## [!INCLUDE [Product short](includes/product-short.md)] Advanced Audit Policy check

To make it easier to verify the current status of each of your domain controller's Advanced Audit Policies, [!INCLUDE [Product short](includes/product-short.md)] automatically checks your existing Advanced Audit Policies and issues health alerts for policy settings that require modification. Each health alert provides specific details of the domain controller, the problematic policy as well as remediation suggestions.

![Advanced Audit Policy Health Alert](media/health-alert-audit.png)

Advanced Security Audit Policy is enabled via **Default Domain Controllers Policy** GPO. These audit events are recorded on the domain controller's Windows Events.
-->

## Configure event collection

These events can be collected automatically by the [!INCLUDE [Product short](includes/product-short.md)] sensor or, if the [!INCLUDE [Product short](includes/product-short.md)] sensor is not deployed, they can be forwarded to the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor in one of the following ways:

- [Configure the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor](configure-event-forwarding.md) to listen for SIEM events
- [Configure Windows Event Forwarding](configure-event-forwarding.md)

> [!NOTE]
>
> - [!INCLUDE [Product short](includes/product-short.md)] standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the [!INCLUDE [Product short](includes/product-short.md)] sensor.
> - It is important to review and verify your [audit policies]() before enabling event collection to ensure that the domain controllers are properly configured to record the necessary events.

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] sizing tool](https://aka.ms/aatpsizingtool)
- [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md)
- [[!INCLUDE [Product short](includes/product-short.md)] SIEM log reference](cef-format-sa.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](https://aka.ms/MDIcommunity)
