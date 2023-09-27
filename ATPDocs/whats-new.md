---
title: What's new | Microsoft Defender for Identity
description: This article is updated frequently to let you know what's new in the latest release of Microsoft Defender for Identity.
ms.date: 09/12/2023
ms.topic: overview
#CustomerIntent: As a Defender for Identity customer, I want to know what's new in the latest release of Defender for Identity, so that I can take advantage of new features and functionality. 
---

# What's new in Microsoft Defender for Identity

This article is updated frequently to let you know what's new in the latest releases of Microsoft Defender for Identity.

[!INCLUDE [automatic-redirect](../includes/automatic-redirect.md)]

## Get notified about updates

Get notified when this page is updated by copying and pasting the following URL into your feed reader: `https://aka.ms/mdi/rss`

## What's new scope and references

Defender for Identity releases are deployed gradually across customer tenants. If there's a feature documented here that you don't see yet in your tenant, check back later for the update.

For more information, see also:

- [What's new in Microsoft 365 Defender](/microsoft-365/security/defender/whats-new)
- [What's new in Microsoft Defender for Endpoint](/microsoft-365/security/defender-endpoint/whats-new-in-microsoft-defender-endpoint)
- [What's new in Microsoft Defender for Cloud Apps](/cloud-app-security/release-notes)

For updates about versions and features released six months ago or earlier, see the [What's new archive for Microsoft Defender for Identity](whats-new-archive.md).

## September 2023

### Alert learning period enhancements

Defender for Identity alert learning periods have been enhanced to provide more control over the learning period experience, including:

- Any new Defender for Identity workspace now automatically has an alert learning period turned on for 30 days. When 30 days is complete, the learning period is automatically turned off and a health alert is triggered to notify administrators.

- Administrators can now configure the sensitivity used for specific alerts, and can also completely turn off learning for specific alerts. For example:

    :::image type="content" source="media/advanced-settings/learning-period.png" alt-text="Screenshot of a learning period turned on." lightbox="media/advanced-settings/learning-period.png":::

During the learning period, Defender for Identity learns about your network and builds a profile of your network's normal activity. Learning periods can be useful for updating your baseline algorithms, but can also result in a high volume of alerts, some of which may be triggered by legitimate activity.

For more information, see [Advanced settings](advanced-settings.md).

> [!NOTE]
> If you'd previously had the **Remove learning period** setting turned on, this setting is now reverted to the default and is turned off. In such cases, we recommend checking your settings and reconfiguring sensitivity as needed.

### Defender for Identity release 2.215

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity reports moved to the main Reports area

Now you can access Defender for Identity reports from Microsoft 365 Defender's main **Reports** area instead of the **Settings** area. For example:

:::image type="content" source="media/whats-new/reports-main-area.png" alt-text="Screenshot of the Defender for Identity report access from the main Reports area.":::

For more information, see [Download and schedule Defender for Identity reports in Microsoft 365 Defender (Preview)](reports.md).

### Go hunt button for groups in Microsoft 365 Defender

Defender for Identity has added the **Go hunt** button for groups in Microsoft 365 Defender. Users can use the **Go hunt** button to query for group-related activities and alerts during an investigation.

For example:

:::image type="content" source="media/whats-new/go-hunt-groups.png" alt-text="Screenshot of the new Go hunt button on a group details pane.":::

For more information, see [Quickly hunt for entity or event information with go hunt](/microsoft-365/security/defender/advanced-hunting-go-hunt).

### Defender for Identity release 2.214

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Performance enhancements

Defender for Identity has made internal improvements for latency, stability, and performance when transferring real-time events from Defender for Identity services to Microsoft 365 Defender. Customers should expect no delays in Defender for Identity data appearing in Microsoft 365 Defender, such as alerts or activities for advanced hunting.


For more information, see:

- [Security alerts in Microsoft Defender for Identity](alerts-overview.md)
- [Microsoft Defender for Identity's security posture assessments](security-assessment.md)
- [Proactively hunt for threats with advanced hunting in Microsoft 365 Defender](/microsoft-365/security/defender/advanced-hunting-overview)

## August 2023

### Defender for Identity release 2.213

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.212

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.211

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### New sensor type for Active Directory Certificate Services (AD CS)

Defender for Identity now supports the new **ADCS** sensor type for a dedicated server with Active Directory Certificate Services (AD CS) configured.

You'll see the new sensor type identified in the **Settings > Identities > Sensors** page in Microsoft 365 Defender. For more information, see [Manage and update Microsoft Defender for Identity sensors](sensor-settings.md#sensor-details).

Together with the new sensor type, Defender for Identity also now provides related AD CS alerts and Secure Score reports. To view the new alerts and Secure Score reports, make sure that the required events are being collected and logged on your server. For more information, see configure event collection [For Active Directory Certificate Services (AD CS) events](configure-windows-event-collection.md#for-active-directory-certificate-services-ad-cs-events).


AD CS is a Windows Server role that issues and manages public key infrastructure (PKI) certificates in secure communication and authentication protocols. For more information, see [What is Active Directory Certificate Services?](/windows-server/identity/ad-cs/active-directory-certificate-services-overview)

### Defender for Identity release 2.210

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## July 2023

### Defender for Identity release 2.209

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Search for Active Directory groups in Microsoft 365 Defender (Preview)

The Microsoft 365 Defender global search now supports searching by Active Directory group name. Any groups found are shown in the results on a separate **Groups** tab. Select an Active Directory group from your search results to see more details, including:

:::row:::
   :::column span="":::
      - Type
      - Scope
      - Domain
      - SAM name
      - SID
   :::column-end:::
   :::column span="":::
      - Group creation time
      - The first time an activity by the group was observed
      - Groups that contain the selected group
      - A list of all group members
   :::column-end:::
:::row-end:::

For example:

:::image type="content" source="media/whats-new/group-search.png" alt-text="Screenshot of the Groups tab in the Microsoft 365 Defender global search." lightbox="media/whats-new/group-search.png":::

For more information, see [Microsoft Defender for Identity in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi?bc=/defender-for-identity/breadcrumb/toc.json&toc=/defender-for-identity/TOC.json).

### New security posture reports

Defender for Identity's identity security posture assessments proactively detect and recommend actions across your on-premises Active Directory configurations.

The following new security posture assessments are now available in Microsoft Secure Score:

- [Do not expire passwords](security-assessment-do-not-expire-passwords.md)
- [Remove access rights on suspicious accounts with the Admin SDHolder permission](security-assessment-remove-suspicious-access-rights.md)
- [Manage accounts with passwords more than 180 days old](security-assessment-old-passwords.md)
- [Remove non-admin accounts with DCSync permissions](security-assessment-non-admin-accounts-dcsync.md)
- [Remove local admins on identity assets](security-assessment-remove-local-admins.md)
- [Start your Defender for Identity deployment](security-assessment-deploy-defender-for-identity.md)

For more information, see [Microsoft Defender for Identity's security posture assessments](security-assessment.md).

### Automatic redirection for the classic Defender for Identity portal

The Microsoft Defender for Identity portal experience and functionality have been converged into Microsoft’s extended detection and response (XDR) platform, Microsoft 365 Defender. As of July 6, 2023, customers using the classic Defender for Identity portal are automatically redirected to Microsoft 365 Defender, with no option to revert back to the classic portal.

For more information, see our [blog post](https://techcommunity.microsoft.com/t5/microsoft-365-defender-blog/leveraging-the-convergence-of-microsoft-defender-for-identity-in/ba-p/3856321) and [Microsoft Defender for Identity in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi).

### Defender for Identity report downloads and scheduling in Microsoft 365 Defender (Preview)

Now you can download and schedule periodic Defender for Identity reports from the Microsoft 365 Defender portal, creating parity in report functionality with the legacy[classic Defender for Identity portal](classic-reports.md).

Download and schedule reports in Microsoft 365 Defender from the **Settings > Identities > Report management** page. For example:

:::image type="content" source="media/whats-new/report-management.png" alt-text="Screenshot of the Report management page." lightbox="media/whats-new/report-management.png":::

For more information, see [Microsoft Defender for Identity reports in Microsoft 365 Defender](reports.md).

### Defender for Identity release 2.208

- This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.207

- This version provides the new **AccessKeyFile** installation parameter. Use the **AccessKeyFile** parameter during a silent installation of a Defender for Identity sensor, to set the workspace Access Key from a provided text path. For more information, see [Install the Microsoft Defender for Identity sensor](install-sensor.md#defender-for-identity-sensor-silent-installation).

- This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## June 2023

### Defender for Identity release 2.206

- This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Advanced hunting with an enhanced IdentityInfo table

- For tenants with Defender for Identity deployed, the Microsoft 365 **IdentityInfo** advanced hunting table now includes more attributes per identity, as well as identities detected by the Defender for Identity sensor from your on-premises environment.

For more information, see the [Microsoft 365 Defender advanced hunting documentation](/microsoft-365/security/defender/advanced-hunting-identityinfo-table).

### Defender for Identity release 2.205

- This version includes improvements and bug fixes for internal sensor infrastructure.

## May 2023

### Enhanced Active Directory account control highlights

The Microsoft 365 Defender **Identity** > user details page now includes new Active Directory account control data.

On the user details **Overview** tab, we've added the new **Active Directory account controls** card to highlight important security settings and Active directory controls. For example, use this card to learn whether a specific user is able to bypass password requirements or has a password that never expires.

For example:

:::image type="content" source="media/whats-new/uac-flags.png" alt-text="Screenshot of the UAC flags card on a user details page.":::

For more information, see the [User-Account-Control attribute](/windows/win32/adschema/a-useraccountcontrol) documentation.

### Defender for Identity release 2.204

Released May 29, 2023

- New health alert for VPN (radius) integration data ingestion failures. For more information, see [Microsoft Defender for Identity sensor health alerts](health-alerts.md#radius-accounting-vpn-integration-data-ingestion-failures).

- This version includes improvements and bug fixes for internal sensor infrastructure.

### Defender for Identity release 2.203

Released May 15, 2023

- New health alert for verifying that ADFS Container Auditing is configured correctly. For more information, see [Microsoft Defender for Identity sensor health alerts](health-alerts.md#auditing-on-the-adfs-container-is-not-enabled-as-required).

- The Microsoft Defender 365 **Identity** page includes UI updates for the lateral movement path experience. No functionality was changed. For more information, see [Understand and investigate Lateral Movement Paths (LMPs) with Microsoft Defender for Identity](understand-lateral-movement-paths.md).

- This version includes improvements and bug fixes for internal sensor infrastructure.

### Identity timeline enhancements

The identity **Timeline** tab now contains new and enhanced features! With the updated timeline, you can now filter by *Activity type*, *Protocol*, and *Location*, in addition to the original filters. You can also export the timeline to a CSV file and find additional information about activities associated with MITRE ATT&CK techniques. For more information, see [Investigate users in Microsoft 365 Defender](/microsoft-365/security/defender/investigate-users).

### Alert tuning in Microsoft 365 Defender

Alert tuning, now available in Microsoft 365 Defender, allows you to adjust your alerts and optimize them. Alert tuning reduces false positives, allows your SOC teams to focus on high-priority alerts, and improves threat detection coverage across your system.

In Microsoft 365 Defender, create rule conditions based on evidence types, and then apply your rule on any rule type that matches your conditions. For more information, see [Tune an alert](/microsoft-365/security/defender/investigate-alerts#public-preview-tune-an-alert).

## April 2023

### Defender for Identity release 2.202

Released April 23, 2023

- New health alert for verifying that Directory Services Configuration Container Auditing is configured correctly, as described in the [health alerts page](health-alerts.md#auditing-on-the-configuration-container-is-not-enabled-as-required).
- New workspaces for AD tenants mapped to New Zealand are created in the Australia East region. For the most current list of regional deployment, see [Defender for Identity components](architecture.md#defender-for-identity-components).
- Version includes improvements and bug fixes for internal sensor infrastructure.


## March 2023

### Defender for Identity release 2.201

Released March 27, 2023

- We're in the process of disabling the SAM-R honeytoken alert. While these types of accounts should never be accessed or queried, certain legacy systems may use these accounts as part of their regular operations. If this functionality is necessary for you, you can always create an advanced hunting query and use it as a custom detection. We're also reviewing the LDAP honeytoken alert over the coming weeks, but remains functional for now.

- We fixed detection logic issues in the [Directory Services Object Auditing health alert](health-alerts.md#directory-services-object-auditing-is-not-enabled-as-required) for non-English operating systems, and for Windows 2012 with Directory Services schemas earlier than version 87.

- We removed the prerequisite of configuring a Directory Services account for the sensors to start. For more information, see [Supported DSA account options](deploy/directory-service-accounts.md#supported-dsa-account-options).

- We no longer require logging 1644 events. If you have this registry setting enabled, you can remove it. For more information, see [Event ID 1644](deploy/configure-windows-event-collection.md#configure-auditing-for-extra-ldap-queries). <!--looks like we removed this-->

- Version includes improvements and bug fixes for internal sensor infrastructure.

### Defender for Identity release 2.200

Released March 16, 2023

- Version includes improvements and bug fixes for internal sensor infrastructure.

### Defender for Identity release 2.199

Released March 5, 2023

- Some exclusions for the **Honeytoken was queried via SAM-R** alert weren't functioning properly. In these instances, alerts were being triggered even for excluded entities. This error has now been fixed.

- **Updated NTLM protocol name for the Identity Advanced Hunting tables**: The old protocol name `Ntlm` is now listed as the new protocol name `NTLM` in Advanced Hunting Identity tables: IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents.
If you're currently using the `Ntlm` protocol in case-sensitive format from the Identity event tables, you should change it to `NTLM`.

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Next steps

- [What is Microsoft Defender for Identity?](what-is.md)
- [Frequently asked questions](technical-faq.yml)
- [Defender for Identity prerequisites](deploy/prerequisites.md)
- [Defender for Identity capacity planning](deploy/capacity-planning.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
