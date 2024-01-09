---
title: What's new | Microsoft Defender for Identity
description: This article is updated frequently to let you know what's new in the latest release of Microsoft Defender for Identity.
ms.date: 12/27/2023
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

- [What's new in Microsoft Defender XDR](/microsoft-365/security/defender/whats-new)
- [What's new in Microsoft Defender for Endpoint](/microsoft-365/security/defender-endpoint/whats-new-in-microsoft-defender-endpoint)
- [What's new in Microsoft Defender for Cloud Apps](/cloud-app-security/release-notes)

For updates about versions and features released six months ago or earlier, see the [What's new archive for Microsoft Defender for Identity](whats-new-archive.md).
## January 2024

### Defender for Identity release 2.225

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## December 2023

> [!NOTE]
> If you're seeing a decreased number of *Remote code execution attempt* alerts, see our updated [September announcements](#september-2023), which include an [update to the Defender for Identity detection logic](#decreased-number-of-alerts-for-remote-code-execution-attempts). Defender for Identity continues to record the remote code execution activities as before.

### New Identities area and dashboard in Microsoft 365 Defender  (Preview)

Defender for Identity customers now have a new **Identities** area in Microsoft 365 Defender for information about identity security with Defender for Identity.

In Microsoft 365 Defender, select **Identities** to see any of the following new pages:

- **Dashboard**:  Shows graphs and widgets to help you monitor identity threat detection and response activities.  For example:

   :::image type="content" source="media/dashboard/dashboard.gif" alt-text="An animated GIF showing a sample ITDR Dashboard page.":::

   For more information, see [Work with Defender for Identity's ITDR dashboard](dashboard.md).

- **Health issues**: Now moved from the **Settings > Identities** area, and lists any current health issues for your general Defender for Identity deployment and specific sensors. For more information, see [Microsoft Defender for Identity sensor health issues](health-alerts.md).

- **Tools**: Links to helpful information and resources when working with Defender for Identity, including links to documentation, specifically on the [capacity planning tool](capacity-planning.md), and the [*Test-MdiReadiness.ps1*](https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness) script.

### Defender for Identity release 2.224

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Security posture assessments for AD CS sensors (Preview)

Defender for Identity's security posture assessments proactively detect and recommend actions across your on-premises Active Directory configurations. 

Recommended actions now include the following new security posture assessments, specifically for certificate templates and certificate authorities.

- **Certificate templates recommended actions**:

   - [Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1)](security-assessment-prevent-users-request-certificate.md)
   - [Edit overly permissive certificate template with privileged EKU (Any purpose EKU or No EKU) (ESC2)](security-assessment-edit-overly-permissive-template.md)
   - [Misconfigured enrollment agent certificate template (ESC3)](security-assessment-edit-misconfigured-enrollment-agent.md)
   - [Edit misconfigured certificate templates ACL (ESC4)](security-assessment-edit-misconfigured-acl.md)
   - [Edit misconfigured certificate templates owner (ESC4)](security-assessment-edit-misconfigured-owner.md)

- **Certificate authority recommended actions**:

   - [Edit vulnerable Certificate Authority setting (ESC6)](security-assessment-edit-vulnerable-ca-setting.md)
   - [Edit misconfigured Certificate Authority ACL (ESC7)](security-assessment-edit-misconfigured-ca-acl.md)
   - [Enforce encryption for RPC certificate enrollment interface (ESC8)](security-assessment-enforce-encryption-rpc.md)

The new assessments are available in Microsoft Secure Score, surfacing security issues and severe misconfigurations that pose risks to the entire organization, alongside detections. Your score is updated accordingly.

For example:

:::image type="content" source="media/secure-score/adcs-new-reports.png" alt-text="Screenshot of the new AD CS security posture assessments.":::

For more information, see [Microsoft Defender for Identity's security posture assessments](security-assessment.md).

> [!NOTE]
> While *certificate template* assessments are available to all customers that have AD CS installed on their environment, *certificate authority* assessments are available only to customers who've installed a sensor on an AD CS server. For more information, see [New sensor type for Active Directory Certificate Services (AD CS)](#new-sensor-type-for-active-directory-certificate-services-ad-cs).

### Defender for Identity release 2.223

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.222

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.221

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## November 2023

### Defender for Identity release 2.220

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.219

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Identity timeline includes more than 30 days of data (Preview)

Defender for Identity is gradually rolling out extended data retentions on identity details to more than 30 days. 

The identity details page **Timeline** tab, which includes activities from Defender for Identity, Microsoft Defender for Cloud Apps, and Microsoft Defender for Endpoint, currently includes a minimum of 150 days and is growing. There might be some variation in data retention rates over the next few weeks.

To view activities and alerts on the identity timeline within a specific time frame, select the default **30 Days** and then select **Custom range**. Filtered data from more than 30 days ago is shown for a maximum of seven days at a time.

For example:

:::image type="content" source="media/whats-new/custom-time-frame.png" alt-text="Screenshot of the custom time frame options." lightbox="media/whats-new/custom-time-frame.png":::

For more information, see [Investigate assets](investigate-assets.md) and [Investigate users in Microsoft Defender XDR](/microsoft-365/security/defender/investigate-users).

### Defender for Identity release 2.218

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## October 2023

### Defender for Identity release 2.217

This version includes the following improvements:

- **Summary report**: The summary report has been updated to include two new columns in the *Health issues* tab:

    -	Details: Additional information on the issue, such as a list of impacted objects or specific sensors on which the issue occurs.
    -	Recommendations: A list of recommended actions that can be taken to resolve the issue, or how to investigate the issue further.

    For more information, see [Download and schedule Defender for Identity reports in Microsoft Defender XDR (Preview)](reports.md).

- **Health issues**: Added the [The 'Remove learning period' toggle was automatically switched off for this tenant](health-alerts.md#the-remove-learning-period-toggle-was-automatically-switched-off-for-this-tenant) issue

This version also includes bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.216

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## September 2023

### Decreased number of alerts for Remote Code Execution Attempts

To better align Defender for Identity and Microsoft Defender for Endpoint alerts, we've updated the detection logic for the Defender for Identity [Remote code execution attempt](other-alerts.md#remote-code-execution-attempt-external-id-2019) detections. 

While this change results in a decreased number of *Remote code execution attempt* alerts, Defender for Identity continues to record the remote code execution activities. Customers can continue to build their own [advanced hunting queries](/microsoft-365/security/defender/advanced-hunting-overview) and create [custom detection policies](/microsoft-365/security/defender/custom-detection-rules). 

### Alert sensitivity settings and learning period enhancements

Some Defender for Identity alerts wait for a *learning period* before alerts are triggered, while building a profile of patterns to use when distinguishing between legitimate and suspicious activities.

Defender for Identity now provides the following enhancements for the learning period experience:

- Administrators can now use the **Remove learning period** setting to configure the sensitivity used for specific alerts. Define the sensitivity as *Normal* to configure the **Remove learning period** setting as *Off* for the selected type of alert. 

- After deploying a new sensor in a new Defender for Identity workspace, the **Remove learning period** setting is automatically turned *On* for 30 days. When 30 days are complete, the **Remove learning period** setting is automatically turned *Off,* and alert sensitivity levels are returned to their default functionality.

   To have Defender for Identity use standard learning period functionality, where alerts aren't generated until the learning period is done, configure the **Remove learning periods** setting to *Off*.

If you'd previously updated the **Remove learning period** setting, your setting remains as you'd configured it.

For more information, see [Advanced settings](advanced-settings.md).

> [!NOTE]
> The **Advanced Settings** page originally listed the *Account enumeration reconnaissance* alert under the **Remove learning period** options as configurable for sensitivity settings. This alert was removed from the list and is replaced by the *Security principal reconnaissance (LDAP)* alert. This user interface bug was fixed in November 2023.
>

### Defender for Identity release 2.215

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity reports moved to the main Reports area

Now you can access Defender for Identity reports from Microsoft Defender XDR's main **Reports** area instead of the **Settings** area. For example:

:::image type="content" source="media/whats-new/reports-main-area.png" alt-text="Screenshot of the Defender for Identity report access from the main Reports area.":::

For more information, see [Download and schedule Defender for Identity reports in Microsoft Defender XDR (Preview)](reports.md).

### Go hunt button for groups in Microsoft Defender XDR

Defender for Identity has added the **Go hunt** button for groups in Microsoft Defender XDR. Users can use the **Go hunt** button to query for group-related activities and alerts during an investigation.

For example:

:::image type="content" source="media/whats-new/go-hunt-groups.png" alt-text="Screenshot of the new Go hunt button on a group details pane.":::

For more information, see [Quickly hunt for entity or event information with go hunt](/microsoft-365/security/defender/advanced-hunting-go-hunt).

### Defender for Identity release 2.214

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Performance enhancements

Defender for Identity has made internal improvements for latency, stability, and performance when transferring real-time events from Defender for Identity services to Microsoft Defender XDR. Customers should expect no delays in Defender for Identity data appearing in Microsoft Defender XDR, such as alerts or activities for advanced hunting.


For more information, see:

- [Security alerts in Microsoft Defender for Identity](alerts-overview.md)
- [Microsoft Defender for Identity's security posture assessments](security-assessment.md)
- [Proactively hunt for threats with advanced hunting in Microsoft Defender XDR](/microsoft-365/security/defender/advanced-hunting-overview)

## August 2023

### Defender for Identity release 2.213

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.212

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.211

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### New sensor type for Active Directory Certificate Services (AD CS)

Defender for Identity now supports the new **ADCS** sensor type for a dedicated server with Active Directory Certificate Services (AD CS) configured.

You see the new sensor type identified in the **Settings > Identities > Sensors** page in Microsoft Defender XDR. For more information, see [Manage and update Microsoft Defender for Identity sensors](sensor-settings.md#sensor-details).

Together with the new sensor type, Defender for Identity also now provides related AD CS alerts and Secure Score reports. To view the new alerts and Secure Score reports, make sure that the required events are being collected and logged on your server. For more information, see [Configure auditing for Active Directory Certificate Services (AD CS) events](configure-windows-event-collection.md#configure-auditing-for-active-directory-certificate-services-ad-cs).

AD CS is a Windows Server role that issues and manages public key infrastructure (PKI) certificates in secure communication and authentication protocols. For more information, see [What is Active Directory Certificate Services?](/windows-server/identity/ad-cs/active-directory-certificate-services-overview)

### Defender for Identity release 2.210

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## July 2023

### Defender for Identity release 2.209

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Search for Active Directory groups in Microsoft Defender XDR (Preview)

The Microsoft Defender XDR global search now supports searching by Active Directory group name. Any groups found are shown in the results on a separate **Groups** tab. Select an Active Directory group from your search results to see more details, including:

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

:::image type="content" source="media/whats-new/group-search.png" alt-text="Screenshot of the Groups tab in the Microsoft Defender XDR global search." lightbox="media/whats-new/group-search.png":::

For more information, see [Microsoft Defender for Identity in Microsoft Defender XDR](/microsoft-365/security/defender/microsoft-365-security-center-mdi?bc=/defender-for-identity/breadcrumb/toc.json&toc=/defender-for-identity/TOC.json).

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

The Microsoft Defender for Identity portal experience and functionality have been converged into Microsoft’s extended detection and response (XDR) platform, Microsoft Defender XDR. As of July 6, 2023, customers using the classic Defender for Identity portal are automatically redirected to Microsoft Defender XDR, with no option to revert back to the classic portal.

For more information, see our [blog post](https://techcommunity.microsoft.com/t5/microsoft-365-defender-blog/leveraging-the-convergence-of-microsoft-defender-for-identity-in/ba-p/3856321) and [Microsoft Defender for Identity in Microsoft Defender XDR](/microsoft-365/security/defender/microsoft-365-security-center-mdi).

### Defender for Identity report downloads and scheduling in Microsoft Defender XDR (Preview)

Now you can download and schedule periodic Defender for Identity reports from the Microsoft Defender portal, creating parity in report functionality with the legacy [classic Defender for Identity portal](classic-reports.md).

Download and schedule reports in Microsoft Defender XDR from the **Settings > Identities > Report management** page. For example:

:::image type="content" source="media/whats-new/report-management.png" alt-text="Screenshot of the Report management page." lightbox="media/whats-new/report-management.png":::

For more information, see [Microsoft Defender for Identity reports in Microsoft Defender XDR](reports.md).

### Defender for Identity release 2.208

- This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.207

- This version provides the new **AccessKeyFile** installation parameter. Use the **AccessKeyFile** parameter during a silent installation of a Defender for Identity sensor, to set the workspace Access Key from a provided text path. For more information, see [Install the Microsoft Defender for Identity sensor](install-sensor.md#defender-for-identity-sensor-silent-installation).

- This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## June 2023

### Defender for Identity release 2.206

- This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Advanced hunting with an enhanced IdentityInfo table

- For tenants with Defender for Identity deployed, the Microsoft 365 **IdentityInfo** advanced hunting table now includes more attributes per identity, and identities detected by the Defender for Identity sensor from your on-premises environment.

For more information, see the [Microsoft Defender XDR advanced hunting documentation](/microsoft-365/security/defender/advanced-hunting-identityinfo-table).

### Defender for Identity release 2.205

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Next steps

- [What is Microsoft Defender for Identity?](what-is.md)
- [Frequently asked questions](technical-faq.yml)
- [Defender for Identity prerequisites](prerequisites.md)
- [Defender for Identity capacity planning](capacity-planning.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
