---
title: What's new | Microsoft Defender for Identity
description: This article is updated frequently to let you know what's new in the latest release of Microsoft Defender for Identity.
ms.date: 06/18/2024
ms.topic: overview
#CustomerIntent: As a Defender for Identity customer, I want to know what's new in the latest release of Defender for Identity, so that I can take advantage of new features and functionality. 
---

# What's new in Microsoft Defender for Identity

This article is updated frequently to let you know what's new in the latest releases of Microsoft Defender for Identity.

[!INCLUDE [automatic-redirect](../includes/automatic-redirect.md)]

## What's new scope and references

Defender for Identity releases are deployed gradually across customer tenants. If there's a feature documented here that you don't see yet in your tenant, check back later for the update.

For more information, see also:

- [What's new in Microsoft Defender XDR](/microsoft-365/security/defender/whats-new)
- [What's new in Microsoft Defender for Endpoint](/microsoft-365/security/defender-endpoint/whats-new-in-microsoft-defender-endpoint)
- [What's new in Microsoft Defender for Cloud Apps](/cloud-app-security/release-notes)

For updates about versions and features released six months ago or earlier, see the [What's new archive for Microsoft Defender for Identity](whats-new-archive.md).

## June 2024

### Easily Go Hunt For user Information From the ITDR Dashboard

The Shield Widget provides a quick overview of the number of users in hybrid, cloud, and on-premises environments. This feature now includes direct links to the Advanced Hunting platform, offering detailed user information at your fingertips.

### ITDR Deployment Health Widget Now Include Entra Conditional Access and Entra Private Access 

Now you can view the license availability for Entra Workload Conditional Access, Entra User Conditional Access, and Entra Private Access.

### Defender for Identity release 2.237

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## May 2024

### Defender for Identity release 2.236

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.235

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## April 2024

### Easily detect CVE-2024-21427 Windows Kerberos Security Feature Bypass Vulnerability

To help customers better identify and detect attempts to bypass security protocols according to [this vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21427), we have added a new activity within Advanced Hunting that monitors Kerberos AS authentication.   
With this data customers can now easily create their own [custom detection rules within Microsoft Defender XDR](https://aka.ms/CustomDetectionsDocs) and automatically trigger alerts for this type of activity

Access Defender XDR portal -> Hunting -> Advanced Hunting.

Now, you can copy our recommended query as provided below, and click on “Create detection rule”. Please be aware that our provided query also tracks failed logon attempts, which may generate information unrelated to a potential attack. Therefore, feel free to customize the query to suit your specific requirements.


```
IdentityLogonEvents
| where Application == "Active Directory"
| where Protocol == "Kerberos"
| where LogonType in("Resource access", "Failed logon")
| extend Error =  AdditionalFields["Error"]
| extend KerberosType = AdditionalFields['KerberosType']
| where KerberosType == "KerberosAs"
| extend Spns = AdditionalFields["Spns"]
| extend DestinationDC = AdditionalFields["TO.DEVICE"]
| where  Spns !contains "krbtgt" and Spns !contains "kadmin"
| project Timestamp, ActionType, LogonType, AccountUpn, AccountSid, IPAddress, DeviceName, KerberosType, Spns, Error, DestinationDC, DestinationIPAddress, ReportId

```

### Defender for Identity release 2.234

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.233

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## March 2024

### New read-only permissions for viewing Defender for Identity settings

Now you can configure Defender for Identity users with read-only permissions to view Defender for Identity settings. 

For more information, see [Required permissions Defender for Identity in Microsoft Defender XDR](role-groups.md#required-permissions-defender-for-identity-in-microsoft-defender-xdr).

### New Graph based API for viewing and managing Health issues

Now you can view and manage Microsoft Defender for Identity health issues through the Graph API

For more information, see [Managing Health issues through Graph API](/graph/api/resources/security-healthissue?view=graph-rest-beta&preserve-view=true).

### Defender for Identity release 2.232

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.231

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## February 2024

### Defender for Identity release 2.230

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### New security posture assessment for insecure AD CS IIS endpoint configuration

Defender for Identity has added the new **Edit insecure ADCS certificate enrollment IIS endpoints (ESC8)** recommendation in Microsoft Secure Score.

Active Directory Certificate Services (AD CS) supports certificate enrollment through various methods and protocols, including enrollment via HTTP using the Certificate Enrollment Service (CES) or the Web Enrollment interface (Certsrv). Insecure configurations of the CES or Certsrv IIS endpoints might create vulnerabilities to relay attacks (ESC8).

The new **Edit insecure ADCS certificate enrollment IIS endpoints (ESC8)** recommendation is added to other AD CS-related recommendations recently released. Together, these assessments offer security posture reports that surface security issues and severe misconfigurations that post risks to the entire organization, together with related detections.

For more information, see:

- [Security assessment: Edit insecure ADCS certificate enrollment IIS endpoints (ESC8)](security-assessment-insecure-adcs-certificate-enrollment.md)
- [Security posture assessments for AD CS sensors](#security-posture-assessments-for-ad-cs-sensors-preview)
- [Microsoft Defender for Identity's security posture assessments](security-assessment.md)

### Defender for Identity release 2.229

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Enhanced user experience for adjusting alert thresholds (Preview)

The Defender for Identity **Advanced Settings** page is now renamed to **Adjust alert thresholds** and provides a refreshed experience with enhanced flexibility for adjusting alert thresholds.

:::image type="content" source="media/whats-new/adjust-alert-thresholds.png" alt-text="Screenshot of the new Adjust alert thresholds page." lightbox="media/whats-new/adjust-alert-thresholds.png":::

Changes include:

- We've removed the previous **Remove learning period** option, and added a new **Recommended test mode** option. Select **Recommended test mode** to set all threshold levels to **Low**, increasing the number of alerts, and sets all other threshold levels to read-only.

- The previous **Sensitivity level** column is now renamed as **Threshold level**, with newly defined values. By default, all alerts are set to a **High** threshold, which represents the default behavior and a standard alert configuration.

The following table lists the mapping between the previous **Sensitivity level** values and the new **Threshold level** values:

|Sensitivity level (previous name) |Threshold level (new name) |
|---------|---------|
|**Normal**     |  **High**       |
|**Medium**      |  **Medium**       |
|**High**      |  **Low**       |

If you had specific values defined on the **Advanced Settings** page, we've transferred them to the new **Adjust alert thresholds** page as follows:

|Advanced settings page configuration  |New Adjust alert thresholds page configuration  |
|---------|---------|
|**Remove learning period** toggled on     |  **Recommended test mode** toggled off. <br><br> Alert threshold configuration settings remain the same.       |
|**Remove learning period** toggled off      |  **Recommended test mode** toggled off. <br><br> Alert threshold configuration settings are all reset to their default values, with a **High** threshold level.   |

Alerts are always triggered immediately if the **Recommended test mode** option is selected, or if a threshold level is set to **Medium** or **Low**, regardless of whether the alert's learning period has already completed.

For more information, see [Adjust alert thresholds](advanced-settings.md).

### Device details pages now include device descriptions (Preview)

Microsoft Defender XDR now includes device descriptions on device details panes and device details pages. The descriptions are populated from the device's Active Directory [Description](/windows/win32/adschema/a-description) attribute.

For example, on the device details side pane:

:::image type="content" source="media/whats-new/device-description.png" alt-text="Screenshot of the new Device description field on a device details pane." lightbox="media/whats-new/device-description.png":::

For more information, see [Investigation steps for suspicious devices](investigate-assets.md#investigation-steps-for-suspicious-devices).

### Defender for Identity release 2.228

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor, and the following new alerts:

- [Account Enumeration reconnaissance (LDAP) (external ID 2437)](reconnaissance-discovery-alerts.md#account-enumeration-reconnaissance-ldap-external-id-2437-preview) (Preview)
- [Directory Services Restore Mode Password Change (external ID 2438)](other-alerts.md#directory-services-restore-mode-password-change-external-id-2438) (Preview)

## January 2024

### Defender for Identity release 2.227

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Timeline tab added for group entities

Now you can view Active Directory group entity-related activities and alerts from the last 180 days in Microsoft Defender XDR, such as group membership changes, LDAP queries and so on.

To access the group timeline page, select **Open timeline** on the group details pane.



For example:

:::image type="content" source="media/whats-new/group-timeline.png" alt-text="Screenshot of the Open timeline button on a group entity details pane." lightbox="media/whats-new/group-timeline.png":::

For more information, see [Investigation steps for suspicious groups](investigate-assets.md#investigation-steps-for-suspicious-groups).

### Configure and validate your Defender for Identity environment via PowerShell

Defender for Identity now supports the new *DefenderForIdentity* PowerShell module, which is designed to help you configure and validate your environment for working with Microsoft Defender for Identity.

Using the PowerShell commands to avoid misconfigurations and save time and avoiding unnecessary load on your system.

We added the following procedures to the Defender for Identity documentation to help you use the new PowerShell commands:

- [Change proxy configuration using PowerShell](configure-proxy.md#change-proxy-configuration-using-powershell)
- [Configure, get, and test audit policies using PowerShell](configure-windows-event-collection.md#configure-get-and-test-audit-policies-using-powershell)
- [Generate a report with current configurations via PowerShell](configure-windows-event-collection.md#generate-a-report-with-current-configurations-via-powershell)
- [Test your DSA permissions and delegations via PowerShell](directory-service-accounts.md#test-your-dsa-permissions-and-delegations-via-powershell)
- [Test service connectivity using PowerShell](deploy/test-connectivity.md#test-service-connectivity-using-powershell)

For more information, see:

- [DefenderForIdentity PowerShell module (PowerShell Gallery)](https://www.powershellgallery.com/packages/DefenderForIdentity/)
- [DefenderForIdentity PowerShell reference documentation](/powershell/defenderforidentity/overview-defenderforidentity)

### Defender for Identity release 2.226

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.225

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## December 2023

> [!NOTE]
> If you're seeing a decreased number of *Remote code execution attempt* alerts, see our updated [September announcements](#september-2023), which include an [update to the Defender for Identity detection logic](#decreased-number-of-alerts-for-remote-code-execution-attempts). Defender for Identity continues to record the remote code execution activities as before.

### New Identities area and dashboard in Microsoft 365 Defender  (Preview)

Defender for Identity customers now have a new **Identities** area in Microsoft 365 Defender for information about identity security with Defender for Identity.

In Microsoft 365 Defender, select **Identities** to see any of the following new pages:

- **Dashboard**: This page shows graphs and widgets to help you monitor identity threat detection and response activities.  For example:

   :::image type="content" source="media/dashboard/dashboard.gif" alt-text="An animated GIF showing a sample ITDR Dashboard page.":::

   For more information, see [Work with Defender for Identity's ITDR dashboard](dashboard.md).

- **Health issues**: This page is moved from the **Settings > Identities** area, and lists any current health issues for your general Defender for Identity deployment and specific sensors. For more information, see [Microsoft Defender for Identity sensor health issues](health-alerts.md).

- **Tools**: This page contains links to helpful information and resources when working with Defender for Identity. On this page, find links to documentation, specifically on the [capacity planning tool](capacity-planning.md), and the [*Test-MdiReadiness.ps1*](https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness) script.

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

- **Summary report**: The summary report is updated to include two new columns in the *Health issues* tab:

    -	Details: Additional information on the issue, such as a list of impacted objects or specific sensors on which the issue occurs.
    -	Recommendations: A list of recommended actions that can be taken to resolve the issue, or how to investigate the issue further.

    For more information, see [Download and schedule Defender for Identity reports in Microsoft Defender XDR (Preview)](reports.md).

- **Health issues**: Added the *The 'Remove learning period' toggle was automatically switched off for this tenant* health issue

This version also includes bug fixes for cloud services and the Defender for Identity sensor.

### Defender for Identity release 2.216

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

## September 2023

### Decreased number of alerts for Remote Code Execution Attempts

To better align Defender for Identity and Microsoft Defender for Endpoint alerts, we updated the detection logic for the Defender for Identity [Remote code execution attempt](other-alerts.md#remote-code-execution-attempt-external-id-2019) detections. 

While this change results in a decreased number of *Remote code execution attempt* alerts, Defender for Identity continues to record the remote code execution activities. Customers can continue to build their own [advanced hunting queries](/microsoft-365/security/defender/advanced-hunting-overview) and create [custom detection policies](/microsoft-365/security/defender/custom-detection-rules). 

### Alert sensitivity settings and learning period enhancements

Some Defender for Identity alerts wait for a *learning period* before alerts are triggered, while building a profile of patterns to use when distinguishing between legitimate and suspicious activities.

Defender for Identity now provides the following enhancements for the learning period experience:

- Administrators can now use the **Remove learning period** setting to configure the sensitivity used for specific alerts. Define the sensitivity as *Normal* to configure the **Remove learning period** setting as *Off* for the selected type of alert. 

- After you deploy a new sensor in a new Defender for Identity workspace, the **Remove learning period** setting is automatically turned *On* for 30 days. When 30 days are complete, the **Remove learning period** setting is automatically turned *Off,* and alert sensitivity levels are returned to their default functionality.

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

Defender for Identity added the **Go hunt** button for groups in Microsoft Defender XDR. Users can use the **Go hunt** button to query for group-related activities and alerts during an investigation.

For example:

:::image type="content" source="media/whats-new/go-hunt-groups.png" alt-text="Screenshot of the new Go hunt button on a group details pane.":::

For more information, see [Quickly hunt for entity or event information with go hunt](/microsoft-365/security/defender/advanced-hunting-go-hunt).

### Defender for Identity release 2.214

This version includes improvements and bug fixes for cloud services and the Defender for Identity sensor.

### Performance enhancements

Defender for Identity made internal improvements for latency, stability, and performance when transferring real-time events from Defender for Identity services to Microsoft Defender XDR. Customers should expect no delays in Defender for Identity data appearing in Microsoft Defender XDR, such as alerts or activities for advanced hunting.


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

## Next steps

- [What is Microsoft Defender for Identity?](what-is.md)
- [Frequently asked questions](technical-faq.yml)
- [Defender for Identity prerequisites](prerequisites.md)
- [Defender for Identity capacity planning](capacity-planning.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
