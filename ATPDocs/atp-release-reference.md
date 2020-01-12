---
# required metadata

title: Reference of older releases in Azure Advanced Threat Protection (Azure ATP) | Microsoft Docs
description: This article is a reference of previous releases updates to Azure Advanced Threat Protection (Azure ATP).
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 11/17/2019
ms.topic: reference
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection



# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: ort
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Release reference of Azure Advanced Threat Protection (Azure ATP) 

This article is a reference of all Azure ATP releases until (and including) release 2.55. For recent Azure ATP release updates (2.56 and newer), see [Azure ATP what's new](atp-whats-new.md).


## Azure ATP release 2.55
Released November 18, 2018

- **Security Alert: Suspicious communication over DNS - general availability**<br>
Azure ATP’s [Suspicious communication over DNS](suspicious-activity-guide.md) security alert is now in general availability. <br> Typically, the DNS protocol in most organizations is not monitored, and rarely blocked for malicious activity. This enables an attacker on a compromised machine to abuse the DNS protocol. Malicious communication over DNS can be used for data exfiltration, command, and control, and/or evading corporate network restrictions.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.54
Released November 11, 2018

- **Feature enhancement: Default domain exclusions added to Suspicious Communication over DNS alert**<br>	New addition of three popular domains to the default domain exclusion list. The exclusion list remains fully customizable. See [Excluding entities from detections](excluding-entities-from-detections.md), to learn more. 

- **Documentation enhancements: SIEM log update, Known Issues guidance**<br>	externalId mapping and additional explanations were added to SIEM log descriptions. See [SIEM log reference](cef-format-sa.md), to learn more. <br>Additional article for currently unresolved Known Issues guidance was added. See, [Azure ATP Known Issues](known-issues.md), to learn more.  

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.53
Released November 4, 2018

- **Security Alert enhancement: Suspicious Authentication Failure**<br>
Azure ATP’s [Suspicious Authentication Failure security alert](suspicious-activity-guide.md) now includes monitoring for detection of password spray brute force attacks.
In a typical **password spray** attack, after successfully enumerating a list of valid users from the domain controller, attackers try ONE carefully crafted password against ALL of the known user accounts (one password to many accounts). When the initial password spray is not successful, they'll try again, utilizing a different carefully crafted password, normally after waiting 30 minutes between attempts. The wait time allows attackers to avoid triggering most time-based account lockout thresholds. Password spray has quickly become a favorite technique of both attackers and pen testers. Password spray attacks have proven to be effective at gaining an initial foothold in an organization, and for making subsequent lateral moves, trying to escalate privileges. 

- **Feature enhancement: Send a test Syslog message**<br>	New ability to send a test Syslog message during the SIEM setup process. See [Integrate with Syslog](setting-syslog.md), to learn more. 

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.52
Released October 28, 2018


- **Security Alert enhancement: Remote Code Execution Attempt**<br>
Azure ATP’s [Remote Code Execution Attempt security alert](suspicious-activity-guide.md) now includes monitoring for suspicious attempts to execute remote PowerShell code on your domain controllers. Remote PowerShell is a common method for executing valid administrative commands, but is often used maliciously in an attempt to run scripts on remote endpoints. 

- **Feature enhancement: Set report scheduling**
<br>You can now set a specific hour to schedule your Azure ATP reports using the [reports](reports.md#) function. 

- **Configuration addition: Tenant role-based access control (RBAC)**
<br>Configure the security roles of your tenant in Azure Active Directory (AAD) Admin Center directly from the new Admin link in the Azure ATP Portal. 

- **Revised documentation structure and content**
<br>Recent content changes to Azure ATP documentation include new articles providing a complete list of all Azure ATP monitored activities, activity filtering instructions, as well as a redesign of the documentation site structure for improved usability:
  - [Azure ATP monitored activities](monitored-activities.md) 
  - [Azure ATP activity filtering](atp-activities-search.md) 
  - [Azure ATP documentation](https://docs.microsoft.com/azure-advanced-threat-protection/)  

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.51
Released October 21, 2018

- You can now enable/disable **WD-ATP integration** from the Azure ATP portal [Configuration](integrate-wd-atp.md#how-to-integrate-azure-atp-with-windows-defender-atp) screen. (To access this functionality, the Azure ATP user must be a Global or Security Administrator on the AAD tenant).

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.50
Released October 14, 2018
- This version includes fixes and improvements for multiple issues.


## Azure ATP release 2.49
Released October 7, 2018
-	**New detections: Suspicious DNS Communication** (preview)<br>New detection added to help protects against suspicious DNS communication attacks:

    -	This detection helps detect attacks against the DNS protocol. In most organizations, the DNS protocol is not monitored and rarely blocked for malicious activity. Enabling an attacker on a compromised machine to abuse the DNS protocol. Malicious communication over DNS can be used for data exfiltration, command and control, and/or evading corporate network restrictions.

- **New functionality** <br>Azure ATP **user role** enhanced with the following capabilities:
  - Change status of security alerts (reopen, close, exclude, suppress)
  - Set scheduled reports
  - Set entity tags (sensitive and honey token)
  - Exclusion of detection
  - Change language
  - Set notifications via email or syslog


- A temporary increase in **Reconnaissance using directory services queries** security alerts that occurred on September 16, 2018 was identified and resolved. 

- This version also includes fixes and improvements for multiple issues.


## Azure ATP release 2.48
Released September 16, 2018
- **Security alert:** Reconnaissance using directory services queries

  This security alert now has improved informational graphics and evidence. 

- **Exclude entities from detections** 

  To reduce false positives, you can now choose to exclude entities from the following detections: 
  - Suspicious VPN connection (user exclusion)
  - Suspicious domain controller promotion (potential DcShadow attack)
  - Suspicious replication request (potential DcShadow attack)

- This version also includes fixes and improvements for multiple issues.


## Azure ATP release 2.47
Released September 2, 2018

- **Azure ATP Advanced Audit Policy Check**
 
Azure Advanced Threat Protection now checks your domain controller’s existing Advanced Audit Policies and recommends policy changes to provide maximum Azure ATP service coverage for your organization. 

**This new check enables you to:**
  -  Identify events missing from your Windows Event logs that are currently excluded from your Azure ATP coverage.
  -  Verify ideal settings and make changes based on the health alert recommendations provided.
  -  A single aggregated health alert will be issued for all of your domain controllers including remediation suggestions (if/as needed).

Review how to [Configure Advanced Audit Policies](atp-advanced-audit-policy.md) to ensure your system is configured correctly. 
- This version also includes fixes and improvements for multiple issues.

## Azure ATP release 2.46

Released August 26, 2018

- This version includes fixes and improvements for multiple issues.

## Azure ATP release 2.45

Released August 19, 2018

- **Azure ATP adds Event Tracing for Windows (ETW) as an additional data source**  <br> 
Event Tracing for Windows (ETW) added as additional data source in addition to existing network traffic and Windows events. ETW provides additional suspicious activity detections, including: suspicious domain controller promotions and suspicious domain controller replication requests (both are potential DCShadow attacks). <br>
Only ATP sensors installed on domain controllers support ETW based detections. ETW detections are not supported by ATP standalone sensors. <br>  

- **Four new detections now in general availability** <br>
  - Suspicious VPN connection
  - Kerberos Golden Ticket – nonexistent account 
  - Suspicious domain controller promotion (potential DcShadow attack) – ETW based detection, only available with ATP sensors 
  - Suspicious domain controller replication request (potential DcShadow attack) – ETW based detection, only available with ATP sensors

- This version also includes fixes and improvements for multiple issues.


## Azure ATP release 2.44

Released August 12, 2018

- This version includes fixes and improvements for multiple issues.
- Log files created on the sensor machine no longer include the "Exception Statistic" log.


## Azure ATP release 2.43

Released August 5, 2018

- This version includes fixes and improvements for multiple issues.



## Azure ATP release 2.42

Released July 29, 2018

- This version includes fixes and improvements for multiple issues. 


## Azure ATP release 2.41

Released July 22, 2018

- **Azure ATP multi-forest support is being gradually rolled out (preview)** <br> Azure ATP can now support organizations with multiple forests that give you the ability monitor activity and profile users across forests. This new capability enables you to:

  -	View and investigate activities performed by users across multiple forests from a single pane of glass.
  - Improves detection and reduces false positives by providing advanced Active Directory integration and account resolution.
  -	Get better monitoring alerts and reporting for cross-org coverage.


-	**New detections: DCShadow**<br>Two new detections were added to help protect against domain controller shadow (DCShadow) attacks:

    -	Suspicious domain controller promotion (potential DCShadow attack) – This detection helps detect attacks in which a machine impersonate a domain controller and then tries to use replication to propagate changes to other domain controllers in your domain.

    -	Suspicious replication request (potential DCShadow attack) – This detection helps protect against attacks that attempt to perform DC promotion of machines that are not domain controllers in order to change directory objects.

-	**Improved encryption downgrade information**<br>Encryption downgrade detection now provides more information regarding the specific type of attack detected: overpass-the-hash, golden ticket, and skeleton key. In addition, these alerts have been aggregated to enable easier investigation.
- This version includes fixes and improvements for multiple issues. 


## Azure ATP release 2.40

Released July 15, 2018

- The pass-the-ticket detection now includes an evidence section in the alert details page. This provides additional information for investigating the alert.

- User access control flags, that can be found in a user's profile under Directory data, now include a legend so you can better understand which attributes are on and which are off.  

## Azure ATP release 2.39

Released July 5, 2018
-	**New detection added: Kerberos golden ticket - nonexistent account** (preview)<br>This new detection helps you protect your organization from attacks in which a golden ticket is created for an account that does not exist in your domain. For more information, see the [Azure Advanced Threat Protection suspicious activity guide](suspicious-activity-guide.md)

- This version includes fixes and improvements for multiple issues. 


## Azure ATP release 2.38

Released July 1, 2018

- This version includes fixes and improvements for multiple issues as well as enhancements of the Azure ATP portal.

## Azure ATP release 2.37

Released June 24, 2018

- This version includes fixes and improvements for multiple issues. 

## Azure ATP release 2.36

Released June 17, 2018

- This version includes fixes and improvements for multiple issues. 


## Azure ATP release 2.35

Released June 10, 2018
 
- **New preview detections**<br></br>From now on, Azure ATP will take advantage of the fact that it's a cloud service -- where new features can be delivered in fast cycles -- and provide you with new detections as quickly as possible. These new detections will be tagged as "preview" when they are first released. Usually a new detection will move from preview to general availability within a few weeks. By default you will see preview detections. For information about opting out, see [preview detections](working-with-suspicious-activities.md#preview-detections).
 
- **Suspicious VPN detection**<br></br>This release introduces a preview version of the Suspicious VPN detection. Azure ATP learns user VPN behavior, including the machines the users signed in to and the locations the users connect from, and alerts you when there is a deviation from the expected behavior. For more information, see [Suspicious VPN detection](suspicious-activity-guide.md).

- **Delayed update**<br></br>You now have the option to set Azure ATP sensors to update at a later time, each time Azure ATP updates. You can now set each Azure ATP sensor to **Delayed update** so that it will update 24 hours after the Azure ATP cloud service updates. This feature enables you to test the update on specific test sensors and only update your production sensors later on. If you discover an issue during the first update cycle, open a support ticket. For more information see [Update Azure ATP sensors](sensor-update.md).

- **Updated unusual protocol implementation detection**<br></br>The unusual protocol implementation detection now provides more information. You can now see which potential attack tool Azure ATP suspects is at work on your network. For more information, see the [Suspicious activity guide](suspicious-activity-guide.md).
 
- **Outdated sensor alert**<br></br>Azure ATP includes a new monitoring alert to let you know if a sensor is more than three versions outdated. If you see this alert, you should update the sensor, or investigate why the sensor isn't updating automatically. If the alert recurs, uninstall and reinstall the sensor.

- This version includes fixes and improvements for multiple issues. 

## Azure ATP release 2.34

Released June 3, 2018
 
- This version includes fixes and improvements for multiple issues. 

 
## Azure ATP release 2.33

Released May 27, 2018

- Preview feature: Azure ATP now supports new languages, and 13 new locales:
    - Czech
    - Hungarian
    - Italian
    - Korean
    - Dutch
    - Polish
    - Portuguese (Brazil)
    - Portuguese (Portugal)
    - Russia
    - Swedish
    - Turkish
    - Chinese (China)
    - Chinese (Taiwan)


## Azure ATP release 2.32

Released May 13, 2018
 
- This version includes fixes and improvements for multiple issues. 

## Azure ATP release 2.31

Released May 6, 2018
 
- Improvements were made to name resolution. As part of this effort, in addition to the RPC and NetBIOS active resolution, the sensor may issue a TLS Client Hello packet to the endpoint RDP port (3389). 
- This version includes fixes and improvements for multiple issues. 

## Azure ATP release 2.30

Released April 29, 2018
 
- Encryption downgrade suspicious activities now include an evidence section which describes the symptoms detected by Azure ATP that cause it to suspect that an encryption downgrade activity transpired. 
-	Azure ATP now uses Azure Email Orchestrator for all emails sent from Azure ATP, including suspicious activities, monitoring alerts and reports. You will see that these email notifications now follow a consistent format for ease-of-use and Excel files will be linked to from the email to be downloaded from the console.
 
 
## Azure ATP release 2.29

Released April 22, 2018
 
- This version includes fixes and improvements for multiple issues. 
 
 
## Azure ATP release 2.28

Released April 15, 2018
 
-	Users who are members of the role groups Azure ATP Users and Azure ATP Viewers now have permissions to see monitoring alerts.
- This version includes fixes and improvements for multiple issues. 


## Azure ATP release 2.27

Released April 8, 2018

- You now have the ability to provide user feedback from the top navigation bar. Clicking the smiley face in the menu bar enables you to send an email to the Azure Advanced Threat Protection team with your feedback.

- This version includes fixes and improvements for multiple issues. 
 

## Azure ATP release 2.26

Released March 25, 2018

- When Azure ATP alerts you of a suspicious activity that you identify as a benign positive (a legitimate action that is not a suspicious activity) you have the option to exclude computers and IP addresses for more detections, including: Encryption downgrade, LDAP brute force, Forged PAC, Brute force and Pass-the-hash.
-	The Azure ATP sensor performance was improved.
-	A new region was added for Workspace deployment, you can now deploy a workspace in Asia. 


## Azure ATP release 2.25

Released March 18, 2018

- Multi-factor authentication (MFA) is now supported in Azure ATP. Tenants using MFA can now enter the Azure ATP portal.
- Azure ATP now has a [**System status**](https://health.atp.azure.com/) page to provide you with information as to whether the Workspace management portal is up and active, if there are issues with detections and if the Sensor is able to send traffic to the cloud. You can access the **System status** from the Azure ATP menu bar.


## Azure ATP release 2.24

Released March 11, 2018

**New & updated detections**
  -	Suspicious service creation – Attackers attempt to run suspicious services on your network. Azure ATP now raises an alert when it identifies that someone on a specific computer is running a new service that seems suspicious. This detection is based on events (not network traffic) and is detected on any domain controller in your network that is forwarding event 7045 to Azure ATP. For more information see the [Suspicious activity guide](suspicious-activity-guide.md).

**Improved investigation**
  -	Azure ATP includes an enriched [entity profile](entity-profiles.md). The entity profile provides you with a platform that is designed for deep-dive investigation of user activities This includes the resources they accessed, computers they logged onto, and many more. The entity profile also provides directory data and enables you to identify potential lateral movement paths to or from the entity, enabling you to learn more about the potential breaches in your organization.

  -	ATP enables you to manually tag entities as *sensitive* to enhance detections and monitoring. This tagging impacts many Azure ATP detections, such as sensitive group modification detection and [lateral movement path](use-case-lateral-movement-path.md), which rely on entities that are considered sensitive.

**New reports to help you investigate**
  -	The [Passwords exposed in clear text report](reports.md) enables you to detect when services send account credentials are sent in plain text. This allows you to investigate services and improve your network security level. This report replaces the cleartext suspicious activity alerts.
  -	The [Lateral movement paths to sensitive accounts report](reports.md) lists the sensitive accounts that are exposed via lateral movement paths. This enables you to mitigate these paths and harden your network to minimize the attack surface risk. This enables you to prevent lateral movement so that attackers can't move across your network between users and computers until they hit the virtual security jackpot: your sensitive admin account credentials.

- You can now easily access the documentation from a link provide within a suspicious activity alert in order to view [investigation steps that you can take](suspicious-activity-guide.md). 

**Performance improvements**
 -	The Azure ATP sensor infrastructure was improved for performance: the aggregated view of traffic enables optimization of CPU and packet pipeline, and reuses sockets to the domain controllers to minimize SSL sessions to the DC.

## See Also
- [What is Azure Advanced Threat Protection?](what-is-atp.md)
- [Frequently asked questions](atp-technical-faq.md)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
