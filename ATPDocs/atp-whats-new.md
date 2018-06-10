---
# required metadata

title: What's new in Azure ATP | Microsoft Docs
description: Describes the latest releases of Azure ATP and provides information about what's new in each version.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 6/5/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 7d0f33db-2513-4146-a395-290e001f4199


# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*


# What's new in Azure ATP 

## Azure ATP release 2.35

Released June 10, 2018
 
- The Azure ATP research team constantly works on implementing new detections for newly discovered attacks. Because Azure ATP is a cloud service, it's possible to release these new detections quickly to enable Azure ATP customers to benefit from new detections as soon as possible. For more information about enabling and disabling preview detections, see [preview detections](working-with-suspicious-activities.md#preview-detections).
 
- This release introduces a preview version of the Suspicious VPN detection. Azure ATP learns user VPN behavior, including the machines the users signed in to and the locations the users connect from, and alerts you when there is a deviation from the expected behavior. For more information, see [Suspicious VPN detection](suspicious-activity-guide.md#suspicious-vpn-detection).
 
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
    - Portuguese (Brasil)
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
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)