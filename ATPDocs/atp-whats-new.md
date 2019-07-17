---
# required metadata

title: What's new in Azure Advanced Threat Protection (Azure ATP) | Microsoft Docs
description: Describes the latest releases of Azure ATP and provides information about what's new in each version.
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 07/14/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 7d0f33db-2513-4146-a395-290e001f4199


# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: ort
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# What's new in Azure ATP

## Azure ATP release 2.86 

Released July 14, 2019

- **New security alert: Suspected NTLM authentication tampering (external ID 2039) – (preview)**<br>
Azure ATP’s new [Suspected NTLM authentication tampering](atp-lateral-movement-alerts.md#suspected-ntlm-authentication-tampering-external-id-2039---preview) security alert is now in public preview. <br> In this detection, an Azure ATP security alert is triggered when use of "man-in-the-middle" attack is suspected of successfully bypassing NTLM Message Integrity Check (MIC), a security vulnerability detailed in Microsoft [CVE-2019-040](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1040). These types of attacks attempt to downgrade NTLM security features and successfully authenticate, with the ultimate goal of making successful lateral movements. 

- **Feature enhancement: TcP FingerPrint**<br> Until now, Azure ATP provided entity device operating system (OS) information based on the available attribute in Active Directory. Previously, if OS information was unavailable in Active Directory, it was also unavailable on device pages. Starting from this version, Azure ATP now also provides this information for devices for which Active Directory(AD) doesn't have the information, or that are not registered in AD, by using TCP fingerprints. 
 
    Azure ATP now evaluates and determines the device OS based on network traffic. For devices that don't have an OS attribute in AD, or are not registered, if the OS was evaluated by TCP fingerprint, this information is now provided on the device page under the device name. This additional data helps identify unregistered and non-Windows devices, while aiding in your investigation process. For learn more about investigating using Azure ATP, see [investigate a computer](investigate-a-computer.md).  

- **New feature: Authenticated proxy -preview**<br> Azure ATP now supports authenticated proxy. Specify the proxy URL using the sensor command line and  specify Username/Password to use proxies that require authentication. For more information about authenticated proxy, see [Configure the proxy](https://docs.microsoft.com/azure-advanced-threat-protection/configure-proxy#configure-the-proxy).

- **Feature enhancement: Automated domain synchronizer process**<br> The process of designating and tagging domain controllers as domain synchronizer candidates during setup and ongoing configuration is now fully automated. The toggle option to select a domain controller as a domain synchronizer candidate is removed. 

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.85

Released July 7, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.84

Released July 1, 2019

- **New location support: Azure UK data center**<br>
    Azure ATP instances are now supported in the Azure UK data center. To learn more about creating Azure ATP instances and their corresponding data center locations, see [Step 1 of Azure ATP installation](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step10).

- **Feature enhancement: New name and features for the Suspicious additions to sensitive groups alert (external ID 2024)**<br> 
    The **Suspicious additions to sensitive groups** alert was previously named the **Suspicious modifications to sensitive groups** alert. The external ID of the alert (ID 2024) remains the same. The descriptive name change more accurately reflects the purpose of alerting on additions to your **sensitive** groups. The enhanced alert also features new evidence and improved descriptions. For more information, see [Suspicious additions to sensitive groups](https://docs.microsoft.com/azure-advanced-threat-protection/atp-domain-dominance-alerts#suspicious-additions-to-sensitive-groups-external-id-2024).  

- **New documentation feature: Guide for moving from Advanced Threat Analytics to Azure ATP**<br>
    This new article includes prerequisites, planning guidance, as well as configuration and verification steps for moving from ATA to Azure ATP service. For more information, see [Move from ATA to Azure ATP](https://docs.microsoft.com/azure-advanced-threat-protection/ata-atp-move-overview).   

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.83

Released June 23, 2019

- **Feature enhancement: Suspicious service creation alert (external ID 2026)**<br> 
    This alert now features an improved alert page with additional evidence and a new description. For more information, see [Suspicious service creation security alert](https://docs.microsoft.com/azure-advanced-threat-protection/atp-domain-dominance-alerts#suspicious-service-creation-external-id-2026).

-  **Instance naming support: Support added for digit only domain prefix**<br>
    Support added for Azure ATP instance creation using initial domain prefixes that only contain digits. For example, use of digit only initial domain prefixes such as  123456.contoso.com are now supported. 

- This version also includes improvements and bug fixes for internal sensor infrastructure.


## Azure ATP release 2.82

Released June 18, 2019

- **New public preview**<br>
Azure ATP's identity threat investigation experience is now in **Public Preview**, and available to all Azure ATP protected tenants. See [Azure ATP Microsoft Cloud App Security investigation experience](atp-mcas-integration.md) to learn more. 

- **General availability**<br>
Azure ATP support for untrusted forests is now in general availability. See [Azure ATP multi-forest](atp-multi-forest.md) to learn more. 

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.81

Released June 10, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.80

Released June 2, 2019

- **Feature enhancement: Suspicious VPN connection alert**<br>
   This alert now includes enhanced evidence and texts for better usability. For more information about alert features, and suggested remediation steps and prevention, see the [Suspicious VPN connection alert description](atp-compromised-credentials-alerts.md#suspicious-vpn-connection-external-id-2025).

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.79
Released May 26, 2019

- **General availability: Security principal reconnaissance (LDAP) (external ID 2038)**

    This alert is now in GA (general availability). For more information about the alert,  alert features and suggested remediation and prevention, see the [Security principal reconnaissance (LDAP) alert description](atp-reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038)

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.78

Released May 19, 2019

- **Feature enhancement: Sensitive entities**<br> Manual Sensitive tagging for Exchange Servers

    You can now manually tag entities as Exchange Servers during configuration.

    To manually tag an entity as an Exchange Server:
    1. In the Azure ATP portal, access the **Configuration** menu.
    2. Under **Detection**, select **Entity tags**, then select **Sensitive**.
    3. Select **Exchange Servers** and then add the entity you wish to tag.

    After tagging a computer as an Exchange Server, it will be tagged as Sensitive and display that it was tagged as an Exchange Server.  The Sensitive tag will appear in the computer’s entity profile, and the computer will be considered in all detections that are based on Sensitive accounts and Lateral Movement Paths.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.77

Released May 12, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.76

Released May 6, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.75

Released April 28, 2019

- **Feature enhancement: Sensitive entities**<br> Starting from this version (2.75), machines identified as Exchange Servers by Azure ATP are now automatically tagged as **Sensitive**.  

    Entities that are automatically tagged as **Sensitive** because they function as Exchange Servers list this classification as the reason they are tagged. 

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.74

Releasing April 14, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.73

Releasing April 10, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.72

Released March 31, 2019

- **Feature enhancement: Lateral Movement Path (LMP) scoped depth**<br>
Lateral movement paths (LMPs) are a key method for threat and risk discovery in Azure ATP. To help keep focus on the critical risks to your most sensitive users, this update makes it easier and faster to analyze and remediate risks to the sensitive users on each LMP, by limiting the scope and depth of each graph displayed.   

    See [Lateral Movement Paths](use-case-lateral-movement-path.md) to learn more about how Azure ATP uses LMPs to surface access risks to each entity in your environment.   

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.71

Released March 24, 2019

- **Feature enhancement: Network Name Resolution (NNR) monitoring alerts**<br>
Monitoring alerts were added for confidence levels associated with Azure ATP security alerts that are based on NNR. Each monitoring alert includes actionable and detailed recommendations to help resolve low NNR success rates. 

    See [What is Network Name Resolution](atp-nnr-policy.md) to learn more about how Azure ATP uses NNR and why it's important for alert accuracy. 

- **Server support: Support added for Server 2019 with use of KB4487044**<br>
Support added for use of Windows Server 2019, with a patch level of KB4487044. Use of Server 2019 without the patch is not supported, and is blocked starting from this update. 

- **Feature enhancement: User-based alert exclusion**<br>
Extended alert exclusion options now allow for excluding specific users from specific alerts. Exclusions can help avoid situations where use or configuration of certain types of internal software repeatedly triggered benign security alerts.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.70
Released March 17, 2019

- **Feature enhancement: Network Name Resolution (NNR) confidence level added to multiple alerts**<br> Network Name Resolution or (NNR) is used to help positively identify the source entity identity of suspected attacks. By adding the NNR confidence levels to Azure ATP alert evidence lists, you can now instantly assess and understand the level of NNR confidence related to the possible sources identified, and remediate appropriately. 

    NNR confidence level evidence was added to the following alerts:
  - [Network mapping reconnaissance (DNS)](atp-reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007)
  - [Suspected identity theft (pass-the-ticket)](atp-lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018) 
  - [Suspected NTLM relay attack (Exchange account) - preview](atp-lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037---preview)
  - [Suspected DCSync attack (replication of directory services)](atp-domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006)

- **Additional health alert scenario: Azure ATP sensor service failed to start**<br>In instances where the Azure ATP sensor failed to start due to a network capturing driver issue, a sensor health alert is now triggered. [Troubleshooting Azure ATP sensor with Azure ATP logs](troubleshooting-atp-using-logs.md) for more information about Azure ATP logs and how to use them. 
  
- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.69
Released March 10, 2019

- **Feature enhancement: Suspected identity theft (pass-the-ticket) alert**<br> This alert now features new evidence showing the details of connections made by using remote desktop protocol (RDP). The added evidence makes it easy to remediate the known issue of (B-TP) Benign-True Positive alerts caused by use of Remote Credential Guard over RDP connections. 

- **Feature enhancement: Remote code execution over DNS alert**<br> 
This alert now features new evidence showing your domain controller security update status, informing you when updates are required.   

- **New documentation feature: Azure ATP Security alert MITRE ATT&CK Matrix™**<br>

    To explain and make it easier to map the relationship between Azure ATP security alerts and the familiar MITRE ATT&CK Matrix, we've added the relevant MITRE techniques to Azure ATP security alert listings. This additional reference makes it easier to understand the suspected attack technique potentially in use when an Azure ATP security alert is triggered. Learn more about the [Azure ATP security alert guide](suspicious-activity-guide.md).  

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.68
Released March 3, 2019

- **Feature enhancement: Suspected brute force attack (LDAP) alert**<br>
Significant usability improvements were made to this security alert including a revised description, provision of additional source information, and guess attempt details for faster remediation. 
Learn more about [Suspected brute force attack (LDAP)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-ldap-external-id-2004) security alerts. 

- **New documentation feature: Security alert lab**<br>

    To explain the power of Azure ATP in detecting the real threats to your working environment, we've added a new **Security alert lab** to this documentation. The **Security alert lab** helps you quickly set up a lab or testing environment, and explains the best defensive posturing against common, real-world threats and attacks.  

    The [step-by-step lab](atp-playbook-lab-overview.md) is designed to ensure you spend minimal time building, and more time learning about your threat landscape and available Azure ATP alerts and protection. We're excited to hear your feedback.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.67
Released February 24, 2019

- **New security alert: Security principal reconnaissance (LDAP) – (preview)**<br>

    Azure ATP’s [Security principal reconnaissance (LDAP) - preview](atp-reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038) security alert is now in public preview. <br> In this detection, an Azure ATP security alert is triggered when security principal reconnaissance is used by attackers to gain critical information about the domain environment. This information helps attackers map the domain structure, as well as identify privileged accounts for use in later steps in their attack kill chain. 

    Lightweight Directory Access Protocol (LDAP) is one the most popular methods used for both legitimate and malicious purposes to query Active Directory. LDAP focused security principal reconnaissance is commonly used as the first phase of a Kerberoasting attack. Kerberoasting attacks are used to get a target list of Security Principal Names (SPNs), which attackers then attempt to get Ticket Granting Server (TGS) tickets for.

- **Feature enhancement: Account enumeration reconnaissance (NTLM) alert** <br> 
    Improved **Account enumeration reconnaissance (NTLM)** alert using additional analysis, and improved detection logic to reduce **B-TP** and **FP** alert results. 
 
- **Feature enhancement: Network mapping reconnaissance (DNS) alert** <br>
    New types of detections added to Network mapping reconnaissance (DNS) alerts. In addition to detecting suspicious AXFR requests, Azure ATP now detects suspicious types of requests originating from non-DNS servers using an excessive number of requests.

 - This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.66
Released February 17, 2019

- **Feature enhancement: Suspected DCSync attack (replication of directory services) alert**<br>
Usability improvements were made to this security alert including a revised description, provision of additional source information, new infographic, and more evidence. 
Learn more about [Suspected DCSync attack (replication of directory services)](atp-domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006) security alerts. 

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.65
Released February 10, 2019

- **New security alert: Suspected NTLM relay attack (Exchange account) – (preview)**<br>
Azure ATP’s [Suspected NTLM relay attack (Exchange account) - preview](atp-lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037---preview) security alert is now in public preview. <br> In this detection, an Azure ATP security alert is triggered when use of Exchange account credentials from a suspicious source is identified. These types of attacks attempt to leverage NTLM relay techniques to gain domain controller exchange privileges and are known as **ExchangePriv**. Learn more about the **ExchangePriv** technique from the [ADV190007 advisory](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV190007) first published January 31, 2019, and the [Azure ATP alert response](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/How-to-win-the-latest-security-race-over-NTLM-relay/ba-p/334511).  

- **General availability: Remote code execution over DNS**<br>
This alert is now in GA (general availability). For more information and alert features, see the [Remote code execution over DNS alert description page](atp-lateral-movement-alerts.md#remote-code-execution-over-dns-external-id-2036). 

- **General availability: Data exfiltration over SMB**<br>
This alert is now in GA (general availability). For more information and alert features, see the [Data exfiltration over SMB alert description page](atp-exfiltration-alerts.md#data-exfiltration-over-smb-external-id-2030).


- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.64
Released February 4, 2019

- **General availability: Suspected Golden Ticket usage (ticket anomaly)**<br>
This alert is now in GA (general availability). For more information and alert features, see the [Suspected Golden Ticket usage (ticket anomaly) alert description page](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-external-id-2032). 

- **Feature enhancement: Network mapping reconnaissance (DNS)**<br>
Improved alert detection logic deployed for this alert to minimize false-positives and alert noise. This alert now has a learning period of eight days before the alert will possibly trigger for the first time. For more information about this alert, see [Network mapping reconnaissance (DNS) alert description page](atp-reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007). 

    **Due to the enhancement of this alert, the nslookup method should no longer be used to test Azure ATP connectivity during initial configuration.** 

- **Feature enhancement:**<br>
This version includes redesigned alert pages, and new evidence, providing better alert investigation. 
    - [Suspected brute force attack (SMB)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-smb-external-id-2033)
    - [Suspected Golden Ticket usage (time anomaly) alert description page](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-time-anomaly-external-id-2022)
    - [Suspected overpass-the-hash attack (Kerberos)](atp-lateral-movement-alerts.md#suspected-overpass-the-hash-attack-kerberos-external-id-2002)
    - [Suspected use of Metasploit hacking framework](atp-compromised-credentials-alerts.md#suspected-use-of-metasploit-hacking-framework-external-id-2034)
    - [Suspected WannaCry ransomware attack](atp-compromised-credentials-alerts.md#suspected-wannacry-ransomware-attack-external-id-2035)

- This version also includes improvements and bug fixes for internal sensor infrastructure.


## Azure ATP release 2.63
Released January 27, 2019

- **New feature: Untrusted forest support – (preview)**<br>
Azure ATP’s support for sensors in untrusted forests is now in public preview. 
From the Azure ATP portal **Directory services** page, configure additional sets of credentials to enable Azure ATP sensors to connect to different Active Directory forests, and report back to the Azure ATP service. See [Azure ATP multi-forest](atp-multi-forest.md) to learn more. 

- **New feature: Domain controller coverage**<br>
Azure ATP now provides coverage information for Azure ATP monitored domain controllers.  
From the Azure ATP portal **Sensors** page, view the number of the monitored and unmonitored domain controllers detected by Azure ATP in your environment. Download the monitored domain controller list for further analysis, and to build an action plan. See the [Domain controller monitoring](atp-sensor-monitoring.md) how-to guide to learn more. 

- **Feature enhancement: Account enumeration reconnaissance**<br>
The Azure ATP account enumeration reconnaissance detection now detects and issues alerts for enumeration attempts using Kerberos and NTLM. Previously, the detection only worked for attempts using Kerberos. See [Azure ATP reconnaissance alerts](atp-reconnaissance-alerts.md#account-enumeration-reconnaissance-external-id-2003) to learn more. 

- **Feature enhancement: Remote code execution attempt alert**<br>
    - All remote execution activities, such as service creation, WMI execution, and the new **PowerShell** execution, were added to the profile timeline of the destination machine. The destination machine is the domain controller the command was executed on. 
    - **PowerShell** execution was added to the list of remote code execution activities listed in the entity profile alert timeline.
    - See [Remote code execution attempt](atp-domain-dominance-alerts.md#remote-code-execution-attempt-external-id-2019) to learn more.  

- **Windows Server 2019 LSASS issue and Azure ATP**<br>
In response to customer feedback regarding Azure ATP usage with domain controllers running Windows Server 2019, this update includes additional logic to avoid triggering the reported behavior on Windows Server 2019 machines. Full support for Azure ATP sensor on Windows Server 2019 is planned for a future Azure ATP update, however installing and running Azure ATP on Windows Servers 2019 is **not** currently supported. See [Azure ATP sensor requirements](atp-prerequisites.md#azure-atp-sensor-requirements) to learn more. 

- This version also includes improvements and bug fixes for internal sensor infrastructure.


## Azure ATP release 2.62
Released January 20, 2019

- **New security alert: Remote code execution over DNS – (preview)**<br>
Azure ATP’s [Remote code execution over DNS](atp-lateral-movement-alerts.md#remote-code-execution-over-dns-external-id-2036) security alert is now in public preview. <br> In this detection, an Azure ATP security alert is triggered when DNS queries suspected of exploiting security vulnerability [CVE-2018-8626](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8626) are made against a domain controller in the network.

- **Feature Enhancement: 72 hour delayed sensor update** <br> Changed option to delay sensor updates on selected sensors to 72 hours (instead of the previous 24-hour delay) after each release update of Azure ATP. See [Azure ATP sensor update](sensor-update.md) for configuration instructions. 


- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.61
Released January 13, 2019

- **New Security Alert: Data exfiltration over SMB - (preview)**<br>
Azure ATP’s [Data exfiltration over SMB](atp-exfiltration-alerts.md) security alert is now in public preview. <br> Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, attackers can create a Kerberos ticket granting ticket (TGT) that provide authorization to any resource. 


- **Feature Enhancement: Remote code execution attempt** security alert <br> A new alert description and additional evidence were added to help make the alert easier to understand, and provide better investigation workflows. 


- **Feature Enhancement: DNS query logical activities** <br>Additional query types were added to [Azure ATP monitored activities](monitored-activities.md) including: **TXT**, **MX**, **NS**, **SRV**, **ANY**, **DNSKEY**. 

- **Feature Enhancement: Suspected Golden Ticket usage (ticket anomaly) and Suspected Golden Ticket usage (nonexistent account)** <br>
Improved detection logic has been applied to both alerts to reduce the number of FP alerts, and deliver more accurate results.

- **Feature Enhancement: Azure ATP Security Alert documentation** <br>
Azure ATP security alert documentation has been enhanced and expanded to include better alert descriptions, more accurate alert classifications, and explanations of evidence, remediation, and prevention. Get familiar with the new security alert documentation design using the following links: 
    - [Azure ATP Security Alerts](suspicious-activity-guide.md)
    - [Understanding security alerts](understanding-security-alerts.md)
        - [Reconnaissance phase alerts](atp-reconnaissance-alerts.md)
        - [Compromised credential phase alerts](atp-compromised-credentials-alerts.md)
        - [Lateral movement phase alerts](atp-lateral-movement-alerts.md)
        - [Domain dominance phase alerts](atp-domain-dominance-alerts.md)
        - [Exfiltration phase alerts](atp-exfiltration-alerts.md)
    - [Investigate a computer](investigate-a-computer.md)
    - [Investigate a user](investigate-a-user.md)

- This version also includes improvements and bug fixes for internal sensor infrastructure.


## Azure ATP release 2.60
Released January 6, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.59
Released December 16, 2018

- This version includes improvements and bug fixes for internal sensor infrastructure.


## Azure ATP release 2.58

Released December 9, 2018

- **Security Alert Enhancement: Unusual Protocol Implementation alert split**<br>
Azure ATP's series of Unusual Protocol Implementation security alerts that previously shared 1 externalId (2002), are now split into four distinctive alerts, with a corresponding unique external ID. 

### New alert externalIds

> [!div class="mx-tableFixed"] 

|New security alert name|Previous security alert name|Unique external ID|
|---------|----------|---------|
|Suspected brute force attack (SMB)|Unusual protocol implementation (potential use of malicious tools such as Hydra)|2033
|Suspected overpass-the-hash attack (Kerberos)|Unusual Kerberos protocol implementation (potential overpass-the-hash attack)|2002|
|Suspected use of Metasploit hacking framework|Unusual protocol implementation (potential use of Metasploit hacking tools)|2034
|Suspected WannaCry ransomware attack|Unusual protocol implementation (potential WannaCry ransomware attack)|2035
|

- **New monitored activity: File copy through SMB**<br>
Copying of files using SMB is now a monitored and filterable activity. Learn more about which [activities Azure ATP monitors](monitored-activities.md), and how to [filter and search monitored activities](atp-activities-search.md) in the portal. 

- **Large Lateral Movement Path image enhancement**<br>
When viewing large lateral movement paths, Azure ATP now highlights only the nodes connected to a selected entity,  instead of blurring the other nodes. This change introduces a significant improvement in large LMP rendering speed. 

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.57
Released December 2, 2018

- **New Security Alert: Suspected Golden ticket usage- ticket anomaly (preview)**<br>
Azure ATP’s [Suspected Golden Ticket usage - ticket anomaly](suspicious-activity-guide.md) security alert is now in public preview. <br> Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, attackers can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource. 
<br>This forged TGT is called a "Golden Ticket" because it allows attackers to achieve lasting network persistence. Forged Golden Tickets of this type have unique characteristics this new detection is designed to identify. 


- **Feature Enhancement: Automated Azure ATP instance (workspace) creation** <br>
From today, Azure ATP *workspaces* are renamed Azure ATP *instances*. Azure ATP now supports one Azure ATP instance per Azure ATP account. Instances for new customers are created using the instance creation wizard in the [Azure ATP portal](https://portal.atp.azure.com). Existing Azure ATP workspaces are converted automatically to Azure ATP instances with this update.  

  - Simplified instance creation for faster deployment and protection using [create your Azure ATP instance](install-atp-step1.md). 
  - All [data privacy and compliance](atp-privacy-compliance.md) remains the same. 

  To learn more about Azure ATP instances, see [Create your Azure ATP instance](install-atp-step1.md). 

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.56
Released November 25, 2018


- **Feature Enhancement: Lateral Movement Paths (LMPs)** <br>
Two additional features are added to enhance Azure ATP Lateral Movement Path (LMP) capabilities:

  - LMP history is now saved and discoverable per entity, and when using LMP reports. 
  - Follow an entity in an LMP via the activity timeline, and investigate using additional evidence provided for discovery of potential attack paths. 

  See [Azure ATP Lateral Movement Paths](use-case-lateral-movement-path.md) to learn more about how to use and investigate with enhanced LMPs. 

- **Documentation enhancements: Lateral Movement Paths, Security Alert names**<br> Additions and updates were made to Azure ATP articles describing Lateral Movement Path descriptions and features, name mapping was added for all instances of old security alert names to new names and externalIds. 
  - See [Azure ATP Lateral Movement Paths](use-case-lateral-movement-path.md), [Investigate  Lateral Movement Paths](investigate-lateral-movement-path.md), and [Security Alert Guide](suspicious-activity-guide.md) to learn more.   

- This version includes improvements and bug fixes for internal sensor infrastructure.

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

  This security alert now has improved infographics and evidence. 

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
