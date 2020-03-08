---
# required metadata

title: What's new in Azure Advanced Threat Protection (Azure ATP) | Microsoft Docs
description: This article is updated frequently to let you know what's new in the latest release of Azure Advanced Threat Protection (Azure ATP).
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 03/01/2020
ms.topic: conceptual
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

# What's new in Azure Advanced Threat Protection (Azure ATP)

This article is updated frequently to let you know what's new in the latest releases of Azure ATP.

For details of earlier Azure ATP releases until (and including) release 2.55, see the [Azure ATP release reference](atp-release-reference.md).

RSS feed: Get notified when this page is updated by copying and pasting the following URL into your feed reader:   `https://docs.microsoft.com/api/search/rss?search=%22This+article+is+updated+frequently+to+let+you+know+what%27s+new+in+the+latest+release+of+Azure+ATP%22&locale=en-us`

## Azure ATP release 2.111

Released Mar 1, 2020

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.110

Released Feb 23, 2020

- **New security assessment: Unmonitored domain controllers**  
Azure ATP security assessments now includes a report on unmonitored domain controllers, servers without a sensor, to help you in managing full coverage of your environment. For more information, see [Unmonitored domain controllers](atp-cas-isp-unmonitored-domain-controller.md).

## Azure ATP release 2.109

Released Feb 16, 2020

- **Feature enhancement: Sensitive entities**  
Starting from this version (2.109), machines identified as Certificate Authority, DHCP, or DNS Servers by Azure ATP are now automatically tagged as **Sensitive**.

## Azure ATP release 2.108

Released Feb 9, 2020

- **New feature: Support for group Managed Service Accounts**  
Azure ATP now supports using group Managed Service Accounts (gMSA) for improved security when connecting Azure ATP sensors to your Azure Active Directory (AD) forests. For more information about using gMSA with Azure ATP sensors, see [Connect to your Active Directory Forest](install-atp-step2.md#prerequisites).

- **Feature enhancement: Scheduled report with too much data**  
When a scheduled report has too much data, the email now informs you of the fact by displaying the following text: There was too much data during the specified period to generate a report. This replaces the previous behavior of only discovering the fact after clicking the report link in the email.

- **Feature enhancement: Updated domain controller coverage logic**  
We've updated our domain controller coverage report logic to include additional information from Azure AD, resulting in a more accurate view of domain controllers without sensors on them. This new logic should also have a positive affect on the corresponding Microsoft Secure Score.

## Azure ATP release 2.107

Released Feb 3, 2020

- **New monitored activity: SID history change**  
SID history change is now a monitored and filterable activity. Learn more about which [activities Azure ATP monitors](monitored-activities.md), and how to [filter and search monitored activities](atp-activities-search.md) in the portal.

- **Feature enhancement: Closed or suppressed alerts are no longer reopened**  
Once an alert is closed or suppressed in the Azure ATP portal, if the same activity is detected again within a short period of time, a new alert is opened. Previously, under the same conditions, the alert was reopened.

- **TLS 1.2 required for portal access and sensors**  
TLS 1.2 is now required to use Azure ATP sensors and the cloud service. Access to the Azure ATP portal will no longer be possible using browsers that do not support TLS 1.2.

## Azure ATP release 2.106

Released Jan 19, 2020

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.105

Released Jan 12, 2020

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.104

Released Dec 23, 2019

- **Sensor version expirations eliminated**  
Azure ATP sensor deployment and sensor installation packages no longer expire after a number of versions and now only update themselves once. The result of this feature is that previously downloaded sensor installation packages can now be installed even if they are older than our max number of lapsed versions.

- **Confirm compromise**  
You can now confirm compromise of specific Office 365 users and set their risk level to **high**. This workflow allows your security operations teams another response capability to reduce their security incidents Time-To-Resolve thresholds. Learn more about [how to confirm compromise](https://docs.microsoft.com/cloud-app-security/tutorial-ueba?branch=pr-en-us-1204#phase-4-protect-your-organization) using Azure ATP and Cloud App Security.

- **New experience banner**  
On Azure ATP portal pages where a new experience is available in the Cloud App Security portal, new banners are displayed describing what's available with access links.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.103

Released Dec 15, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.102

Released Dec 8, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.101

Released Nov 24, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.100

Released Nov 17, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.99

Released November 3, 2019

- **Feature enhancement:  Added user interface notification of Cloud App Security portal availability to the Azure ATP portal**  
Ensuring all users are aware of the availability of the enhanced features available using the Cloud App Security portal, notification was added for the portal from the existing Azure ATP alert timeline.

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.98

Released October 27, 2019

- **Feature enhancement: Suspected brute force attack alert**  
Improved the [Suspected brute force attack (SMB)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-smb-external-id-2033) alert using additional analysis, and improved detection logic to reduce **benign true positive (B-TP)** and **false positive (FP)** alert results.

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.97

Released October 6, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.96

Released September 22, 2019

- **Enriched NTLM authentication data using Windows Event 8004**  
Azure ATP sensors are now able to automatically read and enrich the NTLM authentications activities with your accessed server data when NTLM auditing is enabled, and Windows Event 8004 is turned on. Azure ATP parses Windows Event 8004 for NTLM authentications in order to enrich the NTLM authentication data used for Azure ATP threat analysis and alerts. This enhanced capability provides resource access activity over NTLM data as well as enriched failed logon activities including the destination computer which the user attempted but failed to access.

    Learn more about NTLM authentication activities [using Windows Event 8004](configure-windows-event-collection.md#ntlm-authentication-using-windows-event-8004).

- Version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.95

Released September 15, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.94

Released September 8, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.93

Released September 1, 2019

-   ersion includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.92

Released August 25, 2019

-   ersion includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.91

Released August 18, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.90

Released August 11, 2019

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.89

Released August 4, 2019

- **Sensor method improvements**  
To avoid excess NTLM traffic generation in creation of accurate Lateral Movement Path (LMP) assessments, improvements have been made to Azure ATP sensor methods to rely less on NTLM usage and make more significant use of Kerberos.

- **Alert enhancement: Suspected Golden Ticket usage (nonexistent account)**  
SAM name changes have been added to the supporting evidence types listed in this type of alert. To learn more about the alert, including how to prevent this type of activity and remediate, see  [Suspected Golden Ticket usage (nonexistent account)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-nonexistent-account-external-id-2027).

- **General availability: Suspected NTLM authentication tampering**  
The [Suspected NTLM authentication tampering](atp-lateral-movement-alerts.md#suspected-ntlm-authentication-tampering-external-id-2039) alert is no longer in preview mode and is now generally available.

- Version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.88

Released July 28, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.87

Released July 21, 2019

- **Feature enhancement: Automated Syslog event collection for Azure ATP standalone sensors**  
Incoming Syslog connections for Azure ATP standalone sensors are now fully automated, while removing the toggle option from the configuration screen. These changes have no effect on outgoing Syslog connections.

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.86

Released July 14, 2019

- **New security alert: Suspected NTLM authentication tampering (external ID 2039)**  
Azure ATP's new [Suspected NTLM authentication tampering](atp-lateral-movement-alerts.md#suspected-ntlm-authentication-tampering-external-id-2039) security alert is now in public preview.    In this detection, an Azure ATP security alert is triggered when use of "man-in-the-middle" attack is suspected of successfully bypassing NTLM Message Integrity Check (MIC), a security vulnerability detailed in Microsoft [CVE-2019-040](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1040). These types of attacks attempt to downgrade NTLM security features and successfully authenticate, with the ultimate goal of making successful lateral movements.

- **Feature enhancement: Enriched device operating system identification**  
Until now, Azure ATP provided entity device operating system information based on the available attribute in Active Directory. Previously, if operating system information was unavailable in Active Directory, the information was also unavailable on Azure ATP entity pages. Starting from this version, Azure ATP now provides this information for devices where Active Directory doesn't have the information, or are not registered in Active Directory, by using enriched device operating system identification methods.

    The addition of enriched device operating system identification data helps identify unregistered and non-Windows devices, while simultaneously aiding in your investigation process. For learn more about Network Name Resolution in Azure ATP, see [Understanding Network Name Resolution (NNR)](atp-nnr-policy.md).  

- **New feature: Authenticated proxy - preview**  
Azure ATP now supports authenticated proxy. Specify the proxy URL using the sensor command line and specify Username/Password to use proxies that require authentication. For more information about how to use authenticated proxy, see [Configure the proxy](https://docs.microsoft.com/azure-advanced-threat-protection/configure-proxy#configure-the-proxy).

- **Feature enhancement: Automated domain synchronizer process**  
The process of designating and tagging domain controllers as domain synchronizer candidates during setup and ongoing configuration is now fully automated. The toggle option to manually select domain controllers as domain synchronizer candidates is removed.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.85

Released July 7, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.84

Released July 1, 2019

- **New location support: Azure UK data center**  
Azure ATP instances are now supported in the Azure UK data center. To learn more about creating Azure ATP instances and their corresponding data center locations, see [Step 1 of Azure ATP installation](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step10).

- **Feature enhancement: New name and features for the Suspicious additions to sensitive groups alert (external ID 2024)**  
The **Suspicious additions to sensitive groups** alert was previously named the **Suspicious modifications to sensitive groups** alert. The external ID of the alert (ID 2024) remains the same. The descriptive name change more accurately reflects the purpose of alerting on additions to your **sensitive** groups. The enhanced alert also features new evidence and improved descriptions. For more information, see [Suspicious additions to sensitive groups](https://docs.microsoft.com/azure-advanced-threat-protection/atp-domain-dominance-alerts#suspicious-additions-to-sensitive-groups-external-id-2024).  

- **New documentation feature: Guide for moving from Advanced Threat Analytics to Azure ATP**  
This new article includes prerequisites, planning guidance, as well as configuration and verification steps for moving from ATA to Azure ATP service. For more information, see [Move from ATA to Azure ATP](https://docs.microsoft.com/azure-advanced-threat-protection/ata-atp-move-overview).

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.83

Released June 23, 2019

- **Feature enhancement: Suspicious service creation alert (external ID 2026)**  
This alert now features an improved alert page with additional evidence and a new description. For more information, see [Suspicious service creation security alert](https://docs.microsoft.com/azure-advanced-threat-protection/atp-domain-dominance-alerts#suspicious-service-creation-external-id-2026).

- **Instance naming support: Support added for digit only domain prefix**  
Support added for Azure ATP instance creation using initial domain prefixes that only contain digits. For example, use of digit only initial domain prefixes such as  123456.contoso.com are now supported.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.82

Released June 18, 2019

- **New public preview**  
Azure ATP's identity threat investigation experience is now in **Public Preview**, and available to all Azure ATP protected tenants. See [Azure ATP Microsoft Cloud App Security investigation experience](atp-mcas-integration.md) to learn more.

- **General availability**  
Azure ATP support for untrusted forests is now in general availability. See [Azure ATP multi-forest](atp-multi-forest.md) to learn more.

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.81

Released June 10, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.80

Released June 2, 2019

- **Feature enhancement: Suspicious VPN connection alert**  
This alert now includes enhanced evidence and texts for better usability. For more information about alert features, and suggested remediation steps and prevention, see the [Suspicious VPN connection alert description](atp-compromised-credentials-alerts.md#suspicious-vpn-connection-external-id-2025).

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.79

Released May 26, 2019

- **General availability: Security principal reconnaissance (LDAP) (external ID 2038)**

    This alert is now in GA (general availability). For more information about the alert,  alert features and suggested remediation and prevention, see the [Security principal reconnaissance (LDAP) alert description](atp-reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038)

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.78

Released May 19, 2019

- **Feature enhancement: Sensitive entities**  
Manual Sensitive tagging for Exchange Servers

    You can now manually tag entities as Exchange Servers during configuration.

    To manually tag an entity as an Exchange Server:
    1. In the Azure ATP portal, access the **Configuration** menu.
    2. Under **Detection**, select **Entity tags**, then select **Sensitive**.
    3. Select **Exchange Servers** and then add the entity you wish to tag.

    After tagging a computer as an Exchange Server, it will be tagged as Sensitive and display that it was tagged as an Exchange Server.  The Sensitive tag will appear in the computer's entity profile, and the computer will be considered in all detections that are based on Sensitive accounts and Lateral Movement Paths.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.77

Released May 12, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.76

Released May 6, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.75

Released April 28, 2019

- **Feature enhancement: Sensitive entities**  
Starting from this version (2.75), machines identified as Exchange Servers by Azure ATP are now automatically tagged as **Sensitive**.  

    Entities that are automatically tagged as **Sensitive** because they function as Exchange Servers list this classification as the reason they are tagged.

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.74

Releasing April 14, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.73

Released April 10, 2019

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.72

Released March 31, 2019

- **Feature enhancement: Lateral Movement Path (LMP) scoped depth**  
Lateral movement paths (LMPs) are a key method for threat and risk discovery in Azure ATP. To help keep focus on the critical risks to your most sensitive users, this update makes it easier and faster to analyze and remediate risks to the sensitive users on each LMP, by limiting the scope and depth of each graph displayed.

    See [Lateral Movement Paths](use-case-lateral-movement-path.md) to learn more about how Azure ATP uses LMPs to surface access risks to each entity in your environment.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.71

Released March 24, 2019

- **Feature enhancement: Network Name Resolution (NNR) monitoring alerts**  
Monitoring alerts were added for confidence levels associated with Azure ATP security alerts that are based on NNR. Each monitoring alert includes actionable and detailed recommendations to help resolve low NNR success rates.

    See [What is Network Name Resolution](atp-nnr-policy.md) to learn more about how Azure ATP uses NNR and why it's important for alert accuracy.

- **Server support: Support added for Server 2019 with use of KB4487044**  
Support added for use of Windows Server 2019, with a patch level of KB4487044. Use of Server 2019 without the patch is not supported, and is blocked starting from this update.

- **Feature enhancement: User-based alert exclusion**  
Extended alert exclusion options now allow for excluding specific users from specific alerts. Exclusions can help avoid situations where use or configuration of certain types of internal software repeatedly triggered benign security alerts.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.70

Released March 17, 2019

- **Feature enhancement: Network Name Resolution (NNR) confidence level added to multiple alerts**  Network Name Resolution or (NNR) is used to help positively identify the source entity identity of suspected attacks. By adding the NNR confidence levels to Azure ATP alert evidence lists, you can now instantly assess and understand the level of NNR confidence related to the possible sources identified, and remediate appropriately.

    NNR confidence level evidence was added to the following alerts:
  - [Network mapping reconnaissance (DNS)](atp-reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007)
  - [Suspected identity theft (pass-the-ticket)](atp-lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018)
  - [Suspected NTLM relay attack (Exchange account)-preview](atp-lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037)
  - [Suspected DCSync attack (replication of directory services)](atp-domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006)

- **Additional health alert scenario: Azure ATP sensor service failed to start**  
In instances where the Azure ATP sensor failed to start due to a network capturing driver issue, a sensor health alert is now triggered. [Troubleshooting Azure ATP sensor with Azure ATP logs](troubleshooting-atp-using-logs.md) for more information about Azure ATP logs and how to use them.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.69

Released March 10, 2019

- **Feature enhancement: Suspected identity theft (pass-the-ticket) alert**   This alert now features new evidence showing the details of connections made by using remote desktop protocol (RDP). The added evidence makes it easy to remediate the known issue of (B-TP) Benign-True Positive alerts caused by use of Remote Credential Guard over RDP connections.

- **Feature enhancement: Remote code execution over DNS alert**  
This alert now features new evidence showing your domain controller security update status, informing you when updates are required.

- **New documentation feature: Azure ATP Security alert MITRE ATT&CK Matrix&trade;**  
To explain and make it easier to map the relationship between Azure ATP security alerts and the familiar MITRE ATT&CK Matrix, we've added the relevant MITRE techniques to Azure ATP security alert listings. This additional reference makes it easier to understand the suspected attack technique potentially in use when an Azure ATP security alert is triggered. Learn more about the [Azure ATP security alert guide](suspicious-activity-guide.md).  

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.68

Released March 3, 2019

- **Feature enhancement: Suspected brute force attack (LDAP) alert**  
Significant usability improvements were made to this security alert including a revised description, provision of additional source information, and guess attempt details for faster remediation.  
Learn more about [Suspected brute force attack (LDAP)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-ldap-external-id-2004) security alerts.

- **New documentation feature: Security alert lab**  
To explain the power of Azure ATP in detecting the real threats to your working environment, we've added a new **Security alert lab** to this documentation. The **Security alert lab** helps you quickly set up a lab or testing environment, and explains the best defensive posturing against common, real-world threats and attacks.  

    The [step-by-step lab](atp-playbook-lab-overview.md) is designed to ensure you spend minimal time building, and more time learning about your threat landscape and available Azure ATP alerts and protection. We're excited to hear your feedback.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.67

Released February 24, 2019

- **New security alert: Security principal reconnaissance (LDAP) – (preview)**  
Azure ATP's [Security principal reconnaissance (LDAP) - preview](atp-reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038) security alert is now in public preview.    In this detection, an Azure ATP security alert is triggered when security principal reconnaissance is used by attackers to gain critical information about the domain environment. This information helps attackers map the domain structure, as well as identify privileged accounts for use in later steps in their attack kill chain.

    Lightweight Directory Access Protocol (LDAP) is one the most popular methods used for both legitimate and malicious purposes to query Active Directory. LDAP focused security principal reconnaissance is commonly used as the first phase of a Kerberoasting attack. Kerberoasting attacks are used to get a target list of Security Principal Names (SPNs), which attackers then attempt to get Ticket Granting Server (TGS) tickets for.

- **Feature enhancement: Account enumeration reconnaissance (NTLM) alert**  
Improved **Account enumeration reconnaissance (NTLM)** alert using additional analysis, and improved detection logic to reduce **B-TP** and **FP** alert results.

- **Feature enhancement: Network mapping reconnaissance (DNS) alert**  
New types of detections added to Network mapping reconnaissance (DNS) alerts. In addition to detecting suspicious AXFR requests, Azure ATP now detects suspicious types of requests originating from non-DNS servers using an excessive number of requests.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.66

Released February 17, 2019

- **Feature enhancement: Suspected DCSync attack (replication of directory services) alert**  
Usability improvements were made to this security alert including a revised description, provision of additional source information, new infographic, and more evidence.
Learn more about [Suspected DCSync attack (replication of directory services)](atp-domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006) security alerts.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.65

Released February 10, 2019

- **New security alert: Suspected NTLM relay attack (Exchange account) – (preview)**  
Azure ATP's [Suspected NTLM relay attack (Exchange account) - preview](atp-lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037) security alert is now in public preview.    In this detection, an Azure ATP security alert is triggered when use of Exchange account credentials from a suspicious source is identified. These types of attacks attempt to leverage NTLM relay techniques to gain domain controller exchange privileges and are known as **ExchangePriv**. Learn more about the **ExchangePriv** technique from the [ADV190007 advisory](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV190007) first published January 31, 2019, and the [Azure ATP alert response](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/How-to-win-the-latest-security-race-over-NTLM-relay/ba-p/334511).  

- **General availability: Remote code execution over DNS**  
This alert is now in GA (general availability). For more information and alert features, see the [Remote code execution over DNS alert description page](atp-lateral-movement-alerts.md#remote-code-execution-over-dns-external-id-2036).

- **General availability: Data exfiltration over SMB**  
This alert is now in GA (general availability). For more information and alert features, see the [Data exfiltration over SMB alert description page](atp-exfiltration-alerts.md#data-exfiltration-over-smb-external-id-2030).

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.64

Released February 4, 2019

- **General availability: Suspected Golden Ticket usage (ticket anomaly)**  
This alert is now in GA (general availability). For more information and alert features, see the [Suspected Golden Ticket usage (ticket anomaly) alert description page](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-external-id-2032).

- **Feature enhancement: Network mapping reconnaissance (DNS)**  
Improved alert detection logic deployed for this alert to minimize false-positives and alert noise. This alert now has a learning period of eight days before the alert will possibly trigger for the first time. For more information about this alert, see [Network mapping reconnaissance (DNS) alert description page](atp-reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007).

    **Due to the enhancement of this alert, the nslookup method should no longer be used to test Azure ATP connectivity during initial configuration.**

- **Feature enhancement:**  
This version includes redesigned alert pages, and new evidence, providing better alert investigation.
  - [Suspected brute force attack (SMB)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-smb-external-id-2033)
  - [Suspected Golden Ticket usage (time anomaly) alert description page](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-time-anomaly-external-id-2022)
  - [Suspected overpass-the-hash attack (Kerberos)](atp-lateral-movement-alerts.md#suspected-overpass-the-hash-attack-kerberos-external-id-2002)
  - [Suspected use of Metasploit hacking framework](atp-compromised-credentials-alerts.md#suspected-use-of-metasploit-hacking-framework-external-id-2034)
  - [Suspected WannaCry ransomware attack](atp-compromised-credentials-alerts.md#suspected-wannacry-ransomware-attack-external-id-2035)

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.63

Released January 27, 2019

- **New feature: Untrusted forest support – (preview)**  
Azure ATP's support for sensors in untrusted forests is now in public preview.
From the Azure ATP portal **Directory services** page, configure additional sets of credentials to enable Azure ATP sensors to connect to different Active Directory forests, and report back to the Azure ATP service. See [Azure ATP multi-forest](atp-multi-forest.md) to learn more.

- **New feature: Domain controller coverage**  
Azure ATP now provides coverage information for Azure ATP monitored domain controllers.  
From the Azure ATP portal **Sensors** page, view the number of the monitored and unmonitored domain controllers detected by Azure ATP in your environment. Download the monitored domain controller list for further analysis, and to build an action plan. See the [Domain controller monitoring](atp-sensor-monitoring.md) how-to guide to learn more.

- **Feature enhancement: Account enumeration reconnaissance**  
The Azure ATP account enumeration reconnaissance detection now detects and issues alerts for enumeration attempts using Kerberos and NTLM. Previously, the detection only worked for attempts using Kerberos. See [Azure ATP reconnaissance alerts](atp-reconnaissance-alerts.md#account-enumeration-reconnaissance-external-id-2003) to learn more.

- **Feature enhancement: Remote code execution attempt alert**
  - All remote execution activities, such as service creation, WMI execution, and the new **PowerShell** execution, were added to the profile timeline of the destination machine. The destination machine is the domain controller the command was executed on.
  - **PowerShell** execution was added to the list of remote code execution activities listed in the entity profile alert timeline.
  - See [Remote code execution attempt](atp-domain-dominance-alerts.md#remote-code-execution-attempt-external-id-2019) to learn more.  

- **Windows Server 2019 LSASS issue and Azure ATP**  
In response to customer feedback regarding Azure ATP usage with domain controllers running Windows Server 2019, this update includes additional logic to avoid triggering the reported behavior on Windows Server 2019 machines. Full support for Azure ATP sensor on Windows Server 2019 is planned for a future Azure ATP update, however installing and running Azure ATP on Windows Servers 2019 is **not** currently supported. See [Azure ATP sensor requirements](atp-prerequisites.md#azure-atp-sensor-requirements) to learn more.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.62

Released January 20, 2019

- **New security alert: Remote code execution over DNS – (preview)**  
Azure ATP's [Remote code execution over DNS](atp-lateral-movement-alerts.md#remote-code-execution-over-dns-external-id-2036) security alert is now in public preview.    In this detection, an Azure ATP security alert is triggered when DNS queries suspected of exploiting security vulnerability [CVE-2018-8626](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8626) are made against a domain controller in the network.

- **Feature Enhancement: 72 hour delayed sensor update**  
Changed option to delay sensor updates on selected sensors to 72 hours (instead of the previous 24-hour delay) after each release update of Azure ATP. See [Azure ATP sensor update](sensor-update.md) for configuration instructions.

- This version also includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.61

Released January 13, 2019

- **New Security Alert: Data exfiltration over SMB - (preview)**  
Azure ATP's [Data exfiltration over SMB](atp-exfiltration-alerts.md) security alert is now in public preview. Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, attackers can create a Kerberos ticket granting ticket (TGT) that provide authorization to any resource.

- **Feature Enhancement: Remote code execution attempt** security alert  
A new alert description and additional evidence were added to help make the alert easier to understand, and provide better investigation workflows.

- **Feature Enhancement: DNS query logical activities**  
Additional query types were added to [Azure ATP monitored activities](monitored-activities.md) including: **TXT**, **MX**, **NS**, **SRV**, **ANY**, **DNSKEY**.

- **Feature Enhancement: Suspected Golden Ticket usage (ticket anomaly) and Suspected Golden Ticket usage (nonexistent account)**  
Improved detection logic has been applied to both alerts to reduce the number of FP alerts, and deliver more accurate results.

- **Feature Enhancement: Azure ATP Security Alert documentation**  
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

- **Security Alert Enhancement: Unusual Protocol Implementation alert split**  
Azure ATP's series of Unusual Protocol Implementation security alerts that previously shared 1 externalId (2002), are now split into four distinctive alerts, with a corresponding unique external ID.

### New alert externalIds

> [!div class="mx-tableFixed"]
> |New security alert name|Previous security alert name|Unique external ID|
> |---------|----------|---------|
> |Suspected brute force attack (SMB)|Unusual protocol implementation (potential use of malicious tools such as Hydra)|2033
> |Suspected overpass-the-hash attack (Kerberos)|Unusual Kerberos protocol implementation (potential overpass-the-hash attack)|2002|
> |Suspected use of Metasploit hacking framework|Unusual protocol implementation (potential use of Metasploit hacking tools)|2034
> |Suspected WannaCry ransomware attack|Unusual protocol implementation (potential WannaCry ransomware attack)|2035
> |

- **New monitored activity: File copy through SMB**  
Copying of files using SMB is now a monitored and filterable activity. Learn more about which [activities Azure ATP monitors](monitored-activities.md), and how to [filter and search monitored activities](atp-activities-search.md) in the portal.

- **Large Lateral Movement Path image enhancement**  
When viewing large lateral movement paths, Azure ATP now highlights only the nodes connected to a selected entity,  instead of blurring the other nodes. This change introduces a significant improvement in large LMP rendering speed.

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.57

Released December 2, 2018

- **New Security Alert: Suspected Golden ticket usage- ticket anomaly (preview)**  
Azure ATP's [Suspected Golden Ticket usage - ticket anomaly](suspicious-activity-guide.md) security alert is now in public preview.    Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, attackers can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource.

    This forged TGT is called a "Golden Ticket" because it allows attackers to achieve lasting network persistence. Forged Golden Tickets of this type have unique characteristics this new detection is designed to identify.

- **Feature Enhancement: Automated Azure ATP instance (workspace) creation**  
From today, Azure ATP *workspaces* are renamed Azure ATP *instances*. Azure ATP now supports one Azure ATP instance per Azure ATP account. Instances for new customers are created using the instance creation wizard in the [Azure ATP portal](https://portal.atp.azure.com). Existing Azure ATP workspaces are converted automatically to Azure ATP instances with this update.  

  - Simplified instance creation for faster deployment and protection using [create your Azure ATP instance](install-atp-step1.md).
  - All [data privacy and compliance](atp-privacy-compliance.md) remains the same.

  To learn more about Azure ATP instances, see [Create your Azure ATP instance](install-atp-step1.md).

- This version includes improvements and bug fixes for internal sensor infrastructure.

## Azure ATP release 2.56

Released November 25, 2018

- **Feature Enhancement: Lateral Movement Paths (LMPs)**  
Two additional features are added to enhance Azure ATP Lateral Movement Path (LMP) capabilities:

  - LMP history is now saved and discoverable per entity, and when using LMP reports.
  - Follow an entity in an LMP via the activity timeline, and investigate using additional evidence provided for discovery of potential attack paths.

  See [Azure ATP Lateral Movement Paths](use-case-lateral-movement-path.md) to learn more about how to use and investigate with enhanced LMPs.

- **Documentation enhancements: Lateral Movement Paths, Security Alert names**  
Additions and updates were made to Azure ATP articles describing Lateral Movement Path descriptions and features, name mapping was added for all instances of old security alert names to new names and externalIds.
  - See [Azure ATP Lateral Movement Paths](use-case-lateral-movement-path.md), [Investigate  Lateral Movement Paths](investigate-lateral-movement-path.md), and [Security Alert Guide](suspicious-activity-guide.md) to learn more.

- This version includes improvements and bug fixes for internal sensor infrastructure.

For details of each Azure ATP release prior to (and including) release 2.55, see the [Azure ATP release reference](atp-release-reference.md).

## See Also

- [What is Azure Advanced Threat Protection?](what-is-atp.md)
- [Frequently asked questions](atp-technical-faq.md)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
