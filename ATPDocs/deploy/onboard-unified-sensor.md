---
title: Prepare to deploy a unified sensor
description: Learn how to deploy a unified Microsoft Defender for Identity and Microsoft Defender for Endpoint sensor.
ms.date: 04/04/2024
ms.topic: how-to
---

# Onboard a unified Defender for Identity and Defender for Endpoint sensor


## Prerequisites

Supported operating systems: Windows Server 2019 and Windows Server 2022, 
This section provides guidance on preparing to use the new sensor:
1.	Your tenant is enabled for the new onboarding preview feature (this step is performed by Microsoft).
2.	Currently supported operating systems are Windows Server 2019 and Window Server 2022.
3.	Patch level March 2024 Cumulative Update
•	March 12, 2024—KB5035857 (OS Build 20348.2340) - Microsoft Support
Important Note: Following installation of this update, LSASS may experience a memory leak on domain controllers (DCs). This is observed when on-premises and cloud-based Active Directory Domain Controllers service Kerberos authentication requests. This issue is addressed in the out-of-band update: KB5037422.
4.	Supported Windows Server role is Active Directory Domain Services
5.	Connectivity requirements
•	Microsoft Defender for Endpoint URL endpoints are used for communication (Simplified URL are supported)
•	Configure your network environment to ensure connectivity with Defender for Endpoint service | Microsoft Learn
6.	Permissions required for the MDI onboarding page
Configure Defender for Identity settings	One of the following Microsoft Entra roles:
- Global Administrator
- Security Administrator
Or
The following Unified RBAC permissions:
- Authorization and settings/Security settings/Read
- Authorization and settings/Security settings/All permissions
- Authorization and settings/System settings/Read
- Authorization and settings/System settings/All permissions

7.	Domain Controllers onboarded to Defender for Endpoint (for this current preview), these servers should also not be onboarded to Defender for Identity with the existing agent.
8.	Configuration of auditing is required for Defender for Identity detections; this is covered in detail in the section below: Defender for Identity Auditing configuration. The Defender for Identity PowerShell module can be used to help in this configuration.
Defender for Endpoint onboarding 
For this stage of our private preview, we require Domain Controllers to be onboarded to Defender for Endpoint. For more detailed information on onboarding servers to Defender for Endpoint please see this link: Defender for Endpoint onboarding Windows Server | Microsoft Learn

Defender for Identity Auditing configuration 
Microsoft Defender for Identity detections rely on specific Windows Event log entries to enhance detections and provide extra information on the users who performed specific actions, such as NTLM logons and security group modifications. Full details on the auditing configuration requirements can be found here: Configure audit policies for Windows event logs - Microsoft Defender for Identity | Microsoft Learn
The Defender For Identity PowerShell module can be used to easily enable the required configuration, the reference can be found here: DefenderForIdentity Module | Microsoft Learn and module is available here: https://www.powershellgallery.com/packages/DefenderForIdentity/ 
This example command sets all configurations for the domain, creating the GPOs and linking them.
Set-MDIConfiguration -Mode Domain -Configuration All

Defender for Identity onboarding
Onboarding
Once the requirements above are met you can navigate to the Defender XDR portal https://security.microsoft.com and locate the onboarding page under Settings > Identities > Onboarding (https://security.microsoft.com/settings/identities?tabid=onboarding)
The Onboarding page will display servers eligible for Defender for Identity onboarding with the new sensor. These eligible servers are Domain Controllers onboarded to Defender for Endpoint without the existing Defender for Identity agent installed.
 
To onboard a server, first select the server from the list and then click Onboard, then click Onboard confirmation window. This will instruct the server to onboard to Defender for Identity.
 
 
A green banner stating the server has been successfully installed should show, you can select “Click here to see the onboarded servers” this will take you to the Sensors page at Settings > Identities > Sensors.
 
Check sensor health
You can check the health of the new sensor in the Sensors page. This provides details on the Health status and any Health issues.
NOTE: For the first sensor being onboarded this can take up to 1 hour to show as onboarded. For subsequent sensors this should show within 5 minutes.
 
NOTE: You may see the Service status of “Onboarding” while the machine is performing the onboarding.

Functionality Tests
Please complete the following functionality tests, additional steps and details can be found in the sections under this table.
Functionality Test	Result / Comment
Onboarding: New Sensor Onboarding	Confirm onboarding was successful
Entity: Device Inventory	Check the details of the onboarded server
Entity: User entity data	Check domain users are populated and data available in user pages
Entity: Group entity data	Check domain groups are populated and data available in group pages
ITDR Dashboard	Review the data presented in the ITDR dashboard
ISPM: Resolve Unsecure Domain config
Review the ISPM and test states
Alert: Honeytoken	Test the detection and view alert
Alert: Suspicious Service Creation	Test the detection and view alert
Alert: Remote code execution attempts	Test the detection and view alert
Advanced Hunting queries	Test the example queries 
Remediation Action: Disable User	Test remediation actions
Remediation Action: Enable User	Test remediation actions
Remediation Action: Force password reset	Test remediation actions

Entity Pages
Confirm that entities such as Domain Controllers, Users and Groups are populated.
Device entity:
Check the onboarded Domain Controller information is correct by navigating to Assets > Devices and select the onboarded Domain Controller. Defender for Identity events will show within the device timeline.
 
User entities:
Review the user data and information under Assets > Users for the newly onboarded domain or by using the global search option. This should include domain users and user pages with populated data including:
-	Overview tab (includes directory data such as Manager, SID, SAM Name)
-	Observed in organisation (includes devices, group memberships)
-	Timeline (event data for the user)
 

Group entities:
Groups can be found using the global search or by pivoting from a user or device where group information is present. 
 
You can check details of group memberships, view users and timeline data for the group.
If no event data is found on the group timeline you may need to manually create some, this can easily be done by adding and removing users from the group within active directory. 
 

ITDR Dashboard
To access the ITDR dashboard, navigate to Identities > Dashboard – review the information provided.
 

Identity Security Posture Management (ISPM) recommendations
The following recommendations are supported as part of this preview:
-	Resolve unsecure domain configurations

Recommendations can be checked by navigating to Secure Score > Recommended Actions
Note: You can filter recommendations by Product: Defender for Identity

 

To test the functionality of the Secure Score recommendation, please test the following commands and view the compliance state:

Set configuration to non-compliant state:

Set-ADObject -Identity ((Get-ADDomain).distinguishedname) -Replace @{"ms-DS-MachineAccountQuota"="10"}

Set configuration to compliant state:

Set-ADObject -Identity ((Get-ADDomain).distinguishedname) -Replace @{"ms-DS-MachineAccountQuota"="0"}
Check configuration locally:

Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota

Full details on the recommendation and values can be found here: Unsecure domain configurations assessment - Microsoft Defender for Identity | Microsoft Learn

Advanced Hunting
Check data is showing in the following advanced hunting tables:
Simple queries:
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

Defender for Identity sensor offboarding
To offboard the sensor from Defender for Identity perform the following steps. 
Locate the onboarded sensor under Settings > Identities > Sensors, Select the sensor, then click Delete
 
On the confirmation window, click Delete sensor:
 
NOTE: This action will not offboard the server from Defender for Endpoint.
