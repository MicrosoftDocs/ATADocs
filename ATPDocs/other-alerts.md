---
title: Other security alerts
description: This article explains Microsoft Defender for Identity alerts issued when other attacks are detected against your organization.
ms.date: 01/18/2023
ms.topic: conceptual
---

# Other security alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. Microsoft Defender for Identity identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance and discovery alerts](reconnaissance-discovery-alerts.md)
1. [Persistence and privilege escalation alerts](persistence-privilege-escalation-alerts.md)
1. [Credential access alerts](credential-access-alerts.md)
1. [Lateral movement alerts](lateral-movement-alerts.md)
1. **Other**

To learn more about how to understand the structure, and common components of all Defender for Identity security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Other** phase suspicious activities detected by Defender for Identity in your network.

## Suspected DCShadow attack (domain controller promotion) (external ID 2028)

*Previous name:* Suspicious domain controller promotion (potential DCShadow attack)

**Severity**: High

**Description**:

A domain controller shadow (DCShadow) attack is an attack designed to change directory objects using malicious replication. This attack can be performed from any machine by creating a rogue domain controller using a replication process.

In a DCShadow attack, RPC, and LDAP are used to:

1. Register the machine account as a domain controller (using domain admin rights).
1. Perform replication (using the granted replication rights) over DRSUAPI and send changes to directory objects.

In this Defender for Identity detection, a security alert is triggered when a machine in the network tries to register as a rogue domain controller.

**Learning period**:

None

**MITRE**:

|Primary MITRE tactic  | [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005)  |
|---------|---------|
|MITRE attack technique  | [Rogue Domain Controller (T1207)](https://attack.mitre.org/techniques/T1207/)        |
|MITRE attack sub-technique |   N/A      |

**Suggested steps for prevention**:

Validate the following permissions:

1. Replicate directory changes.
1. Replicate directory changes all.
1. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](/SharePoint/administration/user-profile-service-administration). You can use [AD ACL Scanner](/archive/blogs/pfesweplat/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool) or create a Windows PowerShell script to determine who has these permissions in the domain.

> [!NOTE]
> Suspicious domain controller promotion (potential DCShadow attack) alerts are supported by Defender for Identity sensors only.

## Suspected DCShadow attack (domain controller replication request) (external ID 2029)

*Previous name:* Suspicious replication request (potential DCShadow attack)

**Severity**: High

**Description**:

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with other domain controllers. Given necessary permissions, attackers can grant rights for their machine account, allowing them to impersonate a domain controller. Attackers strive to initiate a malicious replication request, allowing them to change Active Directory objects on a genuine domain controller, which can give the attackers persistence in the domain.
In this detection, an alert is triggered when a suspicious replication request is generated against a genuine domain controller protected by Defender for Identity. The behavior is indicative of techniques used in domain controller shadow attacks.

**Learning period**:

None

**MITRE**:

|Primary MITRE tactic  | [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005)  |
|---------|---------|
|MITRE attack technique  | [Rogue Domain Controller (T1207)](https://attack.mitre.org/techniques/T1207/)        |
|MITRE attack sub-technique |   N/A      |

**Suggested remediation and steps for prevention**:

Validate the following permissions:

1. Replicate directory changes.
1. Replicate directory changes all.
1. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](/SharePoint/administration/user-profile-service-administration). You can use [AD ACL Scanner](/archive/blogs/pfesweplat/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool) or create a Windows PowerShell script to determine who in the domain has these permissions.

> [!NOTE]
> Suspicious replication request (potential DCShadow attack) alerts are supported by Defender for Identity sensors only.

## Suspicious VPN connection (external ID 2025)

*Previous name:* Suspicious VPN connection

**Severity**: Medium

**Description**:

Defender for Identity learns the entity behavior for users VPN connections over a sliding period of one month.

The VPN-behavior model is based on the machines users log in to and the locations the users connect from.

An alert is opened when there is a deviation from the user's behavior based on a machine learning algorithm.

**Learning period**:

30 days from the first VPN connection, and at least 5 VPN connections in the last 30 days, per user.

**MITRE**:

|Primary MITRE tactic  | [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005)  |
|---------|---------|
|Secondary MITRE tactic    | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003)        |
|MITRE attack technique  | [External Remote Services (T1133)](https://attack.mitre.org/techniques/T1133/)        |
|MITRE attack sub-technique |     N/A    |

## Remote code execution attempt (external ID 2019)

*Previous name:* Remote code execution attempt

**Severity**: Medium

**Description**:

Attackers who compromise administrative credentials or use a zero-day exploit can execute remote commands on your domain controller or AD FS server. This can be used for gaining persistency, collecting information, denial of service (DOS) attacks or any other reason. Defender for Identity detects PSexec, Remote WMI, and PowerShell connections.

**Learning period**:

None

**MITRE**:

|Primary MITRE tactic  | [Execution (TA0002)](https://attack.mitre.org/tactics/TA0002)  |
|---------|---------|
|Secondary MITRE tactic    |  [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)       |
|MITRE attack technique  | [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/),[Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)         |
|MITRE attack sub-technique |  [PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/), [Windows Remote Management (T1021.006)](https://attack.mitre.org/techniques/T1021/006/)      |

**Suggested steps for prevention:**

1. Restrict remote access to domain controllers from non-Tier 0 machines.
1. Implement [privileged access](/windows-server/identity/securing-privileged-access/securing-privileged-access), allowing only hardened machines to connect to domain controllers for admins.
1. Implement less-privileged access on domain machines to allow specific users the right to create services.

> [!NOTE]
> Remote code execution attempt alerts on attempted use of Powershell commands are only supported by Defender for Identity sensors.

## Suspicious service creation (external ID 2026)

*Previous name:* Suspicious service creation

**Severity**: Medium

**Description**:

A suspicious service has been created on a domain controller or AD FS server in your organization. This alert relies on event 7045 to identify this suspicious activity.

**Learning period**:

None

**MITRE**:

|Primary MITRE tactic  | [Execution (TA0002)](https://attack.mitre.org/tactics/TA0002) |
|---------|---------|
|Secondary MITRE tactic    |   [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004), [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005), [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)      |
|MITRE attack technique  | [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/), [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/), [System Services (T1569)](https://attack.mitre.org/techniques/T1569/), [Create or Modify System Process (T1543)](https://attack.mitre.org/techniques/T1543/)      |
|MITRE attack sub-technique |   [Service Execution (T1569.002)](https://attack.mitre.org/techniques/T1569/002/), [Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/)      |

**Suggested steps for prevention**:

1. Restrict remote access to domain controllers from non-Tier 0 machines.
1. Implement [privileged access](/windows-server/identity/securing-privileged-access/securing-privileged-access) to allow only hardened machines to connect to domain controllers for administrators.
1. Implement less-privileged access on domain machines to give only specific users the right to create services.

## Suspicious communication over DNS (external ID 2031)

*Previous name*: Suspicious communication over DNS

**Severity**: Medium

**Description**:

The DNS protocol in most organizations is typically not monitored and rarely blocked for malicious activity. Enabling an attacker on a compromised machine, to abuse the DNS protocol. Malicious communication over DNS can be used for data exfiltration, command, and control, and/or evading corporate network restrictions.

**Learning period**:

None

**MITRE**:

|Primary MITRE tactic  | [Exfiltration (TA0010)](https://attack.mitre.org/tactics/TA0010)  |
|---------|---------|
|MITRE attack technique  | [Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/), [Exfiltration Over C2 Channel (T1041)](https://attack.mitre.org/techniques/T1041/), [Scheduled Transfer (T1029)](https://attack.mitre.org/techniques/T1029/), [Automated Exfiltration (T1020)](https://attack.mitre.org/techniques/T1020/), [Application Layer Protocol (T1071)](https://attack.mitre.org/techniques/T1071/)       |
|MITRE attack sub-technique | [DNS (T1071.004)](https://attack.mitre.org/techniques/T1071/004/), [Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol (T1048.003)](https://attack.mitre.org/techniques/T1048/003/)       |

## Data exfiltration over SMB (external ID 2030)

**Severity**: High

**Description**:

Domain controllers hold the most sensitive organizational data. For most attackers, one of their top priorities is to gain domain controller access, to steal your most sensitive data. For example, exfiltration of the Ntds.dit file, stored on the DC, allows an attacker to forge Kerberos ticket granting tickets(TGT) providing authorization to any resource. Forged Kerberos TGTs enable the attacker to set the ticket expiration to any arbitrary time. A Defender for Identity **Data exfiltration over SMB** alert is triggered when suspicious transfers of data are observed from your monitored domain controllers.

**Learning period**:

None

**MITRE**:

|Primary MITRE tactic  |[Exfiltration (TA0010)](https://attack.mitre.org/tactics/TA0010)  |
|---------|---------|
|Secondary MITRE tactic    | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008),[Command and Control (TA0011)](https://attack.mitre.org/tactics/TA0011)        |
|MITRE attack technique  | [Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/), [Lateral Tool Transfer (T1570)](https://attack.mitre.org/techniques/T1570/)      |
|MITRE attack sub-technique | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (T1048.003)](https://attack.mitre.org/techniques/T1048/003/)        |

## See also

- [Investigate assets](investigate-assets.md)
- [Understanding security alerts](understanding-security-alerts.md)
- [Manage security alerts](/defender-for-identity/manage-security-alerts)
- [Defender for Identity SIEM log reference](cef-format-sa.md)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
