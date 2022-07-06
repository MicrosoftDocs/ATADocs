---
title: Microsoft Defender for Identity lateral movement security alerts
description: This article explains the Microsoft Defender for Identity alerts issued when attacks typically part of lateral movement phase efforts are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Lateral movement alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](reconnaissance-alerts.md)
1. [Compromised credentials](compromised-credentials-alerts.md)
1. **Lateral Movements**
1. [Domain dominance](domain-dominance-alerts.md)
1. [Exfiltration](exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Lateral Movement** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network. In this article, you'll learn how to understand, classify, remediate, and prevent the following types of attacks:

> [!div class="checklist"]
>
> - Suspected exploitation attempt on Windows Print Spooler service (external ID 2415)
> - Remote code execution attempt over DNS (external ID 2036)
> - Suspected identity theft (pass-the-hash) (external ID 2017)
> - Suspected identity theft (pass-the-ticket) (external ID 2018)
> - Suspected NTLM authentication tampering (external ID 2039)
> - Suspected NTLM relay attack (Exchange account)  (external ID 2037)
> - Suspected overpass-the-hash attack (Kerberos) (external ID 2002)
> - Suspected rogue Kerberos certificate usage (external ID 2047)
> - Suspected SMB packet manipulation (CVE-2020-0796 exploitation) (external ID 2406)
> - Suspicious network connection over Encrypting File System Remote Protocol (external ID 2416)
> - Exchange Server Remote Code Execution (CVE-2021-26855) (external ID 2414)


<!-- * Suspected overpass-the-hash attack (encryption downgrade) (external ID 2008)-->

## Suspected exploitation attempt on Windows Print Spooler service (external ID 2415)

**Description**

Adversaries might exploit the Windows Print Spooler service to perform privileged file operations in an improper manner. An attacker who has (or obtains) the ability to execute code on the target, and who successfully exploits the vulnerability, could run arbitrary code with SYSTEM privileges on a target system. If run against a domain controller, the attack would allow a compromised non-administrator account to perform actions against a domain controller as SYSTEM.

This functionally allows any attacker who enters the network to instantly elevate privileges to Domain Administrator, steal all domain credentials, and distribute further malware as a Domain Admin.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008) |
|---------|---------|
|MITRE attack technique    |  [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)       |
|MITRE attack sub-technique |  N/A       |

**Learning period**

None

**TP, B-TP or FP**

1. Determine whether the Print Spooler service is frequently used over the network to install printer drivers on domain controllers. This should rarely happen.
2. Check if the source computer is running an attack tool such as Mimikatz or Impacket.
3. If the answers to these questions is yes, it's a true positive. Follow the instructions in the next section to understand the scope of the breach.

**Understand the scope of the breach**

1. Investigate the source computer using [these instructions](investigate-a-computer.md).
2. Investigate the target domain controller, and identify activities that occurred after the attack.

**Suggested remediation**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time that the activity occurred. These users might also be compromised. If you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection,you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
2. Due to the risk of the domain controller being compromised, install the security updates for [CVE-2021-3452](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) on Windows domain controllers, before installing on member servers and workstations.
3. You can use the Defender for Identity built-in security assessment that tracks the availability of Print spooler services on domain controllers. [Learn more](cas-isp-print-spooler.md).

## Remote code execution attempt over DNS (external ID 2036)

**Description**

12/11/2018 Microsoft published [CVE-2018-8626](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8626), announcing that a newly discovered remote code execution vulnerability exists in Windows Domain Name System (DNS) servers. In this vulnerability, servers fail to properly handle requests. An attacker who successfully exploits the vulnerability can run arbitrary code in the context of the Local System Account. Windows servers currently configured as DNS servers are at risk from this vulnerability.

In this detection, a [!INCLUDE [Product short](includes/product-short.md)] security alert is triggered when DNS queries suspected of exploiting the CVE-2018-8626 security vulnerability are made against a domain controller in the network.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008) |
|---------|---------|
|Secondary MITRE tactic    |  [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004)       |
|MITRE attack technique  |   [Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068/), [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)      |
|MITRE attack sub-technique |  N/A       |

**Learning period**

None

**TP, B-TP or FP**

1. Are the destination computers up-to-date and patched against CVE-2018-8626?
    - If the computers are up-to-date and patched, **Close** the security alert as a **FP**.
1. Was a service created or an unfamiliar process executed around the time of the attack
    - If no new service or unfamiliar process is found, **Close** the security alert as a **FP**.
1. This type of attack can crash the DNS service before successfully causing code execution.
    - Check if the DNS service was restarted a few times around the time of the attack.
    - If the DNS was restarted, it was likely an attempt to exploit CVE-2018-8626. Consider this alert a **TP** and follow the instructions in **Understand the scope of the breach**.

**Understand the scope of the breach**

- Investigate the [source and destination computers](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

**Remediation**

1. Contain the domain controllers.
    1. Remediate the remote code execution attempt.
    1. Look for users also logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    1. Find the tool that performed the attack and remove it.
    1. Look for users also logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

**Prevention**

- Make sure all DNS servers in the environment are up-to-date, and patched against [CVE-2018-8626](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8626).

## Suspected identity theft (pass-the-hash) (external ID 2017)

*Previous name:* Identity theft using Pass-the-Hash attack

**Description**

Pass-the-Hash is a lateral movement technique in which attackers steal a user's NTLM hash from one computer and use it to gain access to another computer.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008) |
|---------|---------|
|MITRE attack technique  | [Use Alternate Authentication Material (T1550)](https://attack.mitre.org/techniques/T1550/)       |
|MITRE attack sub-technique | [Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/)         |

**Learning period**

None

**TP, B-TP, or FP?**

1. Determine if the hash was used from computers the user is using regularly?
    - If the hash was used from computers used regularly, **Close** the alert as an **FP**.

**Understand the scope of the breach**

1. Investigate the [source and destination computers](investigate-a-computer.md) further.
1. Investigate the [compromised user](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source and destination computers.
1. Find the tool that performed the attack and remove it.
1. Look for users logged in around the same time of the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

## Suspected identity theft (pass-the-ticket) (external ID 2018)

*Previous name:* Identity theft using Pass-the-Ticket attack

**Description**

Pass-the-Ticket is a lateral movement technique in which attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by reusing the stolen ticket. In this detection, a Kerberos ticket is seen used on two (or more) different computers.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008) |
|---------|---------|
|MITRE attack technique  | [Use Alternate Authentication Material (T1550)](https://attack.mitre.org/techniques/T1550/)       |
|MITRE attack sub-technique | [Pass the Ticket (T1550.003)](https://attack.mitre.org/techniques/T1550/002/)         |

**Learning period**

None

**TP, B-TP, or FP?**

Successfully resolving IPs to computers in the organization is critical to identify pass-the-ticket attacks from one computer to another.

1. Check if the IP address of one or both computers belong to a subnet that is allocated from an undersized DHCP pool, for example, VPN, VDI or WiFi?
1. Is the IP address shared (for example, by a NAT device)?
1. Is the sensor not resolving one or more of the destination IP addresses? If a destination IP address is not resolved, it may indicate that the correct ports between sensor and devices are not open correctly.

    If the answer to any of the previous questions is **yes**, check if the source and destinations computers are the same. If they are the same, it is an **FP** and there were no real attempts at **pass-the-ticket**.

The [Remote Credential Guard](/windows/security/identity-protection/remote-credential-guard) feature of RDP connections, when used with Windows 10 on Windows Server 2016 and newer, can cause **B-TP** alerts.
Using the alert evidence, check if the user made a remote desktop connection from the source computer to the destination computer.

1. Check for correlating evidence.
1. If there is correlating evidence, check if the RDP connection was made using Remote Credential Guard.
1. If the answer is yes, **Close** the security alert as a **B-TP** activity.

There are custom applications that forward tickets on behalf of users. These applications have delegation rights to user tickets.

1. Is a custom application type like the one previously described, currently on the destination computers? Which services is the application running? Are the services acting on behalf of users, for example, accessing databases?
    - If the answer is yes, **Close** the security alert as a **B-TP** activity.
1. Is the destination computer a delegation server?
    - If the answer is yes, **Close** the security alert, and exclude that computer as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source and destination computers](investigate-a-computer.md).
1. Investigate the [compromised user](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source and destination computers.
1. Find the tool that performed the attack and remove it.
1. Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. If you have Microsoft Defender for Endpoint installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.

## Suspected NTLM authentication tampering (external ID 2039)

In June 2019, Microsoft published [Security Vulnerability CVE-2019-1040](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1040), announcing discovery of a new tampering vulnerability in Microsoft Windows, when a "man-in-the-middle" attack is able to successfully bypass NTLM MIC (Message Integrity Check) protection.

Malicious actors that successfully exploit this vulnerability have the ability to downgrade NTLM security features, and may successfully create authenticated sessions on behalf of other accounts. Unpatched Windows Servers are at risk from this vulnerability.

In this detection, a [!INCLUDE [Product short](includes/product-short.md)] security alert is triggered when NTLM authentication requests suspected of exploiting security vulnerability identified in [CVE-2019-1040](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1040) are made against a domain controller in the network.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)  |
|---------|---------|
|Secondary MITRE tactic    | [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004)     |
|MITRE attack technique  | [Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068/), [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)        |
|MITRE attack sub-technique |   N/A      |

**Learning period**

None

**TP, B-TP, or FP?**

1. Are the involved computers, including domain controllers, up-to-date and patched against [CVE-2019-1040](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1040)?
    - If the computers are up-to-date and patched, we expect the authentication to fail. If the authentication ailed, **Close** the security alert as a failed attempt.

**Understand the scope of the breach**

1. Investigate the [source computers](investigate-a-computer.md).
1. Investigate the [source account](investigate-a-user.md).

**Suggested remediation and steps for prevention**

**Remediation**

1. Contain the source computers
1. Find the tool that performed the attack and remove it.
1. Look for users logged on around the same time as the activity occurred, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Force the use of sealed NTLMv2 in the domain, using the **Network security: LAN Manager authentication level** group policy. For more information, see [LAN Manager authentication level instructions](/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level) for setting the group policy for domain controllers.

**Prevention**

- Make sure all devices in the environment are up-to-date, and patched against [CVE-2019-1040](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1040).

## Suspected NTLM relay attack (Exchange account) (external ID 2037)

**Description**

An Exchange Server can be configured to trigger NTLM authentication with the Exchange Server account to a remote http server, run by an attacker. The server waits for the Exchange Server communication to relay its own sensitive authentication to any other server, or even more interestingly to Active Directory over LDAP, and grabs the authentication information.

Once the relay server receives the NTLM authentication, it provides a challenge that was originally created by the target server. The client responds to the challenge, preventing an attacker from taking the response, and using it to continue NTLM negotiation with the target domain controller.

In this detection, an alert is triggered when [!INCLUDE [Product short](includes/product-short.md)] identify use of Exchange account credentials from a suspicious source.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)  |
|---------|---------|
|Secondary MITRE tactic    | [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004)     |
|MITRE attack technique  | [Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068/), [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/), [Man-in-the-Middle (T1557)](https://attack.mitre.org/techniques/T1557/)        |
|MITRE attack sub-technique |   [LLMNR/NBT-NS Poisoning and SMB Relay (T1557.001)](https://attack.mitre.org/techniques/T1557/001/)     |

**Learning period**

None

**TP, B-TP, or FP?**

1. Check the source computers behind the IP addresses.
    1. If the source computer is an Exchange Server, **Close** the security alert as an **FP** activity.
    1. Determine if the source account should authenticate using NTLM from these computers? If they should authenticate, **Close** the security alert, and exclude these computers as a **B-TP** activity.

**Understand the scope of the breach**

1. Continue [investigating the source computers](investigate-a-computer.md) behind the IP addresses involved.
1. Investigate the [source account](investigate-a-user.md).

**Suggested remediation and steps for prevention**

1. Contain the source computers
    1. Find the tool that performed the attack and remove it.
    1. Look for users logged on around the same time as the activity occurred, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Force the use of sealed NTLMv2 in the domain, using the **Network security: LAN Manager authentication level** group policy. For more information, see [LAN Manager authentication level instructions](/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level) for setting the group policy for domain controllers.

<!--
## Suspected overpass-the-hash attack (encryption downgrade) (external ID 2008)

*Previous name:* Encryption downgrade activity

**Description**

Encryption downgrade is a method of weakening Kerberos using encryption downgrade of different fields of the protocol, normally encrypted using the highest levels of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, [!INCLUDE [Product short](includes/product-short.md)] learns the Kerberos encryption types used by computers and users, and alerts you when a weaker cypher is used that is unusual for the source computer, and/or user, and matches known attack techniques.

In an over-pass-the-hash attack, an attacker can use a weak stolen hash to create a strong ticket, with a Kerberos AS request. In this detection,  instances are detected where the AS_REQ message encryption type from the source computer is downgraded, when compared to the previously learned behavior (the computer used AES).

**Learning period**

None

**TP, B-TP, or FP?**

1. Determine if the smartcard configuration recently changed.
    - Did the accounts involved recently have smartcard configurations changes?

      If the answer is yes, **Close** the security alert as a **B-TP** activity.

Some legitimate resources don't support strong encryption ciphers and may trigger this alert.

1. Do all source users share something?
    1. For example, are all of your marketing personnel accessing a specific resource that could cause the alert to be triggered?
    1. Check the resources accessed by those tickets.
       - Check this in Active Directory by checking the attribute *msDS-SupportedEncryptionTypes*, of the resource service account.
    1. If there is only one accessed resource, check if it is a valid resource for these users to access.

      If the answer to one of the previous questions is **yes**, it is likely to be a **B-TP** activity. Check if the resource can support a strong encryption cipher, implement a stronger encryption cipher where possible, and **Close** the security alert.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
1. Investigate the [compromised user](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

**Remediation**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
1. Find the tool that performed the attack and remove it.
1. Look for users logged on around the time of the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

**Prevention**

1. Configure your domain to support strong encryption cyphers, and remove *Use Kerberos DES encryption types*. Learn more about [encryption types and Kerberos](/archive/blogs/openspecification/windows-configurations-for-kerberos-supported-encryption-type).
1. Make sure the domain functional level is set to support strong encryption cyphers.
1. Give preference to using applications that support strong encryption cyphers.
-->

## Suspected overpass-the-hash attack (Kerberos) (external ID 2002)

*Previous name:* Unusual Kerberos protocol implementation (potential overpass-the-hash attack)

**Description**

Attackers use tools that implement various protocols such as Kerberos and SMB in non-standard ways. While Microsoft Windows accepts this type of network traffic without warnings, [!INCLUDE [Product short](includes/product-short.md)] is able to recognize potential malicious intent. The behavior is indicative of techniques such as over-pass-the-hash, Brute Force, and advanced ransomware exploits such as WannaCry, are used.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)  |
|---------|---------|
|MITRE attack technique  |  [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/),[Use Alternate Authentication Material (T1550)](https://attack.mitre.org/techniques/T1550/)      |
|MITRE attack sub-technique | [Pass the Has (T1550.002)](https://attack.mitre.org/techniques/T1550/002/), [Pass the Ticket (T1550.003)](https://attack.mitre.org/techniques/T1550/003/)        |

**Learning period**

None

**TP, B-TP, or FP?**

Sometimes applications implement their own Kerberos stack, not in accordance with the Kerberos RFC.

1. Check if the source computer is running an application with its own Kerberos stack, not in accordance with Kerberos RFC.
1. If the source computer is running such an application, and it should **not** do this, fix the application configuration. **Close** the security alert as a **B-TP** activity.
1. If the source computer is running such an application and it should continue to do so, **Close** the security alert as a **B-TP** activity and exclude the computer.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
1. If there is a [source user](investigate-a-user.md), investigate.

**Suggested remediation and steps for prevention**

1. Reset the passwords of the compromised users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
1. Find the tool that performed the attack and remove it.
1. Look for users logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Reset the passwords of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

<!-- REMOVE BOOKMARK FROM TITLE WHEN PREVIEW REMOVED -->

<a name="suspected-smb-packet-manipulation-cve-2020-0796-exploitation-external-id-2406"></a>

## Suspected rogue Kerberos certificate usage (external ID 2047)

**Description**

Rogue certificate attack is a persistence technique used by attackers after gaining control over the organization. Attackers compromise the Certificate Authority (CA) server and generate certificates that can be used as backdoor accounts in future attacks.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008) |
|---------|---------|
|Secondary MITRE tactic    | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004)       |
|MITRE attack technique  |  N/A       |
|MITRE attack sub-technique |  N/A       |

**Learning period**

None

**TP, B-TP, or FP**

- Determine if the account regularly logs into the computer?
  - If the certificate is regularly used from computers, **Close** the alert as an **FP**.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
2. Investigate the [source user](investigate-a-user.md).
3. Check which resources were accessed successfully and [investigate](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Find the certificate used in the CA server and revoke the certificate by invalidating the TLS/SSL before its scheduled expiration date.

## Suspected SMB packet manipulation (CVE-2020-0796 exploitation) - (external ID 2406)

**Description**

03/12/2020 Microsoft published [CVE-2020-0796](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796), announcing that a newly remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests. An attacker who successfully exploited the vulnerability could gain the ability to execute code on the target server or client. Unpatched Windows servers are at risk from this vulnerability.

In this detection, a [!INCLUDE [Product short](includes/product-short.md)] security alert is triggered when SMBv3 packet suspected of exploiting the CVE-2020-0796 security vulnerability are made against a domain controller in the network.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)  |
|---------|---------|
|MITRE attack technique  |   [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)      |
|MITRE attack sub-technique |    N/A     |

**Learning period**

None

**TP, B-TP, or FP?**

1. Are the involved domain controllers up-to-date and patched against CVE-2020-0796?
    - If the computers are up-to-date and patched, we expect the attack to fail, **Close** the security alert as a failed attempt.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
1. Investigate the destination DC.

**Suggested remediation and steps for prevention**

**Remediation**

1. Contain the source computer.
1. Find the tool that performed the attack and remove it.
1. Look for users logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. If your have computers with operating systems that don't support [KB4551762](https://www.catalog.update.microsoft.com/Search.aspx?q=KB4551762), we recommend disabling the SMBv3 compression feature in the environment, as described in the [Workarounds](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796) section.

**Prevention**

1. Make sure all devices in the environment are up-to-date, and patched against [CVE-2020-0796](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796).

> [!div class="nextstepaction"]
> [Domain dominance alerts](domain-dominance-alerts.md)

## Suspicious network connection over Encrypting File System Remote Protocol (external ID 2416)

**Description**

Adversaries may exploit the Encrypting File System Remote Protocol to improperly perform privileged file operations.

In this attack, the attacker can escalate privileges in an Active Directory network by coercing authentication from machine accounts and relaying to the certificate service.

This attack allows an attacker to take over an Active Directory (AD) Domain by exploiting a flaw in the Encrypting File System Remote (EFSRPC) Protocol and chaining it with a flaw in Active Directory Certificate Services.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008) |
|---------|---------|
|MITRE attack technique    |  [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)       |
|MITRE attack sub-technique |  N/A       |

**Learning period**

None
  
**TP, B-TP, or FP**

1. Check if the source computer is running an attack tool such as ADCSPwn, or if the originating device is a network scanner.
1. If the answer to the questions above is yes, it's a true positive. Follow the instructions in **Understand the scope of the breach** below.
1. Investigate the file name the attacker was trying forcing the authentication with. *PetitPotam.exe* is a good example for an attacking tool using this vulnerability.

**Understand the scope of the breach**

1. Investigate the source computer.
1. Investigate the target domain controller, and identify activities that occurred after the attack.
  
**Remediation:**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time that the activity occurred. These users might also be compromised. If you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

## Exchange Server Remote Code Execution (CVE-2021-26855) (external ID 2414)

**Description**

Some Exchange vulnerabilities can be used in combination to allow unauthenticated remote code execution on devices running Exchange Server. Microsoft has also observed subsequent web shell implantation, code execution, and data exfiltration activities during attacks. This threat may be exacerbated by the fact that numerous organizations publish Exchange Server deployments to the internet to support mobile and work-from-home scenarios. In many of the observed attacks, one of the first steps attackers took following successful exploitation of CVE-2021-26855, which allows unauthenticated remote code execution, was to establish persistent access to the compromised environment via a web shell.

Adversaries may create authentication bypass vulnerability results from having to treat requests to static resources as authenticated requests on the backend, because files such as scripts and images must be available even without authentication.

**Prerequisites**

Defender for Identity needs Windows Event 4662 to be enabled and collected to monitor for this attack. For information on how to configure and collect this event, see [Configure Windows Event collection](configure-windows-event-collection.md), and follow the instructions for [Enable auditing on an Exchange object](configure-windows-event-collection.md#enable-auditing-on-an-exchange-object).

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008) |
|---------|---------|
|MITRE attack technique    |  [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)       |
|MITRE attack sub-technique |  N/A       |

**Learning period**

None

1. Check if the source computer should have changed the attribute of the Exchange server object.
1. If not, it might be a true positive. Follow the instructions in **Understand the scope of the breach** below.

**Understand the scope of the breach**

1. Investigate the Exchange object in Active Directory and identify activities that occurred after the attack. For more information about indicators of compromise from this attack, see [HAFNIUM targeting Exchange Servers with 0-day exploits](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
1. Once this object has been modified, the first stage of the attack has likely begun.

**Remediation**

Update your Exchange servers with the latest security patches. The vulnerabilities are addressed in the [March 2021 Exchange Server Security Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-march-2021-exchange-server-security-updates/ba-p/2175901).

## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
