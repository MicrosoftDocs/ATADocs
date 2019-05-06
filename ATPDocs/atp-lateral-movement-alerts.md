---
# required metadata

title: Azure ATP lateral movement security alerts | Microsoft Docs
d|Description: This article explains the Azure ATP alerts issued when attacks typically part of lateral movement phase efforts are detected against your organization.
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 03/18/2019
ms.topic: tutorial
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 2257eb00-8614-4577-b6a1-5c65085371f2

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---


# Tutorial: Lateral movement alerts  

Typically, cyber attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. Azure ATP identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](atp-reconnaissance-alerts.md)
2. [Compromised credentials](atp-compromised-credentials-alerts.md)
3. **Lateral Movements**
4. [Domain dominance](atp-domain-dominance-alerts.md)
5. [Exfiltration](atp-exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all Azure ATP security alerts, see [Understanding security alerts](understanding-security-alerts.md).

The following security alerts help you identify and remediate **Lateral Movement** phase suspicious activities detected by Azure ATP in your network. In this tutorial, you'll learn how to understand, classify, remediate, and prevent the following types of attacks:

> [!div class="checklist"]
> * Remote code execution over DNS (external ID 2036)
> * Suspected identity theft (pass-the-hash) (external ID 2017)
> * Suspected identity theft (pass-the-ticket) (external ID 2018)
> * Suspected NTLM relay attack (Exchange account)  (external ID 2037) - preview
> * Suspected overpass-the-hash attack (encryption downgrade) (external ID 2008)
> * Suspected overpass-the-hash attack (Kerberos) (external ID 2002)

## Remote code execution over DNS (external ID 2036)

**Description**

12/11/2018 Microsoft published [CVE-2018-8626](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8626), announcing that a newly discovered remote code execution vulnerability exists in Windows Domain Name System (DNS) servers. In this vulnerability, servers fail to properly handle requests. An attacker who successfully exploits the vulnerability can run arbitrary code in the context of the Local System Account. Windows servers currently configured as DNS servers are at risk from this vulnerability.

In this detection, an Azure ATP security alert is triggered when DNS queries suspected of exploiting the CVE-2018-8626 security vulnerability are made against a domain controller in the network.

**TP, B-TP or FP**

1. Are the destination computers up-to-date and patched against CVE-2018-8626? 
    - If the computers are up-to-date and patched, **Close** the security alert as a **FP**.
2. Was a service created or an unfamiliar process executed around the time of the attack
    - If no new service or unfamiliar process is found, **Close** the security alert as a **FP**. 
3. This type of attack can crash the DNS service before successfully causing code execution.
    - Check if the DNS service was restarted a few times around the time of the attack.
    - If the DNS was restarted, it was likely an attempt to exploit CVE-2018-8626. Consider this alert a **TP** and follow the instructions in **Understand the scope of the breach**. 

**Understand the scope of the breach**

- Investigate the [source and destination computers](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

**Remediation**

1. Contain the domain controllers. 
    1. Remediate the remote code execution attempt.
    2. Look for users also logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA. 
2. Contain the source computer.
    1. Find the tool that performed the attack and remove it.
    2. Look for users also logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA.

**Prevention**

- Make sure all DNS servers in the environment are up-to-date, and patched against [CVE-2018-8626](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8626). 

## Suspected identity theft (pass-the-hash) (external ID 2017)

*Previous name:* Identity theft using Pass-the-Hash attack

**Description**

Pass-the-Hash is a lateral movement technique in which attackers steal a user’s NTLM hash from one computer and use it to gain access to another computer.

**TP, B-TP, or FP?**
1. Determine if the hash was used from computers the user is using regularly? 
    - If the hash was used from computers used regularly, **Close** the alert as an **FP**.  
 
**Understand the scope of the breach**

1. Investigate the [source and destination computers](investigate-a-computer.md) further.  
2. Investigate the [compromised user](investigate-a-computer.md).
 
**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA.
2. Contain the source and destination computers.
3. Find the tool that performed the attack and remove it.
4. Look for users logged in around the same time of the activity, as they may also be compromised. Reset their passwords and enable MFA.

## Suspected identity theft (pass-the-ticket) (external ID 2018)

*Previous name:* Identity theft using Pass-the-Ticket attack

**Description**

Pass-the-Ticket is a lateral movement technique in which attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by reusing the stolen ticket. In this detection, a Kerberos ticket is seen used on two (or more) different computers.

**TP, B-TP, or FP?**

Successfully resolving IPs to computers in the organization is critical to identify pass-the-ticket attacks from one computer to another. 

1. Check if the IP address of one or both computers belong to a subnet that is allocated from an undersized DHCP pool, for example, VPN, VDI or WiFi? 
2. Is the IP address shared (for example, by a NAT device)?  
3. Is the sensor not resolving one or more of the destination IP addresses? If a destination IP address is not resolved, it may indicate that the correct ports between sensor and devices are not open correctly. 

    If the answer to any of the previous questions is **yes**, check if the source and destinations computers are the same. If they are the same, it is an **FP** and there were no real attempts at **pass-the-ticket**. 

The [Remote Credential Guard](https://docs.microsoft.com/windows/security/identity-protection/remote-credential-guard) feature of RDP connections, when used with Windows 10 on Windows Server 2016 and newer, can cause **B-TP** alerts. 
Using the alert evidence, check if the user made a remote desktop connection from the source computer to the destination computer.

1. Check for correlating evidence.
2. If there is correlating evidence, check if the RDP connection was made using Remote Credential Guard. 
3. If the answer is yes, **Close** the security alert as a **T-BP** activity. 

There are custom applications that forward tickets on behalf of users. These applications have delegation rights to user tickets.

1. Is a custom application type like the one previously described, currently on the destination computers? Which services is the application running? Are the services acting on behalf of users, for example, accessing databases?
    - If the answer is yes, **Close** the security alert as a **T-BP** activity.
2. Is the destination computer a delegation server?
    - If the answer is yes, **Close** the security alert, and exclude that computer as a **T-BP** activity.
 
**Understand the scope of the breach**

1. Investigate the [source and destination computers](investigate-a-computer.md).  
2. Investigate the [compromised user](investigate-a-computer.md). 

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA.
2. Contain the source and destination computers.
3. Find the tool that performed the attack and remove it.
4. Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA.
5. If you have Windows Defender ATP installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.

## Suspected NTLM relay attack (Exchange account) (external ID 2037) - preview

**Description**

An Exchange Server can be configured to triggered NTLM authentication with the Exchange Server account to a remote http server run by an attacker. This server waits for the Exchange Server communication to relay its own sensitive authentication to any other server, or even more interestingly to the Active Directory over LDAP, and grabs the authentication information.

Once the relay server receives the NTLM authentication, it provides a challenge that was originally created by the target server. The client responds to the challenge, preventing an attacker from taking the response, and using it to continue NTLM negotiation with the target domain controller. 

In this detection, an alert is triggered when Azure ATP identify use of Exchange account credentials from a suspicious source.

**TP, B-TP, or FP?**

1. Check the source computers behind the IP addresses. 
    1. If the source computer is an Exchange Server, **Close** the security alert as an **FP** activity.
    2. Determine if the source account should authenticate using NTLM from these computers? If they should authenticate, **Close** the security alert, and exclude these computers as a **B-TP** activity.

**Understand the scope of the breach**

1. Continue [investigating the source computers](investigate-a-computer.md) behind the IP addresses involved.  
2. Investigate the [source account](investigate-a-user.md).

**Suggested remediation and steps for prevention**

1. Contain the source computers
    1. Find the tool that preformed the attack and remove it.
    2. Look for users logged on around the same time as the activity occurred, as they may also be compromised. Reset their passwords and enable MFA.
2. Force the use of sealed NTLMv2 in the domain, using the **Network security: LAN Manager authentication level** group policy. For more information, see [LAN Manager authentication level instructions](https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level) for setting the group policy for domain controllers. 

## Suspected overpass-the-hash attack (encryption downgrade) (external ID 2008) 

*Previous name:* Encryption downgrade activity

**Description**

Encryption downgrade is a method of weakening Kerberos using encryption downgrade of different fields of the protocol, normally encrypted using the highest levels of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, Azure ATP learns the Kerberos encryption types used by computers and users, and alerts you when a weaker cypher is used that is unusual for the source computer, and/or user, and matches known attack techniques. 

In an over-pass-the-hash attack, an attacker can use a weak stolen hash to create a strong ticket, with a Kerberos AS request. In this detection,  instances are detected where the AS_REQ message encryption type from the source computer is downgraded, when compared to the previously learned behavior (the computer used AES).

**TP, B-TP, or FP?**
1. Determine if the smartcard configuration recently changed. 
   - Did the accounts involved recently have smartcard configurations changes?  
    
     If the answer is yes, **Close** the security alert as a **T-BP** activity. 

Some legitimate resources don’t support strong encryption ciphers and may trigger this alert. 

2. Do all source users share something? 
   1. For example, are all of your marketing personnel accessing a specific resource that could cause the alert to be triggered?
   2. Check the resources accessed by those tickets. 
       - Check this in Active Directory by checking the attribute *msDS-SupportedEncryptionTypes*, of the resource service account.
   3. If there is only one accessed resource, check if it is a valid resource for these users to access.   

      If the answer to one of the previous questions is **yes**, it is likely to be a **T-BP** activity. Check if the resource can support a strong encryption cipher, implement a stronger encryption cipher where possible, and **Close** the security alert.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).  
2. Investigate the [compromised user](investigate-a-computer.md). 

**Suggested remediation and steps for prevention** 

**Remediation**
1. Reset the password of the source user and enable MFA. 
2. Contain the source computer. 
3. Find the tool that performed the attack and remove it. 
4. Look for users logged on around the time of the activity, as they may also be compromised. Reset their passwords and enable MFA  

**Prevention**
 
1. Configure your domain to support strong encryption cyphers, and remove *Use Kerberos DES encryption types*. Learn more about [encryption types and Kerberos](https://blogs.msdn.microsoft.com/openspecification/2011/05/30/windows-configurations-for-kerberos-supported-encryption-type/). 
2. Make sure the domain functional level is set to support strong encryption cyphers.  
3. Give preference to using applications that support strong encryption cyphers.

## Suspected overpass-the-hash attack (Kerberos) (external ID 2002) 

*Previous name:* Unusual Kerberos protocol implementation (potential overpass-the-hash attack)

**Description**

Attackers use tools that implement various protocols such as Kerberos and SMB in non-standard ways. While Microsoft Windows accepts this type of network traffic without warnings, Azure ATP is able to recognize potential malicious intent. The behavior is indicative of techniques such as over-pass-the-hash, Brute Force, and advanced ransomware exploits such as WannaCry, are used.

**TP, B-TP, or FP?**

Sometimes applications implement their own Kerberos stack, not in accordance with the Kerberos RFC. 

1. Check if the source computer is running an application with its own Kerberos stack, not in accordance with Kerberos RFC.  
2. If the source computer is running such an application, and it should **not** do this, fix the application configuration. **Close** the security alert as a **T-BP** activity.  
3. If the source computer is running such an application and it should continue to do so, **Close** the security alert as a **T-BP** activity and exclude the computer. 

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).  
2. If there is a [source user](investigate-a-user.md), investigate. 

**Suggested remediation and steps for prevention** 

1. Reset the passwords of the compromised users and enable MFA.
2. Contain the source computer.
3. Find the tool that performed the attack and remove it.
4. Look for users logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA.  
5. Reset the passwords of the source user and enable MFA.

> [!div class="nextstepaction"]
> [Domain dominance alert tutorial](atp-domain-dominance-alerts.md)

## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](atp-reconnaissance-alerts.md)
- [Compromised credential alerts](atp-compromised-credentials-alerts.md)
- [Domain dominance alerts](atp-domain-dominance-alerts.md)
- [Exfiltration alerts](atp-exfiltration-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
