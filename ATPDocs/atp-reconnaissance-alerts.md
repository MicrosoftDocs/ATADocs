---
# required metadata

title: Azure ATP reconnaissance phase security alerts | Microsoft Docs
d|Description: This article explains the Azure ATP alerts issued when attacks typically part of reconnaissance phase efforts are detected against your organization. 
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 1/15/2019
ms.topic: tutorial
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: e9cf68d2-36bd-4b0d-b36e-7cf7ded2618e

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---


# Tutorial: Reconnaissance alerts  

Typically, cyber attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. Azure ATP identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. **Reconnaissance**
2. [Compromised credentials](atp-compromised-credentials-alerts.md)
3. [Lateral Movements](atp-lateral-movement-alerts.md)
4. [Domain dominance](atp-domain-dominance-alerts.md)
5. [Exfiltration](atp-exfiltration-alerts.md) 

To learn more about how to understand the structure, and common components of all Azure ATP security alerts, see [Understanding security alerts](understanding-security-alerts.md).

The following security alerts help you identify and remediate **Reconnaissance** phase suspicious activities detected by Azure ATP in your network.

In this tutorial, learn how to understand, classify, remediate, and prevent the following types of attacks:

> [!div class="checklist"]
> * Account enumeration reconnaissance (external ID 2003)
> * Network mapping reconnaissance (DNS) (external ID 2007)
> * User and IP address reconnaissance (SMB) (external ID 2012)
> * User and Group membership reconnaissance (SAMR) (external ID 2021)

## Account enumeration reconnaissance (external ID 2003) 


*Previous name:* Reconnaissance using account enumeration

**Description**

In account enumeration reconnaissance, an attacker uses a dictionary with thousands of user names, or tools such as KrbGuess in an attempt to guess user names in the domain. The attacker makes Kerberos requests using these names to try to find a valid username in the domain. If a guess successfully determines a username, the attacker gets the Kerberos error **Preauthentication required** instead of **Security principal unknown**.

In this detection, Azure ATP detects where the account enumeration attack came from, the total number of guess attempts, and how many attempts were matched. If there are too many unknown users, Azure ATP detects it as a suspicious activity.

**TP, B-TP, or FP**

Some servers and applications query domain controllers to determine if accounts exist in legitimate usage scenarios.

To determine if this query was a **TP**, **BTP** or **FP**, click the alert to get to its detail page:

1. Check if the source computer was supposed to perform this type of query. Examples of a **B-TP** in this case could be Microsoft Exchange servers or human resource systems.

2. Check the account domains.
   - Do you see additional users who belong to a different domain? 
     <br>A server misconfiguration such as Exchange/Skype or ADSF can cause additional users that belong to different domains.
   - Look at the configuration of the problematic service to fix the misconfiguration.

     If you answered **yes** to the questions above, it is a **B-TP** activity. *Close* the security alert.<br>

As the next step, look at the source computer: 

1. Is there a script or application running on the source computer that could generate this behavior?  
   - Is the script an old script running with old credentials? <br>If yes, stop and edit or delete the script. 
   - Is the application an administrative or security script/application that is supposed to run in the environment?
 
     If you answered **yes** to previous question, *Close* the security alert and exclude that computer. It is probably a **B-TP** activity.

Now, look at the accounts:<br>
<br>Attackers are known to use a dictionary of randomized account names to find existing account names in an organization.

1. Do the non-existing accounts look familiar?  
   - If the non-existing accounts look familiar, they may be disabled accounts or belong to employees who left the company.
   - Check for an application or script that checks to determine which accounts still exist in Active Directory.

     If you answered **yes** to one of the previous questions, *Close* the security alert, it is probably a **B-TP** activity.

2. If any of the guess attempts match existing account names, the attacker knows of the existence of accounts in your environment and can attempt to use brute force to access your domain using the discovered user names. 
    - Check the guessed account names for additional suspicious activities. 
    - Check to see if any of the matched accounts are sensitive accounts.

### Understand the scope of the breach

1. Investigate the source computer
2. If any of the guess attempts match existing account names, the attacker knows of the existence of accounts in your environment, and can use brute force to attempt to access your domain using the discovered user names. Investigate the existing accounts using the [user investigation guide](investigate-a-user.md). 

### Suggested remediation and steps for prevention

1. Contain the source [computer](investigate-a-computer.md). 
    1. Find the tool that performed the attack and remove it.
    2. Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. 
    3. Reset their passwords and enable MFA.
2. Enforce [Complex and long passwords](https://docs.microsoft.com/windows/device-security/security-policy-settings/password-policy) in the organization. Complex and long passwords provide the necessary first level of security against brute-force attacks. Brute force attacks are typically the next step in the cyber-attack kill chain following enumeration. 

## Network mapping reconnaissance (DNS) (external ID 2007) 


*Previous name:* Reconnaissance using DNS

**Description**

Your DNS server contains a map of all the computers, IP addresses, and services in your network. This information is used by attackers to map your network structure and target interesting computers for later steps in their attack. 
 
There are several query types in the DNS protocol. This Azure ATP security alert detects the AXFR (transfer) request originating from non-DNS servers.

**TP, B-TP, or FP**

1. Check if the source computer is a DNS server.

    - If the source computer **is** a DNS server, close the security alert as an **FP**. 
    - To prevent future **FPs**, verify that UDP port 53 is **open** between the Azure ATP sensor and the source computer.

Security scanners and legitimate applications can  generate DNS queries. 

1. Check if this source computer is supposed to generate this type of activity?

    - If this source computer is supposed to generate this type of activity, **Close** the security alert and exclude the computer as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md). 

**Suggested remediation and steps for prevention**

**Remediation:**
1. Contain the source computer. 
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.

**Prevention:**
It is important to preventing future attacks using AXFR queries by securing your internal DNS server.

1. Secure your internal DNS server to prevent reconnaissance using DNS by disabling zone transfers or by [restricting zone transfers](https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee649273(v=ws.10)) only to specified IP addresses. Modifying zone transfers is one task among a checklist that should be addressed for [securing your DNS servers from both internal and external attacks](https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee649273(v=ws.10)).

## User and IP address reconnaissance (SMB) (external ID 2012) 


*Previous name:* Reconnaissance using SMB Session Enumeration

### Description

Enumeration using Server Message Block (SMB) protocol enables attackers to get information about where users recently logged on. Once attackers have this information, they can move laterally in the network to get to a specific sensitive account.

In this detection, an alert is triggered when an SMB session enumeration is performed against a domain controller. 

**TP, B-TP, or FP**

Security scanners and applications may legitimately query domain controllers for open SMB sessions.

1. Is this source computer supposed to generate activities of this type?
2. Is there some kind of security scanner running on the source computer?  
    If the answer is yes, it is probably a B-TP activity. *Close* the security alert and exclude that computer.
3. Check the users that performed the operation.
    Are those users supposed to perform those actions?  
    If the answer is yes, *Close* the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the source computer.  
2. On the alert page, check if there are any exposed users. To further investigate each exposed user, check their profile. We recommend you begin your investigation with sensitive and high investigation priority users.

**Suggested remediation and steps for prevention**

Use the [Net Cease tool](https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b) to harden your environment against this attack.

## User and Group membership reconnaissance (SAMR) (external ID 2021) 


*Previous name:* Reconnaissance using directory services queries 

**Description** 
User and group membership reconnaissance are used by attackers to map the directory structure and target privileged accounts for later steps in their attack. The Security Account Manager Remote (SAM-R) protocol is one of the methods used to query the directory to perform this type of mapping.  
In this detection, no alerts are triggered in the first month after Azure ATP is deployed (learning period). During the learning period, Azure ATP profiles which SAM-R queries are made from which computers, both enumeration and individual queries of sensitive accounts. 

**Learning period**

Four weeks per domain controller starting from the first network activity of SAMR against the specific DC.

**TP, B-TP, or FP** 

1. Click the source computer to go to its profile page.        
   - Is the source computer supposed to generate activities of this type?
     - If yes, *Close* the security alert and exclude that computer, as a  **B-TP** activity. 
   - Check the user/s that performed the operation.
     - Do those users normally log into that source computer, or are they administrators that should be performing those specific actions?   
     - Check the user profile, and their related user activities. Understand their normal user behavior and search for additional suspicious activities using the [user investigation guide](investigate-a-user.md). 
    
     If you answered **yes** to the previous above, *Close* the alert as a **B-TP** activity. 
  
**Understand the scope of the breach**

1. Check the queries that were performed, for example, Enterprise admins, or Administrator,  and determine if they were successful.
2. Investigate each exposed user using the user investigation guide.
3. Investigate the source computer.  
  
**Suggested remediation and steps for prevention**

1. Contain the source computer.
2. Find and remove the tool that performed the attack.
3. Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA.
4. Reset the source user password and enable MFA.
5. Apply Network access and restrict clients allowed to make remote calls to SAM group policy.

> [!NOTE]
> To disable any Azure ATP security alert, contact support.

> [!div class="nextstepaction"]
> [Compromised credential alert tutorial](atp-compromised-credentials-alerts.md)

## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Investigate a user](investigate-a-user.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Compromised credential alerts](atp-compromised-credentials-alerts.md)
- [Lateral movement alerts](atp-lateral-movement-alerts.md)
- [Domain dominance alerts](atp-domain-dominance-alerts.md)
- [Exfiltration alerts](atp-exfiltration-alerts.md)
- [Azure ATP SIEM log reference](cef-format-sa.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
