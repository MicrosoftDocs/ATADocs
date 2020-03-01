---
# required metadata

title: Azure ATP compromised credentials phase security alerts | Microsoft Docs
d|Description: This article explains the Azure ATP alerts issued when attacks typical of the compromised credentials phase are detected against your organization.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 11/19/2019
ms.topic: tutorial
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
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

# Tutorial: Compromised credential alerts  

Typically, cyber-attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets – such as sensitive accounts, domain administrators, and highly sensitive data. Azure ATP identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](atp-reconnaissance-alerts.md)
2. **Compromised credential**
3. [Lateral Movements](atp-lateral-movement-alerts.md)
4. [Domain dominance](atp-domain-dominance-alerts.md)
5. [Exfiltration](atp-exfiltration-alerts.md) 

To learn more about how to understand the structure, and common components of all Azure ATP security alerts, see [Understanding security alerts](understanding-security-alerts.md).

The following security alerts help you identify and remediate **Compromised credential** phase suspicious activities detected by Azure ATP in your network. In this tutorial, you'll learn how to understand, classify, remediate and prevent the following types of attacks:

> [!div class="checklist"]
> * Honeytoken activity (external ID 2014)
> * Suspected Brute Force attack (Kerberos, NTLM) (external ID 2023)
> * Suspected Brute Force attack (LDAP) (external ID 2004)
> * Suspected Brute Force attack (SMB) (external ID 2033)
> * Suspected WannaCry ransomware attack (external ID 2035)
> * Suspected use of Metasploit hacking framework (external ID 2034)
> * Suspicious VPN connection (external ID 2025)

## Honeytoken activity (external ID 2014) 

*Previous name:* Honeytoken activity

**Description**

Honeytoken accounts are decoy accounts set up to identify and track malicious activity that involves these accounts. Honeytoken accounts should be left unused, while having an attractive name to lure attackers (for example,
SQL-Admin). Any activity from them might indicate malicious behavior.

For more information on honeytoken accounts, see [Configure detection exclusions and honeytoken accounts](install-atp-step7.md).

**TP, B-TP, or FP**

1. Check if the owner of the source computer used the Honeytoken account to authenticate, using the method described in the suspicious activity page (for example, Kerberos, LDAP, NTLM).

    If the owner of the source computer used the honeytoken account to authenticate, using the exact method described in the alert, *Close* the security alert, as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source user](investigate-a-user.md).
2. Investigate the [source computer](investigate-a-computer.md).

    > [!NOTE]
    > If the authentication was made using NTLM, in some scenarios, there may not be enough information available about the server the source computer tried to access. Azure ATP captures the source computer data based on Windows Event 4776, which contains the computer defined source computer name. <br>
    > Using Windows Event 4776 to capture this information, the source field for this information is occasionally overwritten by the device or software to display only Workstation or MSTSC. If you frequently have devices that display as Workstation or MSTSC, make sure to enable NTLM auditing on the relevant domain controllers to get the true source computer name.<br>  
    > To enable NTLM auditing, turn on Windows Event 8004 (NTLM authentication event that includes information about the source computer, user account, and the server the source machine tried to access).

**Suggested remediation and steps for prevention**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.

## Suspected Brute Force attack (Kerberos, NTLM) (external ID 2023)

*Previous name:* Suspicious authentication failures

**Description**

In a brute-force attack, the attacker attempts to authenticate with multiple passwords on different accounts until a correct password is found or by using one password in a large-scale password spray that works for at least one account. Once found, the attacker logs in using the authenticated account.

In this detection, an alert is triggered when many authentication failures occur using Kerberos, NTLM, or use of a password spray is detected. Using Kerberos or NTLM, this type of attack is typically committed either *horizontal*, using a small set of passwords across many users, *vertical* with a large set of passwords on a few users, or any combination of the two.

In a password spray, after successfully enumerating a list of valid users from the domain controller, attackers try ONE carefully crafted password against ALL of the known user accounts (one password to many accounts). If the initial password spray fails, they try again, utilizing a different carefully crafted password, normally after waiting 30 minutes between attempts. The wait time allows attackers to avoid triggering most time-based account lockout thresholds. Password spray has quickly become a favorite technique of both attackers and pen testers. Password spray attacks have proven to be effective at gaining an initial foothold in an organization, and for making subsequent lateral moves, trying to escalate privileges. The minimum period before an alert can be triggered is one week.

**Learning period**
 <br>1 week

**TP, B-TP, or FP**

It is important to check if any login attempts ended with successful authentication.

1. If any login attempts ended successfully, check if  any of the **Guessed accounts** are normally used from that source computer.
   - Is there any chance these accounts failed because a wrong password was used?  
   - Check with the user(s) if they generated the activity, (failed to login a fe times and then succeeded). 

     If the answer to the questions above is **yes**,  **Close** the security alert as a B-TP activity.

2. If there are no **Guessed accounts**, check if any of the **Attacked accounts** are normally used from the source computer.
    - Check if there is a script running on the source computer with wrong/old credentials?
    - If the answer to the previous question is **yes**, stop and edit, or delete the script. **Close** the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the source computer.  
1. On the alert page, check which, if any, users were guessed successfully.
    - For each user that was guessed successfully, [check their profile](investigate-a-user.md) to investigate further.

    > [!NOTE]
    > Examine the evidence to learn the authentication protocol used. If NTLM authentication was used, enable NTLM auditing of Windows Event 8004 on the domain controller to determine the resource server the users attempted to access. Windows Event 8004 is the NTLM authentication event that includes information about the source computer, user account, and server that the source user account  attempted to access. <br>
    > Azure ATP captures the source computer data based on Windows Event 4776, which contains the computer defined source computer name. Using Windows Event 4776 to capture this information, the information source field is occasionally overwritten by the device or software and only displays Workstation or MSTSC as the information source. In addition, the source computer might not actually exist on your network. This is possible because adversaries commonly target open, internet-accessible servers from outside the network and then use it to enumerate your users. If you frequently have devices that display as Workstation or MSTSC, make sure to enable NTLM auditing on the domain controllers to get the accessed resource server name. You should also investigate this server, check if it is opened to the internet, and if you can, close it.
    
1. When you learn which server sent the authentication validation, investigate the server by checking events, such as Windows Event 4624, to better understand the authentication process. 
1. Check if this server is exposed to the internet using any open ports. 
    For example, is the server open using RDP to the internet?

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
2. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
3. Reset the passwords of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
4. Enforce [complex and long passwords](https://docs.microsoft.com/windows/device-security/security-policy-settings/password-policy) in the organization, it will provide the necessary first level of security against future brute-force attacks.

## Suspected Brute Force attack (LDAP) (external ID 2004) 

*Previous name:* Brute force attack using LDAP simple bind

**Description**

In a brute-force attack, the attacker attempts to authenticate with many different passwords for different accounts until a correct password is found for at least one account. Once found, an attacker can log in using that account.  

In this detection, an alert is triggered when Azure ATP detects a massive number of simple bind authentications. This alert detects brute force attacks performed either *horizontally* with a small set of passwords across many users, *vertically* with a large set of passwords on just a few users, or any combination of the two options.

**TP, B-TP, or FP**

It is important to check if any login attempts ended with successful authentication.

1. If any login attempts ended successfully, are any of the **Guessed accounts** normally used from that source computer?
   - Is there any chance these accounts failed because a wrong password was used?  
   - Check with the user(s) if they generated the activity, (failed to login a few times and then succeeded).

     If the answer to the previous questions is **yes**,  **Close** the security alert as a B-TP activity.

2. If there are no **Guessed accounts**, check if any of the **Attacked accounts** are normally used from the source computer.
   - Check if there is a script running on the source computer with wrong/old credentials?

     If the answer to the previous question is **yes**, stop and edit, or delete the script. **Close** the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).  
2. On the alert page, check which users, if any, were guessed successfully. For each user that was guessed successfully, [check their profile](investigate-a-user.md) to investigate further.

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
2. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
3. Reset the passwords of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
4. Enforce [complex and long passwords](https://docs.microsoft.com/windows/device-security/security-policy-settings/password-policy) in the organization, it will provide the necessary first level of security against future brute-force attacks.
5. Prevent future usage of LDAP clear text protocol in your organization.

## Suspected Brute Force attack (SMB) (external ID 2033) 

*Previous name:* Unusual protocol implementation (potential use of malicious tools such as Hydra)

**Description**

Attackers use tools that implement various protocols such as SMB, Kerberos, and NTLM in non-standard ways. While this type of network traffic is accepted by Windows without warnings, Azure ATP is able to recognize potential malicious intent. The behavior is indicative of brute force techniques.

**TP, B-TP, or FP**

1. Check if the source computer is running an attack tool such as Hydra.
   1. If the source computer is running an attack tool, this alert is a **TP**. Follow the instructions in **understand the scope of the breach**, above.

Occasionally, applications implement their own NTLM or SMB stack.

1. Check if the source computer is running its own NTLM or SMB stack type of application.
    1. If the source computer is found running that type of application, and it should not continue to run, fix the application configuration as needed. **Close** the security alert as a **T-BP** activity.
    2. If the source computer is found running that type of application, and it should continue doing so, **Close** the security alert as a **T-BP** activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
2. Investigate the [source user](investigate-a-user.md)) (if there is a source user).

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable  multi-factor authentication.
2. Contain the source computer
   1. Find the tool that performed the attack and remove it.
   2. Search for users logged on around the time of the activity, as they may also be compromised.
   3. Reset their passwords and enable multi-factor authentication.
3. Enforce [Complex and long passwords](https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/password-policy) in the organization. Complex and long passwords provide the necessary first level of security against future brute-force attacks.
4. [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

## Suspected WannaCry ransomware attack (external ID 2035)

*Previous name:* Unusual protocol implementation (potential WannaCry ransomware attack)

**Description**

Attackers use tools that implement various protocols in non-standard ways. While this type of network traffic is accepted by Windows without warnings, Azure ATP is able to recognize potential malicious intent. The behavior is indicative of techniques used by advanced ransomware, such as WannaCry.

**TP, B-TP, or FP**

1. Check if WannaCry is running on the source computer. 

    - If WannaCry is running, this alert is a **TP**. Follow the instructions in **understand the scope of the breach**, above.

Occasionally, applications implement their own NTLM or SMB stack.

1. Check if the source computer is running its own NTLM or SMB stack type of application. 
    1. If the source computer is found running that type of application, and it should not continue to run, fix the application configuration as needed. **Close** the security alert as a **T-BP** activity.
    2. If the source computer is found running that type of application, and it should continue doing so, **Close** the security alert as a **T-BP** activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
2. Investigate the [compromised user](investigate-a-user.md).

**Suggested remediation and steps for prevention**

1. Contain the source computer.
      - [Remove WannaCry](https://support.microsoft.com/help/890830/remove-specific-prevalent-malware-with-windows-malicious-software-remo)
      - WanaKiwi can decrypt the data in the hands of some ransom software, but only if the user has not restarted or turned off the computer. For more information, see [WannaCry Ransomware](https://answers.microsoft.com/en-us/windows/forum/windows_10-security/wanna-cry-ransomware/5afdb045-8f36-4f55-a992-53398d21ed07?auth=1)
      - Look for users logged on around the time of the activity, as they might also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
2. Patch all of your machines, making sure to apply security updates. 
      - [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

## Suspected use of Metasploit hacking framework (external ID 2034)

*Previous name:* Unusual protocol implementation (potential use of Metasploit hacking tools)

**Description**

Attackers use tools that implement various protocols (SMB, Kerberos, NTLM) in non-standard ways. While this type of network traffic is accepted by Windows without warnings, Azure ATP is able to recognize potential malicious intent. The behavior is indicative of techniques such as use of the Metasploit hacking framework. 

**TP, B-TP, or FP**

1. Check if the source computer is running an attack tool such as Metasploit or Medusa.

2. If yes, it is a true positive. Follow the instructions in **understand the scope of the breach**, above.

Occasionally, applications implement their own NTLM or SMB stack.

 1. Check if the source computer is running its own NTLM or SMB stack type of application. 
    1. If the source computer is found running that type of application, and it should not continue to run, fix the application configuration as needed. **Close** the security alert as a **T-BP** activity.
    2. If the source computer is found running that type of application, and it should continue doing so, **Close** the security alert as a **T-BP** activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
2. If there is a source user, [investigate the user](investigate-a-user.md).

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
2. Contain the source computer.
   1. Find the tool that performed the attack and remove it.
   2. Search for users logged on around the time of the activity, as they may also be compromised. Reset their passwords and enable multi-factor authentication.
3. Reset the passwords of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal. 
4. [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/) 

## Suspicious VPN connection (external ID 2025) 

*Previous name:* Suspicious VPN connection 

**Description**

Azure ATP learns the entity behavior for users VPN connections over a sliding period of one month. 

The VPN-behavior model is based on the machines users log in to and the locations the users connect from. 

An alert is opened when there is a deviation from the user’s behavior based on a machine learning algorithm.

**Learning period**

30 days from the first VPN connection, and at least 5 VPN connections in the last 30 days, per user.

**TP, B-TP, or FP**

1. Is the suspicious user supposed to be performing these operations?
    1. Did the user recently change their location?
    2. Is the user travelling and connecting from a new device?

If the answer is yes to the questions above, **Close** the security alert as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
2. If there is a source user, [investigate the user](investigate-a-user.md).

**Suggested remediation and steps for prevention**

1. Reset the password of the user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
2. Consider blocking this user from connecting using VPN.
3. Consider blocking this computer from connecting using VPN.
4. Check if there are other users connected through VPN from these locations, and check if they are compromised.

> [!div class="nextstepaction"]
> [Lateral Movement alert tutorial](atp-lateral-movement-alerts.md)

## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Investigate a user](investigate-a-user.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](atp-reconnaissance-alerts.md)
- [Lateral movement alerts](atp-lateral-movement-alerts.md)
- [Domain dominance alerts](atp-domain-dominance-alerts.md)
- [Exfiltration alerts](atp-exfiltration-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
