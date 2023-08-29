---
title: Configure Windows Event collection
description: In this step of installing Microsoft Defender for Identity, you configure Windows Event collection.
ms.date: 08/16/2023
ms.topic: how-to
---

# Configure Windows Event collection

Microsoft Defender for Identity detection relies on specific Windows Event log entries to enhance some detections and provide additional information on who performed specific actions such as NTLM logons, security group modifications, and similar events. For the correct events to be audited and included in the Windows Event Log, your domain controllers require accurate Advanced Audit Policy settings. Incorrect Advanced Audit Policy settings can lead to the required events not being recorded in the Event Log and result in incomplete Defender for Identity coverage.

To enhance threat detection capabilities, Defender for Identity needs the following Windows Events to be [configured](#configure-audit-policies) and [collected](#configure-event-collection) by Defender for Identity:

## Relevant Windows Events

### For Active Directory Federation Services (AD FS) events

- 1202 - The Federation Service validated a new credential
- 1203 - The Federation Service failed to validate a new credential
- 4624 - An account was successfully logged on
- 4625 - An account failed to log on

### For Active Directory Certificate Services (AD CS) events

- 4870: Certificate Services revoked a certificate
- 4882: The security permissions for Certificate Services changed
- 4885: The audit filter for Certificate Services changed
- 4887: Certificate Services approved a certificate request and issued a certificate
- 4888: Certificate Services denied a certificate request
- 4890: The certificate manager settings for Certificate Services changed.
- 4896: One or more rows have been deleted from the certificate database

For more information, see 
[Configure auditing for AD CS](#configure-auditing-for-ad-cs).
### For other events

- 1644 - LDAP search
- 4662 - An operation was performed on an object
- 4726 - User Account Deleted
- 4728 - Member Added to Global Security Group
- 4729 - Member Removed from Global Security Group
- 4730 - Global Security Group Deleted
- 4732 - Member Added to Local Security Group
- 4733 - Member Removed from Local Security Group
- 4741 - Computer Account Added
- 4743 - Computer Account Deleted
- 4753 - Global Distribution Group Deleted
- 4756 - Member Added to Universal Security Group
- 4757 - Member Removed from Universal Security Group
- 4758 - Universal Security Group Deleted
- 4763 - Universal Distribution Group Deleted
- 4776 - Domain Controller Attempted to Validate Credentials for an Account (NTLM)
- 5136 - A directory service object was modified
- 7045 - New Service Installed
- 8004 - NTLM Authentication

## Configure audit policies

Modify the Advanced Audit Policies of your domain controller using the following instructions:

1. Log in to the server as **Domain Administrator**.
1. Open the Group Policy Management Editor from **Server Manager** > **Tools** > **Group Policy Management**.
1. Expand the **Domain Controllers Organizational Units**, right-click  **Default Domain Controllers Policy**, and then select **Edit**.

    > [!NOTE]
    > You can use the Default Domain Controllers Policy or a dedicated GPO to set these policies.

    ![Edit domain controller policy.](media/advanced-audit-policy-check-step-1.png)

1. From the window that opens, go to **Computer Configuration** > **Policies** > **Windows Settings** > **Security Settings** and depending on the policy you want to enable, do the following:

    **For Advanced Audit Policy Configuration**

    1. Go to **Advanced Audit Policy Configuration** > **Audit Policies**.
        ![Advanced Audit Policy Configuration.](media/advanced-audit-policy-check-step-2.png)
    1. Under **Audit Policies**, edit each of the following policies and select **Configure the following audit events** for both **Success** and **Failure** events.

        | Audit policy | Subcategory | Triggers event IDs |
        | --- |---|---|
        | Account Logon | Audit Credential Validation | 4776 |
        | Account Management | Audit Computer Account Management | 4741, 4743 |
        | Account Management | Audit Distribution Group Management | 4753, 4763 |
        | Account Management | Audit Security Group Management | 4728, 4729, 4730, 4732, 4733, 4756, 4757, 4758 |
        | Account Management | Audit User Account Management | 4726 |
        | DS Access | Audit Directory Service Access | 4662 - For this event, it's also necessary to [Configure object auditing](#configure-object-auditing).  |
        | DS Access | Audit Directory Service Changes | 5136  |
        | System | Audit Security System Extension | 7045 |

        For example, to configure **Audit Security Group Management**, under **Account Management**, double-click **Audit Security Group Management**, and then select **Configure the following audit events** for both **Success** and **Failure** events.

        ![Audit Security Group Management.](media/advanced-audit-policy-check-step-4.png)

1. From an elevated command prompt type `gpupdate`.

1. After applying via GPO, the new events are visible in the Event Viewer, under **Windows Logs** -> **Security**.

### Event ID 8004

To audit Event ID 8004, more configuration steps are required.

> [!NOTE]
>
> - Domain group policies to collect Windows Event 8004 should **only** be applied to domain controllers.
> - When Windows Event 8004 is parsed by Defender for Identity Sensor, Defender for Identity NTLM authentications activities are enriched with the server accessed data.

1. Following the initial steps mentioned [above](#configure-audit-policies), open **Group Policy Management** and navigate to the **Default Domain Controllers Policy**.
1. Go to **Local Policies** > **Security Options**.
1. Under **Security Options**, configure the specified security policies, as follows

    | Security policy setting | Value |
    |---|---|
    | Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers | Audit all |
    | Network security: Restrict NTLM: Audit NTLM authentication in this domain | Enable all |
    | Network security: Restrict NTLM: Audit Incoming NTLM Traffic | Enable auditing for all accounts |

    For example, to configure **Outgoing NTLM traffic to remote servers**, under **Security Options**, double-click **Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers**, and then select **Audit all**.

    ![Audit Outgoing NTLM traffic to remote servers.](media/advanced-audit-policy-check-step-3.png)

## Configure auditing for AD CS

If you're working with a dedicated server with Active Directory Certificate Services (AD CS) configured, make sure to configure auditing as follows to view dedicated alerts and Secure Score reports:

1. Create a group policy to apply to your AD CS server. Edit it and configure the following auditing settings:

    1. Go to and double click **Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Certification Services**, and then configure audit events for **Success and Failure**. For example:

    ![Screenshot of the Group Policy Management Editor](media/configure-windows-event-collection/group-policy-management-editor.png)

1. Configure auditing on the certificate authority (CA) using one of the following methods:

    - **To configure CA auditing using the command line**, run:

        ```cmd
        certutil –setreg CA\AuditFilter 127 

        net stop certsvc && net start certsvc
        ````

    - **To Configure CA auditing using the GUI**:

        1. Select **Start -> Certification Authority (MMC Desktop application)**. Right-click your CA's name and select **Properties**. For example: 

            ![Screenshot of the Certification Authority dialog.](media/configure-windows-event-collection/certification-authority.png)

        1. Select the **Auditing** tab, select all the events you want to audit, and then select **Apply**. For example:


            ![Screenshot of the Auditing tab.](media/configure-windows-event-collection/auditing.png)
> [!NOTE]
> Configuring "Start and Stop Active Directory Certificate Services" event auditing may cause restarts delays when dealing with a large AD CS database. Consider removing irrelevant entries from the DB, or alternatively, refrain from enabling this specific type of event.

For more information, see [For Active Directory Certificate Services (AD CS) events](#for-active-directory-certificate-services-ad-cs-events).

## Configure object auditing

To collect 4662 events, it's also necessary to configure object auditing on the user, group and computer objects. Here's how to enable auditing on all users, groups, and computers in the Active Directory domain:

> [!NOTE]
> It is important to [review and verify your audit policies](#configure-audit-policies) before enabling event collection to ensure that the domain controllers are properly configured to record the necessary events.
>
>If configured properly, this auditing should have minimal effect on server performance.

1. Go to the **Active Directory Users and Computers** console.
1. Select the domain you want to audit.
1. Select the **View** menu and select **Advanced Features**.
1. Right-click the domain and select **Properties**.

    ![Container properties.](media/container-properties.png)

1. Go to the **Security** tab, and select **Advanced**.

    ![Advanced security properties.](media/security-advanced.png)

1. In **Advanced Security Settings**, choose the **Auditing** tab. Select **Add**.

    ![Select auditing tab.](media/auditing-tab.png)

1. Choose **Select a principal**.

    ![Select a principal.](media/select-a-principal.png)

1. Under **Enter the object name to select**, type **Everyone**. Then select **Check Names**, and select **OK**.

    ![Select everyone.](media/select-everyone.png)

1. You'll then return to **Auditing Entry**. Make the following selections:

    1. For **Type** select **Success**.
    1. For **Applies to** select **Descendant User objects.**
    1. Under **Permissions**, scroll down and select the **Clear all** button.

        :::image type="content" source="media/clear-all.png" alt-text="Select Clear all.":::

    1. Then scroll back up and select **Full Control**. All the permissions will be selected. Then **uncheck** the **List contents**, **Read all properties**, and **Read permissions** permissions. Select **OK**. This will set all the **Properties** settings to **Write**. Now when triggered, all relevant changes to directory services will appear as 4662 events.

        ![Select permissions.](media/select-permissions.png)

1. Then repeat the steps above, but for **Applies to**, select the following object types:
   - **Descendant Group Objects**
   - **Descendant Computer Objects**
   - **Descendant msDS-GroupManagedServiceAccount Objects**
   - **Descendant msDS-ManagedServiceAccount Objects**

> [!NOTE]
> Assigning the auditing permissions on the 'All descendant objects' would work as well, but we only require the object types as detailed above.
>

### Auditing for specific detections

Some detections require auditing specific Active Directory objects. To do so, follow the steps above, but note the changes below regarding which objects to audit and which permissions to include.

#### Enable auditing on an ADFS object

1. Go to the **Active Directory Users and Computers** console, and choose the domain you want to enable the logs on.
1. Navigate to **Program Data** > **Microsoft** > **ADFS**.

    ![ADFS container.](media/adfs-container.png)

1. Right-click **ADFS** and select **Properties**.
1. Go to the **Security** tab, and select **Advanced**.
1. In **Advanced Security Settings**, choose the **Auditing** tab. Select **Add**.
1. Choose **Select a principal**.
1. Under **Enter the object name to select**, type **Everyone**. Then select **Check Names**, and select **OK**.
1. You'll then return to **Auditing Entry**. Make the following selections:

    - For **Type** select **All**.
    - For **Applies to** select **This object and all descendant objects**.
    - Under **Permissions**, scroll down and select **Clear all**. Scroll up and select **Read all properties** and **Write all properties**.

    ![Auditing settings for ADFS.](media/audit-adfs.png)

1. Select **OK**.

#### Enable auditing on the Configuration container
<a name="enable-auditing-on-an-exchange-object"></a>

1. Open ADSI Edit. To do this, select **Start**, select **Run**, type *ADSIEdit.msc*, and then select **OK**.
1. On the **Action** menu, select **Connect to**.
1. In the **Connection Settings** dialog box under **Select a well known Naming Context**, select **Configuration**, and then select **OK**.
1. Expand the **Configuration** container. Under the **Configuration** container, you'll see the **Configuration** node. It will begin with *“CN=Configuration,DC=..."*
1. Right-click the **Configuration** node and select **Properties**.

    ![Configuration node properties.](media/configuration-properties.png)

1. Go to the **Security** tab, and select **Advanced**.
1. In **Advanced Security Settings**, choose the **Auditing** tab. Select **Add**.
1. Choose **Select a principal**.
1. Under **Enter the object name to select**, type **Everyone**. Then select **Check Names**, and select **OK**.
1. You'll then return to **Auditing Entry**. Make the following selections:

    - For **Type** select **All**.
    - For **Applies to** select **This object and all descendant objects**.
    - Under **Permissions**, scroll down and select **Clear all**. Scroll up and select **Write all properties**.

    ![Auditing settings for Configuration.](media/audit-configuration.png)

1. Select **OK**.

## Configure event collection

These events can be collected automatically by the Defender for Identity sensor or, if the Defender for Identity sensor isn't deployed, they can be forwarded to the Defender for Identity standalone sensor in one of the following ways:

- [Configure the Defender for Identity standalone sensor](configure-event-forwarding.md) to listen for SIEM events
- [Configure Windows Event Forwarding](configure-event-forwarding.md)

> [!NOTE]
>
> - Defender for Identity standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the Defender for Identity sensor.

## Event ID 1644

> [!IMPORTANT]
> Defender for Identity no longer requires logging 1644 events. If you have this registry setting enabled, you can remove it.
>
> ```reg
>
>Windows Registry Editor Version 5.00
>
>[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics]
>"15 Field Engineering"=dword:00000005
>
>[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters]
>"Expensive Search Results Threshold"=dword:00000001
>"Inefficient Search Results Threshold"=dword:00000001
>"Search Time Threshold (msecs)"=dword:00000001
>```
>
> No functionality is lost due to this requirement being removed.


## Next steps

> [!div class="step-by-step"]
> [« Plan capacity for Microsoft Defender for Identity](capacity-planning.md)
> [Directory Service accounts »](directory-service-accounts.md)

