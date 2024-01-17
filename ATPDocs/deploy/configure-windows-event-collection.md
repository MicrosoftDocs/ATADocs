---
title: Configure audit policies for Windows event logs | Microsoft Defender for Identity
description: Describes how to configure audit policies for Windows event logs as part of deploying a Microsoft Defender for Identity sensor.
ms.date: 01/16/2024
ms.topic: how-to
---

# Configure audit policies for Windows event logs

Microsoft Defender for Identity detection relies on specific Windows Event log entries to enhance detections and provide extra information on the users who performed specific actions, such as NTLM logons and security group modifications.

For the correct events to be audited and included in the Windows Event Log, your domain controllers require specific Windows server Advanced Audit Policy settings. Misconfigured Advanced Audit Policy settings can cause gaps in the Event Log and incomplete Defender for Identity coverage.

This article describes how to configure your Advanced Audit Policy settings as needed for a Defender for Identity sensor, and other configurations for specific event types.

For more information, see [What is Windows event collection for Defender for Identity](event-collection-overview.md) and [Advanced security audit policies](/windows/security/threat-protection/auditing/advanced-security-auditing) in the Windows documentation.

## Generate a report with current configurations via PowerShell

**Prerequisites**: Before running Defender for Identity PowerShell commands, make sure that you downloaded the [Defender for Identity PowerShell module](https://www.powershellgallery.com/packages/DefenderForIdentity/).

Before you start creating new event and audit policies, we recommend that you run the following PowerShell command to generate a report of your current domain configurations:

```powershell
New-MDIConfigurationReport [-Path] <String> [-Mode] <String> [-OpenHtmlReport]
```

Where: 

- **Path** specifies the path to save the reports to
- **Mode** specifies whether you want to use *Domain* or *LocalMachine* mode. In *Domain* mode, the settings are collected from the Group Policy objects. In *LocalMachine* mode, the settings are collected from the local machine.
- **OpenHtmlReport** opens the HTML report after the report is generated

For example, to generate a report and open it in your default browser, run the following command:

```powershell
New-MDIConfigurationReport -Path "C:\Reports" -Mode Domain -OpenHtmlReport
```

For more information, see the [DefenderforIdentity PowerShell reference](/powershell/module/defenderforidentity/new-mdiconfigurationreport).

> [!TIP]
> The `Domain` mode report includes only configurations set as group policies on the domain. If you have settings defined locally on your Domain Controllers, we recommend that you also run the [Test-MdiReadiness.ps1](https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness) script.
>

## Configure auditing for domain controllers

When working with a domain controller, you need to update your Advanced Audit Policy settings and extra configurations for specific events and event types, such as users, groups, computers, and more. Audit configurations for domain controllers include:

- [Advanced Audit Policy settings](#configure-advanced-audit-policy-settings)
- [NTLM auditing](#configure-ntlm-auditing)
- [Domain object auditing](#configure-domain-object-auditing)

### Configure Advanced Audit Policy settings

This procedure describes how to modify your domain controller's Advanced Audit Policies as needed for Defender for Identity.

1. Sign in to the server as **Domain Administrator**.
1. Open the Group Policy Management Editor from **Server Manager** > **Tools** > **Group Policy Management**.
1. Expand the **Domain Controllers Organizational Units**, right-click  **Default Domain Controllers Policy**, and then select **Edit**. For example:

    ![Screenshot of the Edit domain controller policy dialog.](../media/advanced-audit-policy-check-step-1.png)

    > [!NOTE]
    > Use the Default Domain Controllers Policy or a dedicated GPO to set these policies.

1. From the window that opens, go to **Computer Configuration** > **Policies** > **Windows Settings** > **Security Settings** and depending on the policy you want to enable, do the following:

    1. Go to **Advanced Audit Policy Configuration** > **Audit Policies**. For example:

        ![Screenshot of the Advanced Audit Policy Configuration dialog.](../media/advanced-audit-policy-check-step-2.png)

    1. Under **Audit Policies**, edit each of the following policies and select **Configure the following audit events** for both **Success** and **Failure** events.

        | Audit policy | Subcategory | Triggers event IDs |
        | --- |---|---|
        | **Account Logon** | Audit Credential Validation | 4776 |
        | **Account Management** | Audit Computer Account Management | 4741, 4743 |
        | **Account Management** | Audit Distribution Group Management | 4753, 4763 |
        | **Account Management** | Audit Security Group Management | 4728, 4729, 4730, 4732, 4733, 4756, 4757, 4758 |
        | **Account Management** | Audit User Account Management | 4726 |
        | **DS Access** | Audit Directory Service Changes | 5136  |
        | **System** | Audit Security System Extension | 7045 |
        | **DS Access** | Audit Directory Service Access | 4662 - For this event, you must also [configure domain object auditing](#configure-domain-object-auditing).  |

        For example, to configure **Audit Security Group Management**, under **Account Management**, double-click **Audit Security Group Management**, and then select **Configure the following audit events** for both **Success** and **Failure** events:

        ![Screenshot of the Audit Security Group Management dialog.](../media/advanced-audit-policy-check-step-4.png)

1. From an elevated command prompt, type `gpupdate`.

1. After you apply the policy via GPO, the new events are visible in the Event Viewer, under **Windows Logs** -> **Security**.

### Test audit policies from the command line

To test your audit policies from the command line, run the following command:

```cmd
auditpol.exe /get /category:*
```

For more information, see [auditpol reference documentation](/windows-server/administration/windows-commands/auditpol).


### Configure, get, and test audit policies using PowerShell

To configure audit policies using PowerShell, run the following command:

```powershell
Set-MDIConfiguration [-Mode] <String> [-Configuration] <String[]> [-CreateGpoDisabled] [-SkipGpoLink] [-Force]
```

Where:

- **Mode** specifies whether you want to use *Domain* or *LocalMachine* mode. In *Domain* mode, the settings are collected from the Group Policy objects. In *LocalMachine* mode, the settings are collected from the local machine.

- **Configuration** specifies which configuration to set. Use `All` to set all configurations. 

- **CreateGpoDisabled** specifies if the GPOs are created and kept as disabled.

- **SkipGpoLink** specifies that GPO links aren't created.

- **Force** specifies that the configuration is set or GPOs are created without validating the current state.

To view or test your audit policies using PowerShell, run the following commands as needed. Use the **Get-MDIConfiguration** command to show the current values. Use the **Test-MDIConfiguration** command to get a `true` or `false` response as to whether the values are configured correctly.

```powershell
Get-MDIConfiguration [-Mode] <String> [-Configuration] <String[]>
```

Where:

- **Mode** specifies whether you want to use *Domain* or *LocalMachine* mode. In *Domain* mode, the settings are collected from the Group Policy objects. In *LocalMachine* mode, the settings are collected from the local machine.

- **Configuration** specifies which configuration to get. Use `All` to get all configurations.


```powershell
Test-MDIConfiguration [-Mode] <String> [-Configuration] <String[]>
```

Where:

- **Mode** specifies whether you want to use *Domain* or *LocalMachine* mode. In *Domain* mode, the settings are collected from the Group Policy objects. In *LocalMachine* mode, the settings are collected from the local machine.

- **Configuration** specifies which configuration to test. Use `All` to test all configurations.

For more information, see the following [DefenderForIdentity PowerShell references](/powershell/defenderforidentity/overview-defenderforidentity):

- [Set-MDIConfiguration](/powershell/module/defenderforidentity/set-mdiconfiguration)
- [Get-MDIConfiguration](/powershell/module/defenderforidentity/get-mdiconfiguration)
- [Test-MDIConfiguration](/powershell/module/defenderforidentity/test-mdiconfiguration)

### Configure NTLM auditing

This section describes the extra configuration steps needed to audit Event ID 8004.

> [!NOTE]
>
> - Domain group policies to collect Windows Event 8004 should **only** be applied to domain controllers.
> - When Windows Event 8004 is parsed by Defender for Identity Sensor, Defender for Identity NTLM authentications activities are enriched with the server accessed data.

1. Following the [initial steps](#configure-advanced-audit-policy-settings), open **Group Policy Management** and go to the **Default Domain Controllers Policy** > **Local Policies** > **Security Options**.

1. Under **Security Options**, configure the specified security policies as follows:

    | Security policy setting | Value |
    |---|---|
    | **Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers** | Audit all |
    | **Network security: Restrict NTLM: Audit NTLM authentication in this domain** | Enable all |
    | **Network security: Restrict NTLM: Audit Incoming NTLM Traffic** | Enable auditing for all accounts |

For example, to configure **Outgoing NTLM traffic to remote servers**, under **Security Options**, double-click **Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers**, and then select **Audit all**:

:::image type="content" source="../media/advanced-audit-policy-check-step-3.png" alt-text="Screenshot of the Audit Outgoing NTLM traffic to remote servers configuration." border="false":::

### Configure domain object auditing

To collect events for object changes, such as event 4662, you must also configure object auditing on the user, group, computer, and other objects. This procedure describes how to enable auditing in the Active Directory domain.

> [!IMPORTANT]
> Make sure to [review and verify your audit policies](#configure-advanced-audit-policy-settings) before enabling event collection to ensure that the domain controllers are properly configured to record the necessary events. If configured properly, this auditing should have minimal effect on server performance.

1. Go to the **Active Directory Users and Computers** console.
1. Select the domain you want to audit.
1. Select the **View** menu and select **Advanced Features**.
1. Right-click the domain and select **Properties**. For example:

    ![Screenshot of the container properties option.](../media/container-properties.png)

1. Go to the **Security** tab, and select **Advanced**. For example:

    ![Screenshot of the advanced security properties dialog.](../media/security-advanced.png)

1. In **Advanced Security Settings**, select the **Auditing** tab and then select **Add**. For example:

    ![Screenshot of the Advanced Security Settings Auditing tab.](../media/auditing-tab.png)

1. Select **Select a principal**. For example:

    ![Screenshot of the Select a principal option.](../media/select-a-principal.png)

1. Under **Enter the object name to select**, enter **Everyone** and select **Check Names** > **OK**. For example:

    ![Screenshot of the Select everyone settings.](../media/select-everyone.png)

1. You then return to **Auditing Entry**. Make the following selections:

    1. For **Type** select **Success**.
    1. For **Applies to** select **Descendant User objects.**
    1. Under **Permissions**, scroll down and select the **Clear all** button. For example:

        :::image type="content" source="../media/clear-all.png" alt-text="Screenshot of selecting Clear all.":::

    1. Scroll back up and select **Full Control**. All the permissions are selected. 
    
    1. Clear the selection for the **List contents**, **Read all properties**, and **Read permissions** permissions, and select **OK**. This sets all the **Properties** settings to **Write**. For example:

        ![Screenshot of selecting permissions.](../media/select-permissions.png)

        Now, when triggered, all relevant changes to directory services appear as `4662` events.

1. Repeat the steps in this procedure, but for **Applies to**, select the following object types:
   - **Descendant Group Objects**
   - **Descendant Computer Objects**
   - **Descendant msDS-GroupManagedServiceAccount Objects**
   - **Descendant msDS-ManagedServiceAccount Objects**

> [!NOTE]
> Assigning the auditing permissions on the **All descendant objects** would work as well, but we only require the object types as detailed in the last step.
>

## Configure auditing on an Active Directory Federation Services (AD FS)

1. Go to the **Active Directory Users and Computers** console, and select the domain you want to enable the logs on.

1. Go to **Program Data** > **Microsoft** > **ADFS**. For example:

    ![Screenshot of an ADFS container.](../media/adfs-container.png)

1. Right-click **ADFS** and select **Properties**.
1. Go to the **Security** tab and select **Advanced** > **Advanced Security Settings** > **Auditing** tab > **Add** > **Select a principal**.
1. Under **Enter the object name to select**, enter **Everyone**. 
1. Select **Check Names** > **OK**.
1. You then return to **Auditing Entry**. Make the following selections:

    - For **Type** select **All**.
    - For **Applies to** select **This object and all descendant objects**.
    - Under **Permissions**, scroll down and select **Clear all**. Scroll up and select **Read all properties** and **Write all properties**.

    For example:

    ![Screenshot of the auditing settings for ADFS.](../media/audit-adfs.png)

1. Select **OK**.

## Configure auditing for Active Directory Certificate Services (AD CS)

If you're working with a dedicated server with Active Directory Certificate Services (AD CS) configured, make sure to configure auditing as follows to view dedicated alerts and Secure Score reports:

1. Create a group policy to apply to your AD CS server. Edit it and configure the following auditing settings:

    1. Go to and double select **Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Certification Services**.
    
    1. Select to configure audit events for **Success** and **Failure**. For example:

        :::image type="content" source="../media/configure-windows-event-collection/group-policy-management-editor.png" alt-text="Screenshot of the Group Policy Management Editor.":::

1. Configure auditing on the certificate authority (CA) using one of the following methods:

    - **To configure CA auditing using the command line**, run:

        ```cmd
        certutil –setreg CA\AuditFilter 127 

        net stop certsvc && net start certsvc
        ````

    - **To Configure CA auditing using the GUI**:

        1. Select **Start -> Certification Authority (MMC Desktop application)**. Right-click your CA's name and select **Properties**. For example: 

            :::image type="content" source="../media/configure-windows-event-collection/certification-authority.png" alt-text="Screenshot of the Certification Authority dialog.":::

        1. Select the **Auditing** tab, select all the events you want to audit, and then select **Apply**. For example:

            :::image type="content" source="../media/configure-windows-event-collection/auditing.png" alt-text="Screenshot of the Properties Auditing tab.":::

> [!NOTE]
> Configuring *Start and Stop Active Directory Certificate Services* event auditing may cause restart delays when dealing with a large AD CS database. Consider removing irrelevant entries from the database, or alternatively, refrain from enabling this specific type of event.

## Configure auditing on the configuration container
<a name="enable-auditing-on-an-exchange-object"></a>

1. Open ADSI Edit by selecting **Start** > **Run**. Enter `ADSIEdit.msc` and select **OK**.

1. On the **Action** menu, select **Connect to**.

1. In the **Connection Settings** dialog box under **Select a well known Naming Context**, select **Configuration** > **OK**.

1. Expand the **Configuration** container to show the **Configuration** node, beginning with *“CN=Configuration,DC=..."*

1. Right-click the **Configuration** node and select **Properties**. For example:

    ![Screenshot of the Configuration node properties.](../media/configuration-properties.png)

1. Select the **Security** tab > **Advanced**.

1. In the **Advanced Security Settings**, select the **Auditing** tab > **Add**.

1. Select **Select a principal**.

1. Under **Enter the object name to select**, enter **Everyone** and select **Check Names** > **OK**.

1. You then return to **Auditing Entry**. Make the following selections:

    - For **Type** select **All**.
    - For **Applies to** select **This object and all descendant objects**.
    - Under **Permissions**, scroll down and select **Clear all**. Scroll up and select **Write all properties**.

    For example:

    ![Screenshot of the auditing settings for the Configuration container.](../media/audit-configuration.png)

1. Select **OK**.

## Legacy configurations

> [!IMPORTANT]
> Defender for Identity no longer requires logging 1644 events. If you have this registry setting enabled, you can remove it.

```reg
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics]
"15 Field Engineering"=dword:00000005

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters]
"Expensive Search Results Threshold"=dword:00000001
"Inefficient Search Results Threshold"=dword:00000001
"Search Time Threshold (msecs)"=dword:00000001
```

## Related content

For more information, see [Windows security auditing](/windows/security/threat-protection/auditing/security-auditing-overview).

## Next step

> [!div class="step-by-step"]
> [What are Defender for Identity roles and permissions? »](../role-groups.md)

