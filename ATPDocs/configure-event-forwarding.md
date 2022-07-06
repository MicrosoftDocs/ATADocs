---
title: Configure Windows Event Forwarding in Microsoft Defender for Identity
description: Describes your options for configuring Windows Event Forwarding with Microsoft Defender for Identity
ms.date: 06/23/2022
ms.topic: how-to
---

# Configuring Windows Event Forwarding

> [!NOTE]
> The [!INCLUDE [Product long](includes/product-long.md)] sensor automatically reads events locally, without the need to configure event forwarding.

To enhance detection capabilities, [!INCLUDE [Product short](includes/product-short.md)] needs the Windows events listed in [Configure event collection](configure-windows-event-collection.md#configure-event-collection). These can either be read automatically by the [!INCLUDE [Product short](includes/product-short.md)] sensor or in case the [!INCLUDE [Product short](includes/product-short.md)] sensor is not deployed, it can be forwarded to the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor in one of two ways, by configuring the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor to listen for SIEM events or by configuring Windows Event Forwarding.

> [!NOTE]
>
> - [!INCLUDE [Product short](includes/product-short.md)] standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the [!INCLUDE [Product short](includes/product-short.md)] sensor.
> - Check that the domain controller is properly configured to capture the required events.

## WEF configuration for Defender for Identity standalone sensor's with port mirroring

After you configured port mirroring from the domain controllers to the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor, follow the following instructions to configure Windows Event forwarding using Source Initiated configuration. This is one way to configure Windows Event forwarding.

**Step 1: Add the network service account to the domain Event Log Readers Group.**

In this scenario, assume that the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor is a member of the domain.

1. Open Active Directory Users and Computers, navigate to the **BuiltIn** folder and double-click **Event Log Readers**.
1. Select **Members**.
1. If **Network Service** is not listed, select **Add**, type **Network Service** in the **Enter the object names to select** field. Then select **Check Names** and select **OK** twice.

After adding the **Network Service** to the **Event Log Readers** group, reboot the domain controllers for the change to take effect.

**Step 2: Create a policy on the domain controllers to set the Configure target Subscription Manager setting.**

> [!NOTE]
> You can create a group policy for these settings and apply the group policy to each domain controller monitored by the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor. The following steps modify the local policy of the domain controller.

1. Run the following command on each domain controller: *winrm quickconfig*
1. From a command prompt type *gpedit.msc*.
1. Expand **Computer Configuration > Administrative Templates > Windows Components > Event Forwarding**

    ![Local policy group editor image.](media/wef-1-local-group-policy-editor.png)

1. Double-click **Configure target Subscription Manager**.

    1. Select **Enabled**.
    1. Under **Options**, click **Show**.
    1. Under **SubscriptionManagers**, enter the following value and select **OK**:
        `Server=http://<fqdnMicrosoftDefenderForIdentitySensor>:5985/wsman/SubscriptionManager/WEC,Refresh=10` (For example: `Server=http://atpsensor9.contoso.com:5985/wsman/SubscriptionManager/WEC,Refresh=10`)

    ![Configure target subscription image.](media/wef-2-config-target-sub-manager.png)

1. Select **OK**.
1. From an elevated command prompt type *gpupdate /force*.

**Step 3: Perform the following steps on the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor**

1. Open an elevated command prompt and type `wecutil qc`. Leave the command window open.
1. Open **Event Viewer**.
1. Right-click **Subscriptions** and select **Create Subscription**.

    1. Enter a name and description for the subscription.
    1. For **Destination Log**, confirm that **Forwarded Events** is selected. For [!INCLUDE [Product short](includes/product-short.md)] to read the events, the destination log must be **Forwarded Events**.
    1. Select **Source computer initiated** and select **Select Computers Groups**.
        1. Select **Add Domain Computer**.
        1. Enter the name of the domain controller in the **Enter the object name to select** field. Then click **Check Names** and click **OK**.
        1. Select **OK**.
        ![Event Viewer image.](media/wef-3-event-viewer.png)
    1. Select **Select Events**.
        1. Select **By log** and then select **Security**.
        1. In the **Includes/Excludes Event ID** field type the event number and select **OK**. For example, type 4776, like in the following sample:<br/>
        ![Query filter image.](media/wef-4-query-filter.png)
    1. Return to the command window opened in the first step. Run the following commands, replacing *SubscriptionName* with the name you created for the subscription.

        ```cmd
        wecutil ss "SubscriptionName" /cm:"Custom"
        wecutil ss "SubscriptionName" /HeartbeatInterval:5000
        ```

    1. Return to the **Event Viewer** console. Right-click the created subscription and select **Runtime Status** to see if there are any issues with the status.
    1. After a few minutes, check to see that the events you set to be forwarded is showing up in the Forwarded Events on the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor.

For more information, see: [Configure the computers to forward and collect events](/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc748890(v=ws.11))

## See Also

- [Install [!INCLUDE [Product short](includes/product-short.md)]](install-step1.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
