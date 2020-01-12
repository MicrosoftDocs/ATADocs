---
# required metadata

title: Configure Windows Event Forwarding in Azure Advanced Threat Protection | Microsoft Docs
description: Describes your options for configuring Windows Event Forwarding with Azure ATP
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 11/29/2018
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 3547519f-8d9c-40a9-8f0e-c7ba21081203

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---



# Configuring Windows Event Forwarding

> [!NOTE]
> The Azure ATP sensor automatically reads events locally, without the need to configure event forwarding.


To enhance detection capabilities, Azure ATP needs the following Windows events: 4776, 4732, 4733, 4728, 4729, 4756, 4757, and 7045. These can either be read automatically by the Azure ATP sensor or in case the Azure ATP sensor is not deployed, it can be forwarded to the Azure ATP standalone sensor in one of two ways, by configuring the Azure ATP standalone sensor to listen for SIEM events or by configuring Windows Event Forwarding.

> [!NOTE]
> Check that the domain controller is properly configured to capture the required events.

### WEF configuration for Azure ATP standalone sensor's with port mirroring

After you configured port mirroring from the domain controllers to the Azure ATP standalone sensor, follow the following instructions to configure Windows Event forwarding using Source Initiated configuration. This is one way to configure Windows Event forwarding. 

**Step 1: Add the network service account to the domain Event Log Readers Group.** 

In this scenario, assume that the Azure ATP standalone sensor is a member of the domain.

1.	Open Active Directory Users and Computers, navigate to the **BuiltIn** folder and double-click **Event Log Readers**. 
2.	Select **Members**.
3.	If **Network Service** is not listed, click **Add**, type **Network Service** in the **Enter the object names to select** field. Then click **Check Names** and click **OK** twice. 

After adding the **Network Service** to the **Event Log Readers** group, reboot the domain controllers for the change to take effect.

**Step 2: Create a policy on the domain controllers to set the Configure target Subscription Manager setting.** 
> [!Note] 
> You can create a group policy for these settings and apply the group policy to each domain controller monitored by the Azure ATP standalone sensor. The following steps modify the local policy of the domain controller. 	

1. Run the following command on each domain controller: *winrm quickconfig*
2. From a command prompt type *gpedit.msc*.
3. Expand **Computer Configuration > Administrative Templates > Windows Components > Event Forwarding**

   ![Local policy group editor image](media/wef%201%20local%20group%20policy%20editor.png)

4. Double-click **Configure target Subscription Manager**.
   
   1.  Select **Enabled**.
   2.  Under **Options**, click **Show**.
   3.  Under **SubscriptionManagers**, enter the following value and click **OK**: 
   Server= http\://\<fqdnATPSensor>:5985/wsman/SubscriptionManager/WEC,Refresh=10` (For example: Server=http\://atpsensor9.contoso.com:5985/wsman/SubscriptionManager/WEC,Refresh=10)
    
   ![Configure target subscription image](media/wef%202%20config%20target%20sub%20manager.png)
    
5. Click **OK**.
6. From an elevated command prompt type *gpupdate /force*. 

**Step 3: Perform the following steps on the Azure ATP standalone sensor** 

1. Open an elevated command prompt and type *wecutil qc*
2. Open **Event Viewer**. 
3. Right-click **Subscriptions** and select **Create Subscription**. 
    
    1. Enter a name and description for the subscription. 
    2. For **Destination Log**, confirm that **Forwarded Events** is selected. For Azure ATP to read the events, the destination log must be **Forwarded Events**. 
    3. Select **Source computer initiated** and click **Select Computers Groups**.
        1. Click **Add Domain Computer**.
        2. Enter the name of the domain controller in the **Enter the object name to select** field. Then click **Check Names** and click **OK**. 
        3. Click **OK**.
        ![Event Viewer image](media/wef3%20event%20viewer.png)     
    4. Click **Select Events**.
        1. Click **By log** and select **Security**.
        2. In the **Includes/Excludes Event ID** field type the event number and click **OK**. For example, type 4776, like in the following sample:<br/>
        ![Query filter image](media/wef-4-query-filter.png)
    5. Right-click the created subscription and select **Runtime Status** to see if there are any issues with the status. 
    6. After a few minutes, check to see that the events you set to be forwarded is showing up in the Forwarded Events on the Azure ATP standalone sensor.


For more information, see: [Configure the computers to forward and collect events](https://technet.microsoft.com/library/cc748890)

## See Also

- [Install Azure ATP](install-atp-step1.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
