---
# required metadata

title: Update your Azure ATP sensors
description: Describes how to update and delay update of sensors in Azure ATP.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 12/24/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 603d9e09-a07d-4357-862f-d5682c8bc3dd

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Update Azure ATP sensors

Keeping your Azure Advanced Threat Protection sensors up-to-date, provides the best possible protection for your organization.

The Azure ATP service is typically updated a few times a month with new detections, features, and  performance improvements. Typically these updates include a corresponding minor update to the sensors. Azure ATP sensors and corresponding updates never have write permissions to your domain controllers. Sensor update packages only control the Azure ATP sensor and sensor detection capabilities. 

### Azure ATP sensor update types    

Azure ATP sensors support two kinds of updates:
- Minor version updates: 
    - Frequent 
    - Requires no MSI install, and no registry changes
    - Restarted: Azure ATP sensor services 
    - Not restarted: Domain controller services and server OS

- Major version updates:
    - Rare
    - Contains significant changes 
    - Restarted: Azure ATP sensor services
    - Possible restart required: Domain controller services and server OS

> [!NOTE]
>- Control automatic sensor restarts (for **major** updates) in the Azure ATP portal configuration page. 
> - Azure ATP sensor always reserves at least 15% of the available memory and CPU available on the domain controller where it is installed. If the Azure ATP service consumes too much memory, the service is automatically stopped and restarted by the Azure ATP sensor updater service.

## Delayed sensor update

Given the rapid speed of ongoing Azure ATP development and release updates, you may decide to define a subset group of your sensors as a delayed update ring, allowing for a gradual sensor update process. Azure ATP enables you to choose how your sensors are updated and set each sensor as a **Delayed update** candidate.  

Sensors not selected for delayed update are updated automatically, each time the Azure ATP service is updated. Sensors set to **Delayed update** are updated on a delay of 72 hours, following the official release of each service update. 

The **delayed update** option enables you to select specific sensors as an automatic update ring, on which all updates are rolled out automatically, and set the rest of your sensors to update on delay, giving you time to confirm that the automatically updated sensors were successful.

> [!NOTE]
> If an error occurs and a sensor does not update, open a support ticket. To further harden your proxy to only communicate with your instance, see [Proxy configuration](configure-proxy.md).
Authentication between your sensors and the Azure cloud service uses strong, certificate-based mutual authentication. 

Each update is tested and validated on all supported operating systems to cause minimal impact to your network and operations.


To set a sensor to delayed update:

1. From the Azure ATP portal, click on the settings icon and select **Configuration**.
2. Click on the **Updates** tab.
3. In the table row next to each sensor you want to delay, set the **Delayed update** slider to **On**.
4. Click **Save**.
 
## Sensor update process

Every few minutes, Azure ATP sensors check whether they have the latest version. After the Azure ATP cloud service is updated to a newer version, the Azure ATP sensor service starts the update process:

1. Azure ATP cloud service updates to the latest version.
2. Azure ATP sensor updater service learns that there is an updated version.
3. Sensors that are not set to **Delayed update** start the update process on a sensor by sensor basis:
   1. Azure ATP sensor updater service pulls the updated version from the cloud service (in cab file format).
   2. Azure ATP sensor updater validates the file signature.
   3. Azure ATP sensor updater service extracts the cab file to a new folder in the sensor's installation folder. By default it is extracted to *C:\Program Files\Azure Advanced Threat Protection Sensor\<version number>*
   4. Azure ATP sensor service points to the new files extracted from the cab file.    
   5. Azure ATP sensor updater service restarts the Azure ATP sensor service.
       > [!NOTE]
      >Minor sensor updates install no MSI, changes no registry values or any system files. Even a pending restart does not impact a sensor update. 
   6. Sensors run based on the newly updated version.
   7. Sensor receives clearance from the Azure cloud service. You can verify sensor status in the **Updates** page.
   8. The next sensor starts the update process. 

4. 72 hours after the Azure ATP cloud service is updated, sensors selected for **Delayed update** start their update process according to the same update process as automatically updated sensors.

![Sensor update](./media/sensor-update.png)


For any sensor that fails to complete the update process, a relevant health alert is triggered, and is sent as a notification.

![Sensor update failure](./media/sensor-outdated.png)


## See Also

- [Configure event forwarding](configure-event-forwarding.md)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
