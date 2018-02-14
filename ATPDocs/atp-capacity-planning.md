---
# required metadata

title: Planning your Azure Advanced Threat Protection deployment | Microsoft Docs
description: Helps you plan your deployment and decide how many Azure ATP servers will be needed to support your network
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/14/2018
ms.topic: get-started-article
ms.service: azure-advanced-threat-protection
ms.prod:
ms.assetid: da0ee438-35f8-4097-b3a1-1354ad59eb32

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*



# Azure ATP capacity planning
This article helps you determine how many Azure ATP Sensors and standalone Sensors you need.

> [!NOTE] 
> The sizing tool has two sheets - one for ATA and one for Azure ATP. Make sure you are on the correct sheet.

## Using the sizing tool
The recommended and simplest way to determine capacity for your Azure ATP deployment is to use the [Azure ATP Sizing Tool](http://aka.ms/trisizingtool). Run the Azure ATP Sizing Tool and from the Excel file results, use the following fields to determine the Azure ATP capacity you need:

- Azure ATP  Sensor: Match the **Busy Packets/sec** field in the Azure ATP  Sensor table in the results file to the **PACKETS PER SECOND** field in the [Azure ATP Standalone Sensor table](#atp-sensor-sizing) or the [Azure ATP Sensor table](#atp-standalone-sensor-sizing), depending on the [sensor type you choose](#choosing-the-right-sensor-type-for-your-deployment).


![Sample capacity planning tool](media/capacity tool.png)


If for some reason you cannot use the Azure ATP Sizing Tool, manually gather the packet/sec counter information from all your Domain Controllers for 24 hours with a low collection interval (approximately 5 seconds). Then, for each Domain Controller, you  must calculate the daily average and the busiest period (15 minutes) average.
The following sections present the instruction for how to collect the packets/sec counter from one Domain Controller.

## Choosing the right sensor type for your deployment
In an Azure ATP deployment any combination of the Azure ATP Standalone Sensor types is supported:

- Only Azure ATP standalone sensors
- Only Azure ATP Sensors
- A combination of both

When deciding the sensor deployment type, consider the following benefits:

|Sensor type|Benefits|Cost|Deployment topology|Domain controller use|
|----|----|----|----|-----|
|Azure ATP Standalone Sensor|The Out of band deployment makes it harder for attackers to discover Azure ATP is present|Higher|Installed alongside the domain controller (out of band)|Supports up to 50,000 packets per second|
|Azure ATP Sensor|Doesn't require a dedicated server and port-mirroring configuration|Lower|Installed on the domain controller|Supports up to 10,000 packets per second|

The following are examples of scenarios in which domain controllers should be covered by the Azure ATP Sensor:


- Branch sites

- Virtual domain controllers deployed in the cloud (IaaS)


The following are examples of scenarios in which domain controllers should be covered by the Azure ATP Standalone Sensor:


- Headquarter data centers (having domain controllers with more than 10,000 packets per seconds)


## Azure ATP Sensor Sizing

An Azure ATP Sensor can support the monitoring of one domain controller based on the amount of network traffic the domain controller generates. 


|Packets per second*|CPU (cores)|Memory (GB)|
|----|----|-----|
|0-1k|0.25|2.50|
|1k-5k|0.75|6.00|
|5k-10k|1.00|6.50|
|10k-20k|2.00|9.00|
|20k-50k|3.50|9.50|
|50k-75k (*)|3.50|9.50|
|75k-100k (*)|3.50 |9.50|

&#42;Total number of packets-per-second on the domain controller being monitored by the specific Azure ATP Sensor.

&#42;&#42;Total number of non-hyper threaded cores that this domain controller has installed.<br>While hyper threading is acceptable for the Azure ATP Sensor, when planning for capacity, you should count actual cores and not hyper threaded cores.

&#42;&#42;&#42;Total amount of memory that this domain controller has installed.

> [!NOTE]	
> -   If the domain controller does not have the resources required by the Azure ATP Sensor, domain controller performance is not effected, but the Azure ATP Sensor might not operate as expected.
> -   When running as a virtual machine dynamic memory or any other memory ballooning feature is not supported.
> -   For optimal performance, set the **Power Option** of the Azure ATP Sensor to **High Performance**.
> -   A minimum of 2 cores and 6 GB of space is required and 10 GB is recommended, including space needed for the Azure ATP binaries, [Azure ATP logs](troubleshooting-atp-using-logs.md), and [performance logs](troubleshooting-atp-using-perf-counters.md).


## Azure ATP standalone sensor sizing

Consider the following issues when deciding how many Azure ATP standalone sensors to deploy.

-	**Active Directory forests and domains**<br>
	Azure ATP can monitor traffic from multiple domains from a single Active Directory forest. Monitoring multiple Active Directory forests requires separate Azure ATP deployments. Do not configure a single Azure ATP deployment to monitor network traffic of domain controllers from different forests.

-	**Port Mirroring**<br>
Port mirroring considerations might require you to deploy multiple Azure ATP standalone sensors per data center or branch site.

-	**Capacity**<br>
	An Azure ATP Standalone Sensor can support monitoring multiple domain controllers, depending on the amount of network traffic of the domain controllers being monitored. 
<br>

|Packets per second*|CPU (cores)|Memory (GB)|
|----|----|-----|
|0-1k|0.25|2.50|
|1k-5k|0.75|6.00|
|5k-10k|1.00|6.50|
|10k-20k|2.00|9.00|
|20k-50k|3.50|9.50|
|50k-75k (*)|3.50|9.50|
|75k-100k (*)|3.50 |9.50|

&#42;Total average number of packets-per-second from all domain controllers being monitored by the specific Azure ATP Standalone Sensor during their busiest hour of the day.

&#42;The total amount of domain controller port-mirrored traffic cannot exceed the capacity of the capture NIC on the Azure ATP Standalone Sensor.

&#42;&#42;Hyper-threading must be disabled.

> [!NOTE] 
> -   Dynamic memory is not supported.
> -   For optimal performance, set the **Power Option** of the Azure ATP Standalone Sensor to **High Performance**.
> -   A minimum of 2 cores and 6 GB of space is required and 10 GB is recommended, including space needed for the Azure ATP binaries, [Azure ATP logs](troubleshooting-atp-using-logs.md), and [performance logs](troubleshooting-atp-using-perf-counters.md).


## Domain controller traffic estimation
There are various tools that you can use to discover the average packets per second of your domain controllers. If you do not have any tools that track this counter, you can use Performance Monitor to gather the required information.

To determine packets per second, perform the following steps on each domain controller:

1.  Open Performance Monitor.

    ![Performance monitor image](media/ATP-traffic-estimation-1.png)

2.  Expand **Data Collector Sets**.

    ![Data collector sets image](media/ATP-traffic-estimation-2.png)

3.  Right click **User Defined** and select **New** &gt; **Data Collector Set**.

    ![New data collector set image](media/ATP-traffic-estimation-3.png)

4.  Enter a name for the collector set and select **Create Manually (Advanced)**.

5.  Under **What type of data do you want to include?** select  **Create data logs, and Performance counter**.

    ![Type of data for new data collector set image](media/ATP-traffic-estimation-5.png)

6.  Under **Which performance counters would you like to log**, click **Add**.

7.  Expand **Network Adapter** and select **Packets/sec** and select the proper instance. If you are not sure, you can select **&lt;All instances&gt;** and click **Add** and **OK**.

    > [!NOTE]
    > To perform this operation in a command line, run `ipconfig /all` to see the name of the adapter and configuration.

    ![Add performance counters image](media/ATP-traffic-estimation-7.png)

8.  Change the **Sample interval** to **1 second**.

9. Set the location where you want the data to be saved.

10. Under **Create the data collector set**,  select **Start this data collector set now**, and click **Finish**.

    You should now see the data collector set you created with a green triangle indicating that it is working.

11. After 24 hours, stop the data collector set, by right-clicking the data collector set and selecting **Stop**.

    ![Stop data collector set image](media/ATP-traffic-estimation-12.png)

12. In File Explorer, browse to the folder where the .blg file was saved and double-click it to open it in Performance Monitor.

13. Select the Packets/sec counter, and record the average and maximum values.

    ![Packets per second counter image](media/ATP-traffic-estimation-14.png)



## See Also
- [Azure ATP sizing tool](http://aka.ms/trisizingtool)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP architecture](atp-architecture.md)
- [Check out the Azure ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
