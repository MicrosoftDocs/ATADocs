---
# required metadata

title: Troubleshooting Azure Advanced Threat Protection with performance counters | Microsoft Docs
description: Describes how you can use performance counters to troubleshoot issues with ATP
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 79c59b97-a717-46a5-acc5-02c8f8b9caf4

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



# Troubleshooting Azure ATP using the performance counters
The Azure ATP performance counters provide insight into how well each component of Azure ATP is performing. The components in Azure ATP process data sequentially, so that when there's a problem, it might cause partial dropped traffic somewhere along the chain of components. In order to fix the problem, you have to figure out which component is backfiring and fix the problem at the beginning of the chain. Use the data found in the performance counters to understand how each component is functioning.
    Refer to [Azure ATP architecture](ata-architecture.md) to understand the flow of internal Azure ATP components.

**Azure ATP component process**:

1.  When a component reaches its maximum size, it blocks the previous component from sending more entities to it.

2.  Then, eventually the previous component will start to increase **its** own size until it blocks the component before it, from sending more entities.

3.  This happens all the way back to the NetworkListener component which will drop traffic when it can no longer forward entities.


## Retrieving performance monitor files for troubleshooting

To retrieve the performance monitor files (BLG) from the various Azure ATP components:
1.  Open perfmon.
2.  Stop the data collector set named: "Azure ATP Standalone Sensor " or “Azure ATP Center”.
3.  Go to the data collector set folder (by default, this is "C:\Program Files\Azure Advanced Threat Protection\Gateway\Logs\DataCollectorSets" or “C:\Program Files\Azure Advanced Threat Protection\Center\Logs\DataCollectorSets”).
4.  Copy the BLG file that was most recently modified.
5.  Restart the data collector set named: "Azure ATP Standalone Sensor" or "Azure ATP Center”.


## Azure ATP Standalone Sensor performance counters

In this section, every reference to Azure ATP Standalone Sensor refers also to the Azure ATP Sensor.

You can observe the real time performance status of the Azure ATP Standalone Sensor by adding the Azure ATP Standalone Sensor's performance counters.
This is done by opening "Performance Monitor" and adding all counters for the Azure ATP Standalone Sensor. The name of the performance counter object is: "Azure ATP Standalone Sensor".

Here is the list of the main Azure ATP Standalone Sensor counters to pay attention to:

> [!div class="mx-tableFixed"]
|Counter|Description|Threshold|Troubleshooting|
|-----------|---------------|-------------|-------------------|
|Azure ATP Standalone Sensor\NetworkListener PEF Parsed Messages\Sec|The amount of traffic being processed by the Azure ATP Standalone Sensor every second.|No threshold|Helps you understand the amount of traffic that is being parsed by the Azure ATP Standalone Sensor.|
|NetworkListener PEF Dropped Events\Sec|The amount of traffic being dropped by the Azure ATP Standalone Sensor every second.|This number should be zero all of the time (rare short burst of drops are acceptable).|Check if there is any component that reached its maximum size and is blocking previous components all the way to the NetworkListener. Refer to the **Azure ATP Component Process** above.<br /><br />Check that there is no issue with the CPU or memory.|
|Azure ATP Standalone Sensor\NetworkListener ETW Dropped Events\Sec|The amount of traffic being dropped by the Azure ATP Standalone Sensor every second.|This number should be zero all of the time (rare short burst of drops are acceptable).|Check if there is any component that reached its maximum size  and is blocking previous components all the way to the NetworkListener. Refer to the **Azure ATP Component Process** above.<br /><br />Check that there is no issue with the CPU or memory.|
|Azure ATP Standalone Sensor\NetworkActivityTranslator Message Data # Block Size|The amount of traffic queued for translation to Network Activities (NAs).|Should be less than the maximum-1 (default maximum: 100,000)|Check if there is any component that reached its maximum size  and is blocking previous components all the way to the NetworkListener. Refer to the **Azure ATP Component Process** above.<br /><br />Check that there is no issue with the CPU or memory.|
|Azure ATP Standalone Sensor\EntityResolver Activity Block Size|The amount of Network Activities (NAs) queued for resolution.|Should be less than the maximum-1 (default maximum: 10,000)|Check if there is any component that reached its maximum size  and is blocking previous components all the way to the NetworkListener. Refer to the **Azure ATP Component Process** above.<br /><br />Check that there is no issue with the CPU or memory.|
|Azure ATP Standalone Sensor\EntitySender Entity Batch Block Size|The amount of Network Activities (NAs) queued to be sent to the Azure ATP cloud service.|Should be less than the maximum-1 (default maximum: 1,000,000)|Check if there is any component that reached its maximum size  and is blocking previous components all the way to the NetworkListener. Refer to the **Azure ATP Component Process** above.<br /><br />Check that there is no issue with the CPU or memory.|
|Azure ATP Standalone Sensor\EntitySender Batch Send Time|The amount of time it took to send the last batch.|Should be less than 1000 milliseconds most of the time|Check if there are any networking issues between the Azure ATP Standalone Sensor and the Azure ATP cloud service.|

> [!NOTE]
> -   Timed counters are in milliseconds.
> -   It is sometimes more convenient to monitor the full list of the counters by using the "Report" graph type (example: real time monitoring of all the counters)

## Azure ATP Sensor performance counters
The performance counters can be used for quota management in the Sensor, to make sure that Azure ATP doesn't drain too many resources from the domain controllers on which it is installed.
To measure the resource limitations that Azure ATP enforces on the Sensor, add these counters.

This is done by opening "Performance Monitor" and adding all counters for the Azure ATP Sensor. The name of the performance counter objects are: "Azure ATP Standalone Sensor" and "Azure ATP Standalone Sensor Updater".

> [!div class="mx-tableFixed"]
|Counter|Description|Threshold|Troubleshooting|
|-----------|---------------|-------------|-------------------|
|Azure ATP Standalone Sensor Updater\GatewayUpdaterResourceManager CPU Time Max %|The maximum amount of CPU time (in percentage) that the Sensor process can consume. |No threshold. | This is the limitation that protects the domain controller resources from being used up by the Azure ATP Sensor. If you see that the process reaches the maximum limit often over a period of time (the process reaches the limit and then starts to drop traffic) it means that you need to add more resources to the server running the domain controller..|
|Azure ATP Standalone Sensor Updater\GatewayUpdaterResourceManager Commit Memory Max Size|The maximum amount of committed memory (in bytes) that the Sensor process can consume.|No threshold. | This is the limitation that protects the domain controller resources from being used up by the Azure ATP Sensor. If you see that the process reaches the maximum limit often over a period of time (the process reaches the limit and then starts to drop traffic) it means that you need to add more resources to the server running the domain controller.| 
|Azure ATP Standalone Sensor Updater\GatewayUpdaterResourceManager Working Set Limit Size|The Maximum amount of physical memory (in bytes) that the Sensor process can consume.|No threshold. | This is the limitation that protects the domain controller resources from being used up by the Azure ATP Sensor. If you see that the process reaches the maximum limit often over a period of time (the process reaches the limit and then starts to drop traffic) it means that you need to add more resources to the server running the domain controller.|



In order to see your actual consumption, refer to the following counters:


> [!div class="mx-tableFixed"]
|Counter|Description|Threshold|Troubleshooting|
|-----------|---------------|-------------|-------------------|
|Process(Microsoft.Tri.Gateway)\%Processor Time|The amount of CPU time (in percentage) that the Sensor process is actually consuming. |No threshold. | Compare the results of this counter to the limit found in GatewayUpdaterResourceManager CPU Time Max %. If you see that the process reaches the maximum limit often over a period of time (the process reaches the limit and then starts to drop traffic) it means that you need to dedicate more resources to the Sensor.|
|Process(Microsoft.Tri.Gateway)\Private Bytes|The amount of committed memory (in bytes) that the Sensor process is actually consuming.|No threshold. | Compare the results of this counter to the limit found in GatewayUpdaterResourceManager Commit Memory Max Size. If you see that the process reaches the maximum limit often over a period of time (the process reaches the limit and then starts to drop traffic) it means that you need to dedicate more resources to the Sensor.| 
|Process(Microsoft.Tri.Gateway)\Working Set|The amount of physical memory (in bytes) that the Sensor process is actually consuming.|No threshold. |Compare the results of this counter to the limit found in GatewayUpdaterResourceManager Working Set Limit Size. If you see that the process reaches the maximum limit often over a period of time (the process reaches the limit and then starts to drop traffic) it means that you need to dedicate more resources to the Sensor.|

## Azure ATP cloud service performance counters
You can observe the real-time performance status of the Azure ATP cloud service by adding the Azure ATP cloud service's performance counters.

This is done by opening "Performance Monitor" and adding all counters for the Azure ATP cloud service. The name of the performance counter object is: "Azure ATP cloud service".

Here is the list of the main Azure ATP cloud service counters to pay attention to:

> [!div class="mx-tableFixed"]
|Counter|Description|Threshold|Troubleshooting|
|-----------|---------------|-------------|-------------------|
|Azure ATP cloud service\EntityReceiver Entity Batch Block Size|The number of entity batches queued by the Azure ATP cloud service.|Should be less than the maximum-1 (default maximum: 10,000)|Check if there is any component that reached its maximum size  and is blocking previous components all the way to the NetworkListener.  Refer to the preceding **Azure ATP Component Process**.<br /><br />Check that there is no issue with the CPU or memory.|
|Azure ATP cloud service\NetworkActivityProcessor Network Activity Block Size|The number of Network Activities (NAs) queued for processing.|Should be less than the maximum-1 (default maximum: 50,000)|Check if there is any component that reached its maximum size  and is blocking previous components all the way to the NetworkListener. Refer to the preceding **Azure ATP Component Process**.<br /><br />Check that there is no issue with the CPU or memory.|
|Azure ATP cloud service\EntityProfiler Network Activity Block Size|The number of Network Activities (NAs) queued for profiling.|Should be less than the maximum-1 (default maximum: 10,000)|Check if there is any component that reached its maximum size  and is blocking previous components all the way to the NetworkListener. Refer to the preceding **Azure ATP Component Process**.<br /><br />Check that there is no issue with the CPU or memory.|
|Azure ATP cloud service\Database &#42; Block Size|The number of Network Activities, of a specific type, queued to be written to the database.|Should be less than the maximum-1 (default maximum: 50,000)|Check if there is any component that reached its maximum size  and is blocking previous components all the way to the NetworkListener. Refer to the preceding **Azure ATP Component Process**.<br /><br />Check that there is no issue with the CPU or memory.|


> [!NOTE]
> -   Timed counters are in milliseconds
> -   It is sometimes more convenient to monitor the full list of the counters using the graph type for Report (example: real-time monitoring of all the counters).

## Operating system counters
The following table lists the main operating system counters to pay attention to:

> [!div class="mx-tableFixed"]
|Counter|Description|Threshold|Troubleshooting|
|-----------|---------------|-------------|-------------------|
|Processor(_Total)\% Processor Time|The percentage of elapsed time that the processor spends to execute a non-Idle thread.|Less than 80% on average|Check if there is a specific process that is taking a lot more processor time than it should.<br /><br />Add more processors.<br /><br />Reduce the amount of traffic per server.<br /><br />The "Processor(_Total)\% Processor Time" counter may be less accurate on virtual servers, in which case the more accurate way to measure the lack of processor power is through the "System\Processor Queue Length" counter.|
|System\Context Switches\sec|The combined rate at which all processors are switched from one thread to another.|Less than 5000&#42;cores (physical cores)|Check if there is a specific process that is taking a lot more processor time than it should.<br /><br />Add more processors.<br /><br />Reduce the amount of traffic per server.<br /><br />The "Processor(_Total)\% Processor Time" counter may be less accurate on virtual servers, in which case the more accurate way to measure the lack of processor power is through the "System\Processor Queue Length" counter.|
|System\Processor Queue Length|The number of threads that are ready to execute and are waiting to be scheduled.|Less than 5&#42;cores (physical cores)|Check if there is a specific process that is taking a lot more processor time than it should.<br /><br />Add more processors.<br /><br />Reduce the amount of traffic per server.<br /><br />The "Processor(_Total)\% Processor Time" counter may be less accurate on virtual servers, in which case the more accurate way to measure the lack of processor power is through the "System\Processor Queue Length" counter.|
|Memory\Available MBytes|The amount of physical memory (RAM) available for allocation.|Should be more than 512|Check if there is a specific process that is taking a lot more physical memory than it should.<br /><br />Increase the amount of physical memory.<br /><br />Reduce the amount of traffic per server.|
|LogicalDisk(&#42;)\Avg. Disk sec\Read|The average latency for reading data from the disk (you should choose the database drive as the instance).|Should be less than 10 milliseconds|Check if there is a specific process that is utilizing the database drive more than it should.<br /><br />Consult with your storage team/vendor if this drive can deliver the current workload while having less than 10 ms of latency. The current workload can be determined by using the disk utilization counters.|
|LogicalDisk(&#42;)\Avg. Disk sec\Write|The average latency for writing data to the disk (you should choose the database drive as the instance).|Should be less than 10 milliseconds|Check if there is a specific process that is utilizing the database drive more than it should.<br /><br />Consult with your storage team\vendor if this drive can deliver the current workload while having less than 10 ms of latency. The current workload can be determined by using the disk utilization counters.|
|\LogicalDisk(&#42;)\Disk Reads\sec|The rate of performing read operations to the disk.|No threshold|Disk utilization counters can add insight when troubleshooting storage latency.|
|\LogicalDisk(&#42;)\Disk Read Bytes\sec|The number of bytes per second that are being read from the disk.|No threshold|Disk utilization counters can add insight when troubleshooting storage latency.|
|\LogicalDisk&#42;\Disk Writes\sec|The rate of performing write operations to the disk.|No threshold|Disk utilization counters (can add insights when troubleshooting the storage latency)|
|\LogicalDisk(&#42;)\Disk Write Bytes\sec|The number of bytes per second that are being written to the disk.|No threshold|Disk utilization counters can add insight when troubleshooting storage latency.|

## See Also
- [Azure ATP prerequisites](ata-prerequisites.md)
- [Azure ATP capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the Azure ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
