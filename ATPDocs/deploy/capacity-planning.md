---
title: Plan capacity for deployment | Microsoft Defender for Identity
description: Plan your deployment and decide how many Microsoft Defender for Identity servers are needed to support your network.
ms.date: 08/27/2023
ms.topic: how-to
---

# Plan capacity for Microsoft Defender for Identity deployment

This article describes how to determine what resources you need for your Microsoft Defender for Identity sensors.

By default, Defender for Identity supports up to 350 sensors. To install more sensors, contact Defender for Identity support.

> [!IMPORTANT]
> While domain controller performance may not be affected if the server doesn't have required resources, the Defender for Identity sensor may not operate as expected. For more information, see [Microsoft Defender for Identity prerequisites](prerequisites.md).

The Sizing Tool measures the capacity needed for domain controllers only. There is no need to run it against AD FS / AD CS servers, as the performance impact on AD FS / AD CS servers is extremely minimal to not existent.

## Prerequisites

- Download the [Defender for Identity Sizing Tool](<https://aka.ms/mdi/sizingtool>).
- Review the [Defender for Identity architecture](../architecture.md) article.
- Review the [Defender for Identity prerequisites](prerequisites.md) article.

<!--
> [!TIP]
> If you're unable to use the Defender for Identity Sizing tool, you can manually gather traffic information instead. For more information, see [Domain controller traffic estimator](#manual-sizing).
>
-->
## Use the sizing tool

This procedure describes how to use the Defender for Identity Sizing Tool, which is the recommended and simplest way to determine capacity for your Defender for Identity deployment.

**To determine capacity with the sizing tool**:

1. Run the Defender for Identity Sizing Tool, **TriSizingTool.exe**, from the zip file you downloaded.

1. When the tool finishes running, open the Excel file results.

1. In the Excel file, locate and select the **Azure ATP Summary** sheet.

    For example:

    :::image type="content" source="../media/capacity-tool.png" alt-text="Screenshot of a sample capacity planning tool." lightbox="../media/capacity-tool.png":::

    The other sheet in the file is used for [Advanced Threat Analytics (ATA)](/advanced-threat-analytics/what-is-ata) planning and isn't needed for Defender for Identity.

1. Locate the **Busy Packets/sec** field in the Azure ATP sensor table in the results Excel file and make a note of it.

1. Match your **Busy Packets/sec** field to the **PACKETS PER SECOND** field in the [Defender for Identity sensor table](#sizing) section of this article. Use the fields to determine the memory and CPU that will be used by the sensor. <!--Not sure why we have this here as the excel Indicates if the sensor is supported or not. I would add a note here if the response is No or Maybe because the busy packets / second are very high to compare the Avg to the - ?-->

> [!NOTE]
> To ensure accurate results, only run the sizing tool *before* you've installed any Defender for Identity sensors in your environment.

<a name="sizing"></a>

## Defender for Identity sensor sizing

A Defender for Identity sensor can support the monitoring of a domain controller based on the amount of network traffic the domain controller generates, such as shown in the following table of estimates.

For more information, see [Resource limitations](../architecture.md#resource-limitations).

**This table is an estimate. The final amount that the sensor parses is dependent on the amount of traffic and the distribution of traffic.**

|Packets per second|CPU (physical cores)|RAM (GB)|
|----|----|-----|
|0-1k|0.25|2.50|
|1k-5k|0.75|6.00|
|5k-10k|1.00|6.50|
|10k-20k|2.00|9.00|
|20k-50k|3.50|9.50|
|50k-60k |5.50|11.50|

<!--
|50k-75k |5.50|11.50|
|75k-100k|7.50|13.50|
-->

In this table:

- CPU and RAM capacity refers to the **sensor's own consumption**, not the domain controller capacity.

- CPU capacity doesn't include hyper-threaded cores. We recommend that you don't work with hyper-threaded cores, which can result in health issues in the Defender for Identity sensor. 

When determining sizing, keep in mind the total number of cores and total amount of memory that will be used by the sensor service.

<!--
<a name="manual-sizing"></a>

## Domain controller traffic estimation

If for some reason you can't use the Defender for Identity Sizing Tool, manually gather the packet/sec counter information from each of your domain controllers instead.

Gather the information for 24 hours with a low collection interval, of approximately 5 seconds each. Then, for each domain controller, calculate the total daily average and the average busiest period of 15 minutes.

This section describes how to collect the packets/sec counter from a domain controller.

> [!TIP]
> There are various tools that you can use to discover the average packets per second of your domain controllers. If you don't have any tools that track this counter, you can use the Windows Performance Monitor to gather the required information.
>

**On each domain controller**:

1. Open Performance Monitor and select **Data Collector Sets**. Then right-click **User Defined > New > Data Collector Set**. For example:

    ![Screenshot of the Performance Monitor with the Data Collector Sets node selected.](../media/traffic-estimation-2.png)

1. Enter a name for the collector set and select **Create Manually (Advanced) > Next**.

1. On the **What type of data do you want to include?** dialog, select  **Create data logs** >  **Performance counter**.

1. On the  **Which performance counters would you like to log** dialog, select **Add** > **Network Adapter** > **Packets/sec**. Select the relevant workspace, and then select **Add > OK**.

    If you aren't sure which workspace to select, select **&lt;All workspace&gt;**.

    > [!NOTE]
    > To perform this operation in a command line, run `ipconfig /all` to see the name of the adapter it's and configuration.

1. Change the **Sample interval** to **five seconds**, and then define the location where you want the data to be saved.

1. On the **Create the data collector set** dialog,  select **Start this data collector set now**, and then select **Finish**.

    The data collector set you created is now shown with a green triangle, indicating that it's working as expected.

1. After 24 hours, stop the data collector set. Right-click the data collector set and select **Stop**. For example:

    ![Screenshot of the Performance Monitor dialog showing the Stop option.](../media/traffic-estimation-12.png)

1. In the File Explorer, browse to the folder where the **.blg** file was saved. Double-click the **.blg** file to open it in Performance Monitor.

1. Select the **Packets/sec** counter, and record the average and maximum values. For example:

    ![Screenshot of the Performance Monitor dialog with the Packets/sec counter selected.](../media/traffic-estimation-14.png)

-->
## Next step

> [!div class="step-by-step"]
> [What are Defender for Identity roles and permissions? »](role-groups.md)