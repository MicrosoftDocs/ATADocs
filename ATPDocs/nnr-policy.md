---
title: Network Name Resolution | Microsoft Defender for Identity
description: This article provides an overview of Microsoft Defender for Identity's Advanced Network Name Resolution functionality and uses.
ms.date: 09/03/2023
ms.topic: conceptual
##CustomerIntent: As a Defender for Identity user, I want to understand how Defender for Identity uses NNR data so that I can best configure my system for working with Defender for Identity.
---

# Network Name Resolution in Microsoft Defender for Identity

Microsoft Defender for Identity captures activities based on network traffic, Windows events, and event tracing for Windows, all of which normally contain IP data. Defender for Identity uses Network Name Resolution (NNR) to identify related computers involved in each activity by correlating raw activities containing IP addresses with relevant computers.

Based on the raw activity data, Defender for Identity profiles entities, including computers, and generates security alerts for suspicious activities. NNR data is especially crucial for detecting the following threats:

- Suspected identity theft (pass-the-ticket)
- Suspected DCSync attack (replication of directory services)
- Network-mapping reconnaissance (DNS)

## IP address lookup methods

Defender for Identity sensors support the following methods when looking up IP addresses to resolve them to computer names. No authentication is performed on any of the ports.

- **Primary methods**:

    - NTLM over RPC (TCP Port 135)
    - NetBIOS (UDP port 137)
    - RDP (TCP port 3389) - only the first packet of **Client hello**

- **Secondary method**: Queries the DNS server using reverse DNS lookup of the IP address (UDP 53)

> [!TIP]
> For the best results, we recommend using at least one of the primary methods.
>
> Reverse DNS lookup of the IP address is only performed when there's no response from any of the primary methods, or if there's a conflict in the response received from two or more primary methods.
>

To disable a specific NNR method in Defender for Identity to fit the needs of your environment, open a support case.

## IP address correlation process

Defender for Identity uses the following process to associate an IP address with a specific computer object:

1. Defender for Identity evaluates and determines the device's operating system based on network traffic.

1. After retrieving the computer name, the Defender for Identity sensor checks Active Directory and uses TCP fingerprints to see if there's a correlated computer object with the same computer name. Using TCP fingerprints helps identify unregistered and non-Windows devices, aiding in your investigation process.

3. When the Defender for Identity sensor finds the correlation, the sensor associates the IP to the computer object.

In cases where no computer name is retrieved, an **unresolved computer profile by IP** is created with the IP and the relevant detected activity.

## Identifying a true positive

To improve your ability to determine if an alert is a **True Positive (TP)** or **False Positive (FP)**, Defender for Identity includes the degree of certainty for the computer name resolving into the evidence of each security alert. 

The evidence includes the time, IP address, and computer name the IP was resolved to. For example:

[![Screenshot of evidence certainty in an alert.](media/nnr-high-certainty.png)](media/nnr-high-certainty.png#lightbox)

After confirming the device, use the evidence to determine if the alert is a **False Positive** or **FP**:

- When computer names are resolved with  **high certainty** it increases the confidence in the resulting security alert as a **True Positive** or **TP**.

- When the resolution certainty is **low**, use this information to investigate and verify which device was the true source of the IP at this time.

For example, the following evidence might suggest a **False Positive**:

- A suspected identity theft (pass-the-ticket) alert, where the alert was triggered for the same computer.
- A suspected DCSync attack (replication of directory services), where the alert was triggered from a domain controller.
- A network-mapping reconnaissance (DNS), where the alert was triggered from a DNS Server.

## Verify your NNR functionality

We recommend checking the following connections to ensure that Defender for Identity can use NNR as expected. While only one method is required for Defender for Identity to use NNR, we recommend checking connections for all methods listed.


- **NTLM over RPC**:

  - Check that TCP Port 135 is open for inbound communication from Defender for Identity Sensors, on all computers in the environment.
  - Check all network configuration (firewalls), as this can prevent communication to the relevant ports.

- **NetBIOS**:
  - Check that UDP Port 137 is open for inbound communication from Defender for Identity Sensors, on all computers in the environment.
  - Check all network configuration (firewalls), as this can prevent communication to the relevant ports.

- **RDP**:
  - Check that TCP Port 3389 is open for inbound communication from Defender for Identity Sensors, on all computers in the environment.
  - Check all network configuration (firewalls), as this can prevent communication to the relevant ports.

- **Reverse DNS**:
  - Check that the Sensor can reach the DNS server and that Reverse Lookup Zones are enabled.

Customized RDP ports aren't supported.

## Health issues

To ensure that Defender for Identity is functioning as expected and your environment is configured correctly, Defender for Identity checks the resolution status for each sensor and issues a health alert per method. 

Health alerts provide you with a list of Defender for Identity sensors with a low success rate of active name resolution using each supported method. Each health alert provides specific details of the method, sensors, the problematic policy as well as configuration recommendations. 

For more information, see [Microsoft Defender for Identity sensor health issues](health-alerts.md).

## Related content

For more information, see:

- [Security alerts in Microsoft Defender for Identity](alerts-overview.md)
- [Configure event collection](configure-event-collection.md)
- [Microsoft Defender for Identity sensor health issues](health-alerts.md)
