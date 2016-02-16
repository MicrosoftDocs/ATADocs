---
title: Troubleshooting ATA Monitoring Alerts
ms.custom: na
ms.reviewer: na
ms.suite: na
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: 51bedf1f-b267-4e68-b12c-2d43db17e82d
author: Rkarlin
robots: noindex,nofollow
---
# Troubleshooting ATA Monitoring Alerts
This article lists the ATA monitoring alerts with a resolution process for each.

## Dropped Port Mirrored Network Traffic
This alert indicates that the ATA Gateway is dropping the traffic that it is receiving on its capture network adapter(s)
This could be the results of either resource issues (such as CPU or memory) or an ATA component that is not keeping up.
Refer to the ATA Performance counters guide to understand how to locate the bottleneck that is causing the ATA Gateway to drop traffic.

## Failed to Connect to Domain Controller

## ATA Gateway Stopped Communicating

## ATA Center at Maximum Capacity

## Known Errors

|Error|Description|Resolution|
|---------|---------------|--------------|
|System.DirectoryServices.Protocols.LdapException: A local error occurred||DNS resolution<br /><br />Time sync with domain<br /><br />CRL|
|System.ServiceModel.FaultException: At least one security token in the message could not be validated.||Certificate issues|
|System.IdentityModel.Tokens.SecurityTokenValidationException: Failed to validate certificate chain||Trusted CA CRL|
|System.Net.Sockets.SocketException: No connection could be made because the target machine actively refused it 127.0.0.2:443||MongoDB|
|System.ServiceModel.EndpointNotFoundException: Could not connect to net.tcp://center.ip.addr:443/IEntityReceiver||Connectivity to SIEM|
|Microsoft.Common.ExtendedException: Failed to parse time generated||SIEM configuration|
|System.DirectoryServices.Protocols.LdapException: The LDAP server is unavailable.||AD Permissions on objects|
|System.ServiceModel.FaultException: An error occurred when verifying security for the message.||Time sync between ATA Gateway and ATA Center|
|Microsoft.Tri.Infrastructure.ContractException: Contract exception||Finish the configuration|
