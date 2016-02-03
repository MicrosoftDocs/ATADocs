---
title: What&#39;s new in ATA version 1.5
ms.custom: na
ms.reviewer: na
ms.suite: na
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: a0d64aff-ca9e-4300-b3f8-eb3c8b8ae045
author: Rkarlin
---
# What&#39;s new in ATA version 1.5
These release notes provide information about known issues in this version of  Advanced Threat Analytics.

## What's new in the ATA 1.5 update?
The update to ATA 1.5 provides improvements in the following areas:

-   Faster detection times

-   Enhanced automatic detection algorithm for NAT (network address translation) devices

-   Enhanced name resolution process for non-domain joined devices

-   Support for data migration during product updates

-   Better UI responsiveness for suspicious activities with thousands of entities involved

-   Improved auto-resolution of monitoring alerts

-   Additional performance counters for enhanced monitoring and troubleshooting

## Known issues
The following known issues exist in this version.

### New ATA Gateway installation fails
After updating your ATA deployment to ATA version 1.5, you get the following error when installing a new ATA Gateway:
Microsoft Advanced Threat Analytics Gateway is not installed

![ATA GW error](/Image/ATA_GW_error.png)

<b>Workaround:</b> Send an email to <ataeval@microsoft.com> to request workaround steps.
### Deployment
The folder specified for the "Database data path" and "Database journal path" has to be empty (no files or subfolders).
If it is not empty, the deployment will not progress.

### Installation from Zip file
When installing the ATA Gateway, make sure to extract the files from the zip file to a local directory and install it from there. Do not install the ATA Gateway directly from within the zip file or the installation will fail.

### Configuration
After the configuration for an ATA Gateway is set, when the ATA Gateway starts for the first time, the "Not Synced" label is displayed until the service is fully started which may take up to 10 minutes the first time the service starts.

### Network Capture Software
On the ATA Gateway, the only supported network capture software you can install is [Microsoft Network Monitor 3.4](http://www.microsoft.com/en-us/download/details.aspx?id=4865). Do not install Microsoft Message Analyzer or any other network capturing software. Installing other software will cause the ATA Gateway to stop functioning properly.

### KB on virtualization host
Do not install KB 3047154 on a virtualization host. This may cause port mirroring to stop working properly.

## See Also
[For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)

