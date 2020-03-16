---
# required metadata

title: Troubleshooting Azure ATP known issues
description: Describes how you can troubleshoot issues in Azure ATP.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 02/18/2020
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 23386e36-2756-4291-923f-fa8607b5518a

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Troubleshooting Azure ATP Known Issues

## Sensor failure communication error

If you receive the following sensor failure error:

System.Net.Http.HttpRequestException:
An error occurred while sending the request. ---> System.Net.WebException:
Unable to connect to the remote server --->
System.Net.Sockets.SocketException: A connection attempt failed because the
connected party did not properly respond after a period of time, or established
connection failed because connected host has failed to respond...

**Resolution:**

Make sure that communication is not blocked for localhost, TCP port 444. To learn more about Azure ATP prerequisites, see [ports](atp-prerequisites.md#ports).

## Deployment log location

The Azure ATP deployment logs are located in the temp directory of the user who installed the product. In the default installation location, it can be found at: C:\Users\Administrator\AppData\Local\Temp (or one directory above %temp%). For more information, see [Troubleshooting ATP using logs](troubleshooting-atp-using-logs.md)

## Proxy authentication problem presents as a licensing error

If during sensor installation you receive the following error:  **The sensor failed to register due to licensing issues.**

**Deployment log entries:**

[1C60:1AA8][2018-03-24T23:59:13]i000: 2018-03-25 02:59:13.1237 Info  InteractiveDeploymentManager ValidateCreateSensorAsync returned [validateCreateSensorResult=LicenseInvalid]]  
[1C60:1AA8][2018-03-24T23:59:56]i000: 2018-03-25 02:59:56.4856 Info  InteractiveDeploymentManager ValidateCreateSensorAsync returned [validateCreateSensorResult=LicenseInvalid]]  
[1C60:1AA8][2018-03-25T00:27:56]i000: 2018-03-25 03:27:56.7399 Debug SensorBootstrapperApplication Engine.Quit [deploymentResultStatus=1602 isRestartRequired=False]]  
[1C60:15B8][2018-03-25T00:27:56]i500: Shutting down, exit code: 0x642

**Cause:**

In some cases, when communicating via a proxy, during authentication it might respond to the Azure ATP sensor with error 401 or 403 instead of error 407. The Azure ATP sensor will interpret error 401 or 403 as a licensing issue and not as a proxy authentication issue.

**Resolution:**

Ensure that the sensor can browse to *.atp.azure.com through the configured proxy without authentication. For more information see, [Configure proxy to enable communication](configure-proxy.md).

## Silent installation error when attempting to use Powershell

If during silent sensor installation you attempt to use Powershell and receive the following error:

    "Azure ATP sensor Setup.exe" "/quiet" NetFrameworkCommandLineArguments="/q" Acce ... Unexpected token '"/quiet"' in expression or statement."

**Cause:**
Failure to include the ./ prefix required to install when using Powershell causes this error.

**Resolution:**
Use the complete command to successfully install.

```powershell
./"Azure ATP sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" AccessKey="<Access Key>"
```

## Azure ATP sensor NIC teaming issue <a name="nic-teaming"></a>

If you attempt to install the ATP sensor on a machine configured with a NIC Teaming adapter, you receive an installation error. If you want to install the ATP sensor on a machine configured with NIC teaming, follow these instructions:

1. Download the Npcap version 0.9984 installer from  [https://nmap.org/npcap/](https://nmap.org/npcap/dist/npcap-0.9984.exe).
    - Alternatively, request the OEM version of the Npcap driver (that supports silent installation) from the support team.
    - Copies of Npcap do not count towards the five copy, five computer or fiver user licensing limitation if they are installed and used solely in conjunction with Azure ATP. For more information, see [NPCAP licensing](https://github.com/nmap/npcap/blob/master/LICENSE).

If you have not yet installed the sensor:

1. Uninstall WinPcap, if it was installed.
1. Install Npcap with the following options: loopback_support=no & winpcap_mode=yes.
    - If using the GUI installer, deselect the **loopback support** and select **WinPcap** mode.
1. Install the sensor package.

If you already installed the sensor:

1. Uninstall the sensor.
1. Uninstall WinPcap.
1. Install Npcap with the following options: loopback_support=no & winpcap_mode=yes
    - If using the GUI installer, deselect the **loopback support** and select **WinPcap** mode.
1. Reinstall the sensor package.

## Multi Processor Group mode

For Windows Operating systems 2008R2 and 2012, Azure ATP Sensor is not supported in a Multi Processor Group mode.

Suggested possible workarounds:

- If hyper threading is on, turn it off. This may reduce the number of logical cores enough to avoid needing to run in **Multi Processor Group** mode.

- If your machine has less than 64 logical cores and is running on a HP host, you may be able to change the **NUMA Group Size Optimization** BIOS setting from the default of **Clustered** to **Flat**.

## Windows Defender ATP integration issue

Azure Advanced Threat Protection enables you to integrate Azure ATP with Windows Defender ATP. See [Integrate Azure ATP with Windows Defender ATP](integrate-wd-atp.md) for more information.

## VMware virtual machine sensor issue

If you have an Azure ATP sensor on VMware virtual machines, you might receive the monitoring alert **Some network traffic is not being analyzed**. This can happen  because of a configuration mismatch in VMware.

To resolve the issue:

Set the following to **Disabled** in the virtual machine's NIC configuration: **IPv4 TSO Offload**.

 ![VMware sensor issue](./media/vm-sensor-issue.png)

Use the following command to check if Large Send Offload (LSO) is enabled or disabled:

`Get-NetAdapterAdvancedProperty | Where-Object DisplayName -Match "^Large*"`

![Check LSO status](./media/missing-network-traffic-health-alert.png)

If LSO is enabled, use the following command to disable it:

`Disable-NetAdapterLso -Name {name of adapter}`

![Disable LSO status](./media/disable-lso-vmware.png)

## Sensor failed to retrieve group Managed Service Account (gMSA) credentials

If you receive the following monitoring alert: **Directory services user credentials are incorrect**

**Sensor log entries:**

2020-02-17 14:01:36.5315 Info ImpersonationManager CreateImpersonatorAsync started [UserName=account_name Domain=domain1.test.local IsGroupManagedServiceAccount=True]  
2020-02-17 14:01:36.5750 Info ImpersonationManager CreateImpersonatorAsync finished [UserName=account_name Domain=domain1.test.local IsSuccess=False]

**Sensor Updater log entries:**

2020-02-17 14:02:19.6258 Warn GroupManagedServiceAccountImpersonationHelper GetGroupManagedServiceAccountAccessTokenAsync failed GMSA password could not be retrieved [errorCode=AccessDenied AccountName=account_name DomainDnsName=domain1.test.local]

**Cause:**

The sensor failed to retrieve the designated gMSA account from the Azure ATP portal.

**Resolution:**

Make sure that the gMSA account's credentials are correct and that the sensor has been granted permissions to retrieve the account's credentials.

## Report downloads cannot contain more than 300,000 entries

Azure ATP does not support report downloads that contain more than 300,000 entries per report. Reports will render as incomplete if more than 300,000 entries are included.

**Cause:**

This is an engineering limitation.

**Resolution:**

No known resolution.

## See Also

- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
