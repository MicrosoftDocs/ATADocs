---
title: Configure event collection
description: In this step of installing Microsoft Defender for Identity, you configure data sources.
ms.date: 02/05/2023
ms.topic: how-to
---

# Configure event collection

To enhance detection capabilities, Microsoft Defender for Identity needs the Windows events listed in [Configure event collection](configure-windows-event-collection.md#configure-event-collection). These events can either be read automatically by the Defender for Identity sensor or if the Defender for Identity sensor isn't deployed, it can be forwarded to the Defender for Identity standalone sensor in one of two ways, by configuring the [Defender for Identity standalone sensor to listen for SIEM events or by [Configuring Windows Event Forwarding](configure-event-forwarding.md).

> [!NOTE]
>
> - Defender for Identity standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the Defender for Identity sensor.

In addition to collecting and analyzing network traffic to and from the domain controllers, Defender for Identity can use Windows events to further enhance detections. These events can be received from your SIEM or by setting Windows Event Forwarding from your domain controller. Events collected provide Defender for Identity with additional information that isn't available via the domain controller network traffic.

## SIEM/Syslog

Defender for Identity Standalone sensors are configured by default to receive Syslog data. For Defender for Identity Standalone sensors to be able to consume that data you need to forward your Syslog data to the sensor.

> [!NOTE]
> Defender for Identity only listens on IPv4 and not IPv6.

> [!IMPORTANT]
>
> - Do not forward all the Syslog data to the Defender for Identity sensor.
> - Defender for Identity supports UDP traffic from the SIEM/Syslog server.

Refer to your SIEM/Syslog server's product documentation for information on how to configure forwarding of specific events to another server.

> [!NOTE]
> If you do not use a SIEM/Syslog server, you can configure your Windows domain controllers to forward all required events to be collected and analyzed by Defender for Identity.

## Configuring the Defender for Identity sensor to listen for SIEM events

- Configure your SIEM or Syslog server to forward all required events to the IP address of one of the Defender for Identity Standalone sensors. For more information about configuring your SIEM, see your SIEM online help or technical support options for specific formatting requirements for each SIEM server.

Defender for Identity supports SIEM events in the following formats:

### RSA Security Analytics

`<Syslog Header>RsaSA\n2015-May-19 09:07:09\n4776\nMicrosoft-Windows-Security-Auditing\nSecurity\XXXXX.subDomain.domain.org.il\nYYYYY$\nMMMMM \n0x0`

- Syslog header is optional.

- "\n" character separator is required between all fields.
- The fields, in order, are:
    1. RsaSA constant (must appear).
    2. The timestamp of the actual event (make sure it's not the timestamp of the arrival to the SIEM or when it's sent to Defender for Identity). Preferably in milliseconds accuracy, this is important.
    3. The Windows event ID
    4. The Windows event provider name
    5. The Windows event log name
    6. The name of the computer receiving the event (the DC in this case)
    7. The name of the user authenticating
    8. The name of the source host name
    9. The result code of the NTLM
- The order is important and nothing else should be included in the message.

### MicroFocus ArcSight

`CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:4776|The domain controller attempted to validate the credentials for an account.|Low| externalId=4776 cat=Security rt=1426218619000 shost=KKKKKK dhost=YYYYYY.subDomain.domain.com duser=XXXXXX cs2=Security cs3=Microsoft-Windows-Security-Auditing cs4=0x0 cs3Label=EventSource cs4Label=Reason or Error Code`

- Must comply with the protocol definition.

- No syslog header.
- The header part (the part that's separated by a pipe) must exist (as stated in the protocol).
- The following keys in the *Extension* part must be present in the event:
  - externalId = the Windows event ID
  - rt = the timestamp of the actual event (make sure it's not the timestamp of the arrival to the SIEM or when it's sent to Defender for Identity). Preferably  in milliseconds accuracy, this is important.
  - cat = the Windows event log name
  - shost = the source host name
  - dhost = the computer receiving the event (the DC in this case)
  - duser = the user authenticating
- The order isn't important for the *Extension* part
- There must be a custom key and keyLable for these two fields:
  - "EventSource"
  - "Reason or Error Code" = The result code of the NTLM

### Splunk

`<Syslog Header>\r\nEventCode=4776\r\nLogfile=Security\r\nSourceName=Microsoft-Windows-Security-Auditing\r\nTimeGenerated=20150310132717.784882-000\r\ComputerName=YYYYY\r\nMessage=`

The computer attempted to validate the credentials for an account.

Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0

Logon Account: Administrator

Source Workstation: SIEM

Error Code: 0x0

- Syslog header is optional.

- There's a "\r\n" character separator between all required fields. Note that these are the control characters CRLF (0D0A in hex) and not literal characters.
- The fields are in key=value format.
- The following keys must exist and have a value:
  - EventCode = the Windows event ID
  - Logfile = the Windows event log name
  - SourceName = The Windows event provider name
  - TimeGenerated = the timestamp of the actual event (make sure it's not the timestamp of the arrival to the SIEM or when it's sent to Defender for Identity). The format should match yyyyMMddHHmmss.FFFFFF, preferably  in milliseconds accuracy, this is important.
  - ComputerName = the source host name
  - Message = the original event text from the Windows event
- The Message Key and value MUST be last.
- The order isn't important for the key=value pairs.

### QRadar

QRadar enables event collection via an agent. If the data is gathered using an agent, the time format is gathered without millisecond data. Because Defender for Identity needs millisecond data, it's necessary to set QRadar to use agentless Windows event collection. For more information, see [QRadar: Agentless Windows Events Collection using the MSRPC Protocol](https://www.ibm.com/support/pages/qradar-agentless-windows-events-collection-using-msrpc-protocol-msrpc-faq).

```text
<13>Feb 11 00:00:00 %IPADDRESS% AgentDevice=WindowsLog AgentLogFile=Security Source=Microsoft-Windows-Security-Auditing Computer=%FQDN% User= Domain= EventID=4776 EventIDCode=4776 EventType=8 EventCategory=14336 RecordNumber=1961417 TimeGenerated=1456144380009 TimeWritten=1456144380009 Message=The computer attempted to validate the credentials for an account. Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: Administrator Source Workstation: HOSTNAME Error Code: 0x0
```

The fields needed are:

- The agent type for the collection

- The Windows event log provider name
- The Windows event log source
- The DC fully qualified domain name
- The Windows event ID

TimeGenerated is the timestamp of the actual event (make sure it's not the timestamp of the arrival to the SIEM or when it's sent to Defender for Identity). The format should match yyyyMMddHHmmss.FFFFFF, preferably in milliseconds accuracy, this is important.

Message is the original event text from the Windows event

Make sure to have \t between the key=value pairs.

>[!NOTE]
> Using WinCollect for Windows event collection is not supported.

## See also

- [Defender for Identity sizing tool](<https://aka.ms/mdi/sizingtool>)
- [Defender for Identity SIEM log reference](cef-format-sa.md)
- [Defender for Identity prerequisites](prerequisites.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
