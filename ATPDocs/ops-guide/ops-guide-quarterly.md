---
title: Quarterly operational guide - Microsoft Defender for Identity
description: Learn about the Microsoft Defender for Identity activities that we recommend for your team on a quarterly basis.
ms.date: 01/29/2024
ms.topic: how-to
---

# Quarterly operational guide - Microsoft Defender for Identity

This article reviews the Microsoft Defender for Identity activities we recommend for your team on a quarterly basis.

## Review server setup process to include sensors

**Where**: Your organization's internal process documentation

**Persona**: Security administrators

We recommend that you periodically verify your organization's server setup process to make sure that it includes installing the Defender for Identity sensor. This ensures that all new domain controllers, AD CS, and AD FS servers are protected right away.

For more information, see [Deploy Microsoft Defender for Identity with Microsoft Defender XDR](../deploy/deploy-defender-identity.md).

## Check domain configuration via PowerShell

**Where**: PowerShell on your Defender for Identity sensor machines

**Persona**: Security administrators

We recommend that you periodically run the **Test-MDIConfiguration** PowerShell command to test whether your domain controller Advanced Audit Policy settings are configured correctly. Misconfigured Advanced Audit Policy settings can cause gaps in the Event Log and incomplete Defender for Identity coverage.

For more information, see:

- [Configure audit policies for Windows event logs](../deploy/configure-windows-event-collection.md)
- [Test-MDIConfiguration](/powershell/module/defenderforidentity/test-mdiconfiguration?view=defenderforidentity-latest) PowerShell documentation


## Related content

For more information, see:

- [Microsoft Defender XDR Security operations overview](/security/operations/overview)
- [Microsoft Defender for Identity operational guide](ops-guide.md)
- [Daily operational guide - Microsoft Defender for Identity](ops-guide-daily.md)
- [Weekly operational guide - Microsoft Defender for Identity](ops-guide-weekly.md)
- [Monthly operational guide - Microsoft Defender for Identity](ops-guide-monthly.md)
