---
# Required metadata
# For more information, see https://review.learn.microsoft.com/en-us/help/platform/learn-editor-add-metadata?branch=main
# For valid values of ms.service, ms.prod, and ms.topic, see https://review.learn.microsoft.com/en-us/help/platform/metadata-taxonomies?branch=main

title:       # Add a title for the browser tab
description: # Add a meaningful description for search results
author:      LiorShapiraa # GitHub alias
ms.author:   t-lshapira # Microsoft alias
ms.service:  # Add the ms.service or ms.prod value
# ms.prod:   # To use ms.prod, uncomment it and delete ms.service
ms.topic:    # Add the ms.topic value
ms.date:     08/12/2024
---

# Security assessment: Rotate password for Entra Connect connector account

This article describes Microsoft Defender for Identity's Entra Connect connector account password rotation security posture assessment report.

> [!NOTE]
> This security assessment will be available only if Microsoft Defender for Identity sensor is installed on servers running Entra Connect services. 
## Why might the Entra Connect Connector account old password be a risk?

This report lists all MSOL (AD DS connector account) accounts in your organization with password last set over 90 days ago. It's important to change the password of MSOL accounts every 90 days to prevent attackers from allowing use of the high privileges that the connector account typically holds - replication permissions, reset password and so on. 

##   
How do I use this security assessment to improve my hybrid organizational security posture? 

1. Review the recommended action at[ https://security.microsoft.com/securescore?viewid=actions](https://security.microsoft.com/securescore?viewid=actions) for **Rotate password for Entra Connect Connector account.  
**  
For example:  
![User's image](media/rotate-password-entra-connect/image1.png)

1. Review the list of exposed entities to discover which of your AD DS connector accounts have a password more than 90 days old.

1. Take appropriate action on those accounts by following the steps on [how to change the AD DS connector account password](https://aka.ms/EntraIdPasswordChangeSyncService).

> [!NOTE]
> While assessments are updated in near real time, scores and statuses are updated every 24 hours. While the list of impacted entities is updated within a few minutes of your implementing the recommendations, the status may still take time until it's marked as **Completed**.
## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)

- [Check out the Defender for Identity forum!](https://aka.ms/MDIcommunity)

