---
title: Edit misconfigured certificate templates owner | Microsoft Defender for Identity
description: This article provides an overview of Microsoft Defender for Identity's misconfigured certificate template ACL security posture assessment report.
ms.date: 11/14/2023
ms.topic: how-to
---

# Security assessment: Edit misconfigured certificate templates owner  (Preview)

## What is a misconfigured certificate template owner?

Certificate templates are Active Directory objects with an owner that controls the access to the object and editing the object.

<!--unsure about this, not in blog-->
If the owner permissions grant a built-in, unprivileged group, such as *Authenticated users*, *Domain users*, *Everyone*, with permissions that allow for template setting changes, like *Full control* or *Write DACL*, an adversary can introduce a template misconfiguration, escalate privileges, and compromise the entire domain.


## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for a misconfigured certificate template owner.

<!--IMAGE TBD-->

1. Research why the template owner might be misconfigured.
1. Remediate the issue by changing the owner to a privileged and monitored user.

Make sure to test your settings in a controlled environment before turning them on in production.

> [!NOTE]
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.

## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
