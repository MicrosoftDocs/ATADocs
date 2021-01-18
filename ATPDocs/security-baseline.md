---
title: Azure security baseline for Microsoft Defender for Identity
description: The Microsoft Defender for Identity security baseline provides procedural guidance and resources for implementing the security recommendations specified in the Azure Security Benchmark.
author: msmbaldwin
ms.service: microsoft-defender-for-identity
ms.topic: conceptual
ms.date: 12/03/2020
ms.author: mbaldwin
ms.custom: subject-security-benchmark

# Important: This content is machine generated; do not modify this topic directly. Contact mbaldwin for more information.

---

# Azure security baseline for Microsoft Defender for Identity

This security baseline applies guidance from the [Azure Security Benchmark version 2.0](/azure/security/benchmarks/overview) to Microsoft Defender
for Identity. The Azure Security Benchmark provides recommendations on how you can secure your cloud solutions on Azure. The content is grouped by the **security controls** defined by the Azure Security Benchmark and the related guidance applicable to Microsoft Defender
for Identity. **Controls** not applicable to Microsoft Defender
for Identity have been excluded.

To see how Microsoft Defender
for Identity completely maps to the Azure Security Benchmark, see the [full Microsoft Defender
for Identity security baseline mapping file](https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Offer%20Security%20Baselines).

## Network Security

*For more information, see the [Azure Security Benchmark: Network Security](/azure/security/benchmarks/security-controls-v2-network-security).*

### NS-6: Simplify network security rules

**Guidance**: Use Azure Virtual Network Service Tags to define network access controls on network security groups or Azure Firewall configured for your Defender for Identity resources. You can use service tags in place of specific IP addresses when creating security rules. By specifying the service tag name (For example: "AzureAdvancedThreatProtection") in the appropriate source or destination field of a rule, you can allow or deny the traffic for the corresponding service. Microsoft manages the address prefixes encompassed by the service tag and automatically updates the service tag as addresses change.

- [Enable access to Defender for Identity service URLs in the proxy server](configure-proxy.md#enable-access-to--service-urls-in-the-proxy-server)

- [Understand and using Service Tags](/azure/virtual-network/service-tags-overview)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

## Identity Management

*For more information, see the [Azure Security Benchmark: Identity Management](/azure/security/benchmarks/security-controls-v2-identity-management).*

### IM-1: Standardize Azure Active Directory as the central identity and authentication system

**Guidance**: Defender for Identity uses Azure Active Directory (Azure AD) as the default identity and access management service. You should standardize Azure AD to govern your organization’s identity and access management in:

- Microsoft Cloud resources, such as the Azure portal, Azure Storage, Azure Virtual Machine (Linux and Windows), Azure Key Vault, PaaS, and SaaS applications.
- Your organization's resources, such as applications on Azure or your corporate network resources.

Securing Azure AD should be a high priority in your organization’s cloud security practice. Azure AD provides an identity secure score to help you assess identity security posture relative to Microsoft’s best practice recommendations. Use the score to gauge how closely your configuration matches best practice recommendations, and to make improvements in your security posture.

Note: Azure AD supports external identity that allows users without a Microsoft account to sign in to their applications and resources with their external identity.

- [Tenancy in Azure Active Directory](/azure/active-directory/develop/single-and-multi-tenant-apps) 

- [How to create and configure an Azure AD instance](/azure/active-directory/fundamentals/active-directory-access-create-new-tenant) 

- [Use external identity providers for application](/azure/active-directory/b2b/identity-providers) 

- [What is the identity secure score in Azure Active Directory](/azure/active-directory/fundamentals/identity-secure-score)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### IM-4: Use strong authentication controls for all Azure Active Directory based access

**Guidance**: Defender for Identity uses Azure Active Directory that supports strong authentication controls through multifactor authentication, and strong passwordless methods.

- Multifactor authentication - Enable Azure AD multifactor authentication and follow Azure Security Center Identity and Access Management recommendations for some best practices in your multifactor authentication setup. Multifactor authentication can be enforced on all, select users or at the per-user level based on sign-in conditions and risk factors.
- Passwordless authentication - Three passwordless authentication options are available: Windows Hello for Business, Microsoft Authenticator app, and on-premises authentication methods such as smart cards.

For administrator and privileged users, ensure the highest level of the strong authentication method is used, followed by rolling out the appropriate strong authentication policy to other users.

- [How to enable multifactor authentication in Azure](/azure/active-directory/authentication/howto-mfa-getstarted) 

- [Introduction to passwordless authentication options for Azure Active Directory](/azure/active-directory/authentication/concept-authentication-passwordless) 

- [Azure AD default password policy](/azure/active-directory/authentication/concept-sspr-policy#password-policies-that-only-apply-to-cloud-user-accounts) 

- [Eliminate bad passwords using Azure AD Password Protection](/azure/active-directory/authentication/concept-password-ban-bad)

**Azure Security Center monitoring**: Yes

**Responsibility**: Customer

## Privileged Access

*For more information, see the [Azure Security Benchmark: Privileged Access](/azure/security/benchmarks/security-controls-v2-privileged-access).*

### PA-1: Protect and limit highly privileged users

**Guidance**: Defender for Identity has the following highly-privileged accounts:
Global administrator

Security administrator

Limit the number of highly privileged accounts or roles and protect these accounts at an elevated level because users with this privilege can directly or indirectly read and modify every resource in your Azure environment.

You can enable just-in-time (JIT) privileged access to Azure resources and Azure Active Directory (Azure AD) using Azure AD Privileged Identity Management (PIM). JIT grants temporary permissions to perform privileged tasks only when users need it. PIM can also generate security alerts when there is suspicious or unsafe activity in your Azure AD organization.
- [Microsoft Defender for Identity role groups](role-groups.md)

- [Administrator role permissions in Azure AD](/azure/active-directory/users-groups-roles/directory-assign-admin-roles) 

- [Use Azure Privileged Identity Management security alerts](/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts) 

- [Securing privileged access for hybrid and cloud deployments in Azure AD](/azure/active-directory/users-groups-roles/directory-admin-roles-secure)

**Azure Security Center monitoring**: Yes

**Responsibility**: Customer

### PA-2: Restrict administrative access to business-critical systems

**Guidance**: Defender for Identity uses Azure role-based access control (Azure RBAC) to isolate access to business-critical systems by restricting which accounts are granted privileged access to the subscriptions and management groups they are in.

Ensure that you also restrict access to the management, identity, and security systems that have administrative access to your business-critical access such as Active Directory Domain Controllers (DCs), security tools, and system management tools with agents installed on business-critical systems. Attackers who compromise these management and security systems can immediately weaponize them to compromise business-critical assets.

All types of access controls should be aligned to your enterprise segmentation strategy to ensure consistent access control.

- [Microsoft Defender for Identity role groups](role-groups.md)

- [Azure Components and Reference model](/security/compass/microsoft-security-compass-introduction#azure-components-and-reference-model-2151) 

- [Management Group Access](/azure/governance/management-groups/overview#management-group-access) 

- [Azure subscription administrators](/azure/cost-management-billing/manage/add-change-subscription-administrator)

**Azure Security Center monitoring**: Yes

**Responsibility**: Customer

### PA-3: Review and reconcile user access regularly

**Guidance**: Defender for Identity uses Azure Active Directory accounts to manage its resources, review user accounts, and access assignment regularly to ensure the accounts and their access are valid. You can use Azure AD access reviews to review group memberships, access to enterprise applications, and role assignments. Azure AD reporting can provide logs to help discover stale accounts. You can also use Azure AD Privileged Identity Management to create an access review report workflow to facilitate the review process.

In addition, Azure Privileged Identity Management can also be configured to alert when an excessive number of administrator accounts are created, and to identify administrator accounts that are stale or improperly configured.

Note: Some Azure services support local users and roles which are not managed through Azure AD. You will need to manage these users separately.

- [Create an access review of Azure resource roles in Privileged Identity Management (PIM)](/azure/active-directory/privileged-identity-management/pim-resource-roles-start-access-review) 

- [How to use Azure AD identity and access reviews](/azure/active-directory/governance/access-reviews-overvie)

**Azure Security Center monitoring**: Yes

**Responsibility**: Customer

### PA-6: Use privileged access workstations

**Guidance**: Secured, isolated workstations are critically important for the security of sensitive roles like administrators, developers, and critical service operators. Use highly secured user workstations and/or Azure Bastion for administrative tasks. Use Azure Active Directory, Microsoft Defender for Endpoint, and/or Microsoft Intune to deploy a secure and managed user workstation for administrative tasks. The secured workstations can be centrally managed to enforce secured configuration including strong authentication, software and hardware baselines, restricted logical and network access.

- [Understand privileged access workstations](/azure/active-directory/devices/concept-azure-managed-workstation) 
- [Deploy a privileged access workstation](/azure/active-directory/devices/howto-azure-managed-workstation)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

## Data Protection

*For more information, see the [Azure Security Benchmark: Data Protection](/azure/security/benchmarks/security-controls-v2-data-protection).*

### DP-2: Protect sensitive data

**Guidance**: Defender for Identity protects sensitive data by restricting access using Azure Active Directory (Azure AD) roles.

To ensure consistent access control, all types of access control should be aligned to your enterprise segmentation strategy. The enterprise segmentation strategy should also be informed by the location of sensitive or business-critical data and systems.

For the underlying platform, which is managed by Microsoft, Microsoft treats all customer content as sensitive and guards against customer data loss and exposure. To ensure customer data within Azure remains secure, Microsoft implements default data protection controls and capabilities.
- [Azure AD roles with access to Cloud App Security](/cloud-app-security/manage-admins)

- [Azure Role-based Access Control (RBAC)](/azure/role-based-access-control/overview) 

- [Understand customer data protection in Azure](/azure/security/fundamentals/protection-customer-data)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

## Asset Management

*For more information, see the [Azure Security Benchmark: Asset Management](/azure/security/benchmarks/security-controls-v2-asset-management).*

### AM-1: Ensure security team has visibility into risks for assets

**Guidance**: Ensure security teams are granted Security Reader permissions in your Azure tenant and subscriptions so they can monitor for security risks using Azure Security Center. 

Depending on how security team responsibilities are structured, monitoring for security risks could be the responsibility of a central security team or a local team. That said, security insights and risks must always be aggregated centrally within an organization. 

Security Reader permissions can be applied broadly to an entire tenant (Root Management Group) or scoped to management groups or specific subscriptions. 

Note: Additional permissions might be required to get visibility into workloads and services. 

- [Overview of Security Reader Role](/azure/role-based-access-control/built-in-roles#security-reader)

- [Overview of Azure Management Groups](/azure/governance/management-groups/overview)

**Azure Security Center monitoring**: Currently not available

**Responsibility**: Customer

## Logging and Threat Detection

*For more information, see the [Azure Security Benchmark: Logging and Threat Detection](/azure/security/benchmarks/security-controls-v2-logging-threat-protection).*

### LT-1: Enable threat detection for Azure resources

**Guidance**: Defender for Identity can notify you when it detects suspicious activities, by sending security and health alerts to your Syslog server through a nominated sensor.
Forward any logs from Defender for Identity to your SIEM which can be used to set up custom threat detections. Ensure you are monitoring different types of Azure assets for potential threats and anomalies. Focus on getting high-quality alerts to reduce false positives for analysts to sort through. Alerts can be sourced from log data, agents, or other data.

- [How to integrate with Syslog](setting-syslog.md)
- [Create custom analytics rules to detect threats](/azure/sentinel/tutorial-detect-threats-custom) 

- [Cyber threat intelligence with Azure Sentinel](/azure/architecture/example-scenario/data/sentinel-threat-intelligence)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### LT-2: Enable threat detection for Azure identity and access management

**Guidance**: Azure Active Directory (Azure AD) provides the following user logs that can be viewed in Azure AD reporting or integrated with Azure Monitor, Azure Sentinel, or other SIEM/monitoring tools for more sophisticated monitoring and analytics use cases:

- Sign-ins – The sign-ins report provides information about the usage of managed applications and user sign-in activities.

- Audit logs - Provides traceability through logs for all changes done by various features within Azure AD. Examples of audit logs include changes made to any resources within Azure AD like adding or removing users, apps, groups, roles, and policies.

- Risky sign-ins - A risky sign-in is an indicator for a sign-in attempt that might have been performed by someone who is not the legitimate owner of a user account.

- Users flagged for risk - A risky user is an indicator for a user account that might have been compromised.

Azure Security Center can also alert on certain suspicious activities such as an excessive number of failed authentication attempts, deprecated accounts in the subscription. In addition to the basic security hygiene monitoring, Azure Security Center’s Threat Protection module can also collect more in-depth security alerts from individual Azure compute resources (virtual machines, containers, app service), data resources (SQL DB and storage), and Azure service layers. This capability allows you to see account anomalies inside the individual resources.

- [Audit activity reports in the Azure Active Directory](/azure/active-directory/reports-monitoring/concept-audit-logs) 

- [Enable Azure Identity Protection](/azure/active-directory/identity-protection/overview-identity-protection) 
- [Threat protection in Azure Security Center](/azure/security-center/threat-protection)

**Azure Security Center monitoring**: Yes

**Responsibility**: Customer

### LT-5: Centralize security log management and analysis

**Guidance**: Ensure you are integrating Azure activity logs into your central logging. Ingest logs via Azure Monitor to aggregate security data generated by endpoint devices, network resources, and other security systems. In Azure Monitor, use Log Analytics workspaces to query and perform analytics, and use Azure Storage accounts for long term and archival storage.

In addition, enable and onboard data to Azure Sentinel or a third-party SIEM.

Many organizations choose to use Azure Sentinel for “hot” data that is used frequently and Azure Storage for “cold” data that is used less frequently.

Defender for Identity offers to forward all security-related logs to your SIEM for centralized management.

- [How to collect platform logs and metrics with Azure Monitor](/azure/azure-monitor/platform/diagnostic-settings) 
- [How to onboard Azure Sentinel](/azure/sentinel/quickstart-onboard) 

- [Integrate Defender for Identity with Syslog](setting-syslog.md)

**Azure Security Center monitoring**: Yes

**Responsibility**: Customer

## Incident Response

*For more information, see the [Azure Security Benchmark: Incident Response](/azure/security/benchmarks/security-controls-v2-incident-response).*

### IR-1: Preparation – update incident response process for Azure

**Guidance**: Ensure your organization has processes to respond to security incidents, has updated these processes for Azure, and is regularly exercising them to ensure readiness.

- [Implement security across the enterprise environment](/azure/cloud-adoption-framework/security/security-top-10#4-process-update-incident-response-ir-processes-for-cloud)

- [Incident response reference guide](/microsoft-365/downloads/IR-Reference-Guide.pdf)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### IR-2: Preparation – setup incident notification

**Guidance**: Set up security incident contact information in Azure Security Center. This contact information is used by Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. You also have options to customize incident alerts and notifications in different Azure services based on your incident response needs. 

- [How to set the Azure Security Center security contact](/azure/security-center/security-center-provide-security-contact-details)

**Azure Security Center monitoring**: Yes

**Responsibility**: Customer

### IR-3: Detection and analysis – create incidents based on high quality alerts

**Guidance**: Ensure you have a process to create high-quality alerts and measure the quality of alerts. This allows you to learn lessons from past incidents and prioritize alerts for analysts, so they don’t waste time on false positives. 

High-quality alerts can be built based on experience from past incidents, validated community sources, and tools designed to generate and clean up alerts by fusing and correlating diverse signal sources. 

Azure Security Center (ASC) provides high-quality alerts across many Azure assets. You can use the ASC data connector to stream the alerts to Azure Sentinel. Azure Sentinel lets you create advanced alert rules to generate incidents automatically for an investigation. 

Export your Azure Security Center alerts and recommendations using the export feature to help identify risks to Azure resources. Export alerts and recommendations either manually or in an ongoing, continuous fashion.

- [How to configure export](/azure/security-center/continuous-export)

- [How to stream alerts into Azure Sentinel](/azure/sentinel/connect-azure-security-center)

**Azure Security Center monitoring**: Currently not available

**Responsibility**: Customer

### IR-4: Detection and analysis – investigate an incident

**Guidance**: Ensure analysts can query and use diverse data sources as they investigate potential incidents, to build a full view of what happened. Diverse logs should be collected to track the activities of a potential attacker across the kill chain to avoid blind spots.  You should also ensure insights and learnings are captured for other analysts and for future historical reference.  

The data sources for investigation include the centralized logging sources that are already being collected from the in-scope services and running systems but can also include:

- Network data – use network security groups' flow logs, Azure Network Watcher, and Azure Monitor to capture network flow logs and other analytics information. 

- Snapshots of running systems: 

    - Use Azure virtual machine's snapshot capability to create a snapshot of the running system's disk. 

    - Use the operating system's native memory dump capability to create a snapshot of the running system's memory.

    - Use the snapshot feature of the Azure services or your software's own capability to create snapshots of the running systems.

Azure Sentinel provides extensive data analytics across virtually any log source and a case management portal to manage the full lifecycle of incidents. Intelligence information during an investigation can be associated with an incident for tracking and reporting purposes. 

- [Snapshot a Windows machine's disk](/azure/virtual-machines/windows/snapshot-copy-managed-disk)

- [Snapshot a Linux machine's disk](/azure/virtual-machines/linux/snapshot-copy-managed-disk)

- [Microsoft Azure Support diagnostic information and memory dump collection](https://azure.microsoft.com/support/legal/support-diagnostic-information-collection/) 

- [Investigate incidents with Azure Sentinel](/azure/sentinel/tutorial-investigate-cases)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### IR-5: Detection and analysis – prioritize incidents

**Guidance**: Provide context to analysts on which incidents to focus on first based on alert severity and asset sensitivity. 

Azure Security Center assigns a severity to each alert to help you prioritize which alerts should be investigated first. The severity is based on how confident Security Center is in the finding or the analytics used to issue the alert, as well as the confidence level that there was malicious intent behind the activity that led to the alert.

Additionally, mark resources using tags and create a naming system to identify and categorize Azure resources, especially those processing sensitive data.  It is your responsibility to prioritize the remediation of alerts based on the criticality of the Azure resources and environment where the incident occurred.

- [Security alerts in Azure Security Center](/azure/security-center/security-center-alerts-overview)

- [Use tags to organize your Azure resources](/azure/azure-resource-manager/resource-group-using-tags)

**Azure Security Center monitoring**: Currently not available

**Responsibility**: Customer

### IR-6: Containment, eradication and recovery – automate the incident handling

**Guidance**: Automate manual repetitive tasks to speed up response time and reduce the burden on analysts. Manual tasks take longer to execute, slowing each incident, and reducing how many incidents an analyst can handle. Manual tasks also increase analyst fatigue, which increases the risk of human error that causes delays, and degrades the ability of analysts to focus effectively on complex tasks. 
Use workflow automation features in Azure Security Center and Azure Sentinel to automatically trigger actions or run a playbook to respond to incoming security alerts. The playbook takes actions, such as sending notifications, disabling accounts, and isolating problematic networks. 

- [Configure workflow automation in Security Center](/azure/security-center/workflow-automation)

- [Set up automated threat responses in Azure Security Center](/azure/security-center/tutorial-security-incident#triage-security-alerts)

- [Set up automated threat responses in Azure Sentinel](/azure/sentinel/tutorial-respond-threats-playbook)

**Azure Security Center monitoring**: Currently not available

**Responsibility**: Customer

## Posture and Vulnerability Management

*For more information, see the [Azure Security Benchmark: Posture and Vulnerability Management](/azure/security/benchmarks/security-controls-v2-vulnerability-management).*

### PV-8: Conduct regular attack simulation

**Guidance**: As required, conduct penetration testing or red team activities on your Azure resources and ensure remediation of all critical security findings.
Follow the Microsoft Cloud Penetration Testing Rules of Engagement to ensure your penetration tests are not in violation of Microsoft policies. Use Microsoft's strategy and execution of Red Teaming and live site penetration testing against Microsoft-managed cloud infrastructure, services, and applications.

- [Penetration testing in Azure](/azure/security/fundamentals/pen-testing)

- [Penetration Testing Rules of Engagement](https://www.microsoft.com/msrc/pentest-rules-of-engagement?rtc=1) 

- [Microsoft Cloud Red Teaming](https://gallery.technet.microsoft.com/Cloud-Red-Teaming-b837392e)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Shared

## Governance and Strategy

*For more information, see the [Azure Security Benchmark: Governance and Strategy](/azure/security/benchmarks/security-controls-v2-governance-strategy).*

### GS-1: Define asset management and data protection strategy 

**Guidance**: Ensure you document and communicate a clear strategy for continuous monitoring and protection of systems and data. Prioritize discovery, assessment, protection, and monitoring of business-critical data and systems. 

This strategy should include documented guidance, policy, and standards for the following elements: 

-	Data classification standard in accordance with the business risks

-	Security organization visibility into risks and asset inventory 

-	Security organization approval of Azure services for use 

-	Security of assets through their lifecycle

-	Required access control strategy in accordance with organizational data classification

-	Use of Azure native and third-party data protection capabilities

-	Data encryption requirements for in-transit and at-rest use cases

-	Appropriate cryptographic standards

For more information, see the following references:
- [Azure Security Architecture Recommendation - Storage, data, and encryption](/azure/architecture/framework/security/storage-data-encryption?amp;bc=%2fsecurity%2fcompass%2fbreadcrumb%2ftoc.json&toc=%2fsecurity%2fcompass%2ftoc.json)

- [Azure Security Fundamentals - Azure Data security, encryption, and storage](/azure/security/fundamentals/encryption-overview)

- [Cloud Adoption Framework - Azure data security and encryption best practices](/azure/security/fundamentals/data-encryption-best-practices?amp;bc=%2fazure%2fcloud-adoption-framework%2f_bread%2ftoc.json&toc=%2fazure%2fcloud-adoption-framework%2ftoc.json)

- [Azure Security Benchmark - Asset management](/azure/security/benchmarks/security-benchmark-v2-asset-management)

- [Azure Security Benchmark - Data Protection](/azure/security/benchmarks/security-benchmark-v2-data-protection)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### GS-2: Define enterprise segmentation strategy 

**Guidance**: Establish an enterprise-wide strategy to segmenting access to assets using a combination of identity, network, application, subscription, management group, and other controls.

Carefully balance the need for security separation with the need to enable daily operation of the systems that need to communicate with each other and access data.

Ensure that the segmentation strategy is implemented consistently across control types including network security, identity, and access models, and application permission/access models, and human process controls.

- [Guidance on segmentation strategy in Azure (video)](/security/compass/microsoft-security-compass-introduction#azure-components-and-reference-model-2151)

- [Guidance on segmentation strategy in Azure (document)](/security/compass/governance#enterprise-segmentation-strategy)

- [Align network segmentation with enterprise segmentation strategy](/security/compass/network-security-containment#align-network-segmentation-with-enterprise-segmentation-strategy)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### GS-3: Define security posture management strategy

**Guidance**: Continuously measure and mitigate risks to your individual assets and the environment they are hosted in. Prioritize high-value assets and highly-exposed attack surfaces, such as published applications, network ingress and egress points, user and administrator endpoints, etc.

- [Azure Security Benchmark - Posture and vulnerability management](/azure/security/benchmarks/security-benchmark-v2-posture-vulnerability-management)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### GS-4: Align organization roles, responsibilities, and accountabilities

**Guidance**: Ensure you document and communicate a clear strategy for roles and responsibilities in your security organization. Prioritize providing clear accountability for security decisions, educating everyone on the shared responsibility model, and educate technical teams on technology to secure the cloud.

- [Azure Security Best Practice 1 – People: Educate Teams on Cloud Security Journey](/azure/cloud-adoption-framework/security/security-top-10#1-people-educate-teams-about-the-cloud-security-journey)

- [Azure Security Best Practice 2 - People: Educate Teams on Cloud Security Technology](/azure/cloud-adoption-framework/security/security-top-10#2-people-educate-teams-on-cloud-security-technology)

- [Azure Security Best Practice 3 - Process: Assign Accountability for Cloud Security Decisions](/azure/cloud-adoption-framework/security/security-top-10#4-process-update-incident-response-ir-processes-for-cloud)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### GS-5: Define network security strategy

**Guidance**: Establish an Azure network security approach as part of your organization’s overall security access control strategy.  

This strategy should include documented guidance, policy, and standards for the following elements: 

-	Centralized network management and security responsibility

-	Virtual network segmentation model aligned with the enterprise segmentation strategy

-	Remediation strategy in different threat and attack scenarios

-	Internet edge and ingress and egress strategy

-	Hybrid cloud and on-premises interconnectivity strategy

-	Up-to-date network security artifacts (e.g. network diagrams, reference network architecture)

For more information, see the following references:
- [Azure Security Best Practice 11 - Architecture. Single unified security strategy](/azure/cloud-adoption-framework/security/security-top-10#11-architecture-establish-a-single-unified-security-strategy)

- [Azure Security Benchmark - Network Security](/azure/security/benchmarks/security-benchmark-v2-network-security)

- [Azure network security overview](/azure/security/fundamentals/network-overview)

- [Enterprise network architecture strategy](/azure/cloud-adoption-framework/ready/enterprise-scale/architecture)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### GS-6: Define identity and privileged access strategy

**Guidance**: Establish an Azure identity and privileged access approaches as part of your organization’s overall security access control strategy.  

This strategy should include documented guidance, policy, and standards for the following elements: 

-	A centralized identity and authentication system and its interconnectivity with other internal and external identity systems

-	Strong authentication methods in different use cases and conditions

-	Protection of highly privileged users

-	Anomaly user activities monitoring and handling  

-	User identity and access review and reconciliation process

For more information, see the following references:

- [Azure Security Benchmark - Identity management](/azure/security/benchmarks/security-benchmark-v2-identity-management)

- [Azure Security Benchmark - Privileged access](/azure/security/benchmarks/security-benchmark-v2-privileged-access)

- [Azure Security Best Practice 11 - Architecture. Single unified security strategy](/azure/cloud-adoption-framework/security/security-top-10#11-architecture-establish-a-single-unified-security-strategy)

- [Azure identity management security overview](/azure/security/fundamentals/identity-management-overview)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

### GS-7: Define logging and threat response strategy

**Guidance**: Establish a logging and threat response strategy to rapidly detect and remediate threats while meeting compliance requirements. Prioritize providing analysts with high-quality alerts and seamless experiences so that they can focus on threats rather than integration and manual steps. 

This strategy should include documented guidance, policy, and standards for the following elements: 

-	The security operations (SecOps) organization’s role and responsibilities 

-	A well-defined incident response process aligning with NIST or another industry framework 

-	Log capture and retention to support threat detection, incident response, and compliance needs

-	Centralized visibility of and correlation information about threats, using SIEM, native Azure capabilities, and other sources 

-	Communication and notification plan with your customers, suppliers, and public parties of interest

-	Use of Azure native and third-party platforms for incident handling, such as logging and threat detection, forensics, and attack remediation and eradication

-	Processes for handling incidents and post-incident activities, such as lessons learned and evidence retention

For more information, see the following references:

- [Azure Security Benchmark - Logging and threat detection](/azure/security/benchmarks/security-benchmark-v2-logging-threat-detection)

- [Azure Security Benchmark - Incident response](/azure/security/benchmarks/security-benchmark-v2-incident-response)

- [Azure Security Best Practice 4 - Process. Update Incident Response Processes for Cloud](/azure/cloud-adoption-framework/security/security-top-10#4-process-update-incident-response-ir-processes-for-cloud)

- [Azure Adoption Framework, logging, and reporting decision guide](/azure/cloud-adoption-framework/decision-guides/logging-and-reporting/)

- [Azure enterprise scale, management, and monitoring](/azure/cloud-adoption-framework/ready/enterprise-scale/management-and-monitoring)

**Azure Security Center monitoring**: Not applicable

**Responsibility**: Customer

## Next steps

- See the [Azure Security Benchmark V2 overview](/azure/security/benchmarks/overview)
- Learn more about [Azure security baselines](/azure/security/benchmarks/security-baselines-overview)
