---
title: Microsoft Defender for Identity Security Alert lab  overview
description: This overview describes the four parts of the Microsoft Defender for Identity Security Alert lab for simulating threats for detection by Defender for Identity.
ms.date: 10/26/2020
ms.topic: overview
---

# Microsoft Defender for Identity security alert lab overview

Want to test specific Defender for Identity alerts? Find a some examples of Defender for Identity alerts and how to trigger them in [Playbook samples for Microsoft Defender for Identity](playbooks.md).

If you want to learn how to set up your Defender for Identity environment, and test it with a few alerts? Then continue reading this overview.

## Defender for Identity security alert lab

The purpose of the [!INCLUDE [Product long](includes/product-long.md)] Security Alert lab overview is to illustrate **[!INCLUDE [Product short](includes/product-short.md)]**'s capabilities in identifying and detecting suspicious activities and potential attacks against your network. This four part lab explains how to install and configure a working environment to test against some of [!INCLUDE [Product short](includes/product-short.md)]'s *discrete* detections. This lab focuses on [!INCLUDE [Product short](includes/product-short.md)]'s *signature*-based capabilities. The lab doesn't include advanced machine-learning and user or entity-based behavioral detections since those detections require a learning period with real network traffic of up to 30 days.

## Lab setup

The first lab in this four part series walks you through creating a lab for testing [!INCLUDE [Product short](includes/product-short.md)]'s discrete detections. The lab includes information about machines, users, and tools that are needed to set up the lab and complete its playbooks. The instructions assume you're comfortable setting up a domain controller and workstations for lab use along with other administrative tasks. The closer your lab is to the suggested lab setup, the easier it will be to follow [!INCLUDE [Product short](includes/product-short.md)] testing procedures. When your lab setup is complete, use the [!INCLUDE [Product short](includes/product-short.md)] Security Alert playbooks for testing.

> [!div class="nextstepaction"]
> [Setup an ATP security alert lab](playbook-setup-lab.md)

## Reconnaissance playbook

The second lab in this four part series is a reconnaissance playbook. Reconnaissance activities allow attackers to gain a thorough understanding and complete mapping of your environment for later use. The playbook shows some of [!INCLUDE [Product short](includes/product-short.md)]'s capabilities in identifying and detecting suspicious activities from potential attacks using examples from common, publicly available hacking and attack tools.

> [!div class="nextstepaction"]
> [Reconnaissance playbook](playbook-reconnaissance.md)

## Lateral movement playbook

The lateral movement playbook is third in the four part lab series. Lateral movements are made by an attacker attempting to gain domain dominance. As you run this playbook, you'll see lateral movement path threat detections and security alerts services of [!INCLUDE [Product short](includes/product-short.md)] from the simulated lateral movements you make in your lab.  

> [!div class="nextstepaction"]
> [Lateral movement playbook](playbook-lateral-movement.md)

## Domain dominance playbook

The last lab in the four part series is the domain dominance playbook. During the domain dominance phase, an attacker has already gained legitimate credentials to access your domain controller and attempts to achieve persistent domain dominance. You'll simulate some common domain dominance methods to see the domain dominance focused threat detection and security alert services of [!INCLUDE [Product short](includes/product-short.md)].

> [!div class="nextstepaction"]
> [Domain dominance playbook](playbook-domain-dominance.md)

## Next steps

- [[!INCLUDE [Product short](includes/product-short.md)] Security Alert Guide](suspicious-activity-guide.md)
- [Investigate lateral movement paths with [!INCLUDE [Product short](includes/product-short.md)]](use-case-lateral-movement-path.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
