---
# required metadata

title: Azure ATP Security Alert lab tutorial overview
description: This tutorial overview describes the four parts of the Azure ATP Security Alert lab for simulating threats for detection by Azure ATP.
ms.service: azure-advanced-threat-protection
ms.topic: tutorial
author: shsagir
ms.author: shsagir
ms.date: 02/28/2019

# optional metadata

# ms.custom
ms.reviewer: itargoet
# ms.subservice
# ROBOTS

---

# Tutorial overview: ATP security alert lab

The purpose of the Azure ATP Security Alert lab tutorial is to illustrate **Azure ATP**'s capabilities in identifying and detecting suspicious activities and potential attacks against your network. This four part tutorial explains how to install and configure a working environment to test against some of Azure ATP's *discrete* detections. This lab focuses on Azure ATP’s *signature*-based capabilities. The lab doesn't include advanced machine-learning and user or entity-based behavioral detections since those detections require a learning period with real network traffic of up to 30 days.

## Lab setup

The first tutorial in this four part series walks you through creating a lab for testing Azure ATP's discrete detections. The tutorial includes information about machines, users, and tools that are needed to set up the lab and complete its playbooks. The instructions assume you're comfortable setting up a domain controller and workstations for lab use along with other administrative tasks. The closer your lab is to the suggested lab setup, the easier it will be to follow Azure ATP testing procedures. When your lab setup is complete, use the Azure ATP Security Alert playbooks for testing.

> [!div class="nextstepaction"]
> [Setup an ATP security alert lab](atp-playbook-setup-lab.md)

## Reconnaissance playbook

The second tutorial in this four part series is a reconnaissance playbook. Reconnaissance activities allow attackers to gain a thorough understanding and complete mapping of your environment for later use. The playbook shows some of Azure ATP's capabilities in identifying and detecting suspicious activities from potential attacks using examples from common, publicly available hacking and attack tools.

> [!div class="nextstepaction"]
> [Reconnaissance playbook](atp-playbook-reconnaissance.md)


## Lateral movement playbook

The lateral movement playbook is third in the four part tutorial series. Lateral movements are made by an attacker attempting to gain domain dominance. As you run this playbook, you'll see lateral movement path threat detections and security alerts services of Azure ATP from the simulated lateral movements you make in your lab.  

> [!div class="nextstepaction"]
> [Lateral movement playbook](atp-playbook-lateral-movement.md)

## Domain dominance playbook

The last tutorial in the four part series is the domain dominance playbook. During the domain dominance phase, an attacker has already gained legitimate credentials to access your domain controller and attempts to achieve persistent domain dominance. You'll simulate some common domain dominance methods to see the domain dominance focused threat detection and security alert services of Azure ATP.

> [!div class="nextstepaction"]
> [Domain dominance playbook](atp-playbook-domain-dominance.md)


## Join the Community

Have more questions, or an interest in discussing Azure ATP and related security with others? Join the [Azure ATP Community](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection) today!
