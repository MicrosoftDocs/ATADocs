---
title: Troubleshooting ATA using the ATA database
ms.custom: na
ms.reviewer: na
ms.suite: na
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: d89e7aff-a6ef-48a3-ae87-6ac2e39f3bdb
author: Rkarlin
---
# Troubleshooting ATA using the ATA database
ATA uses MongoDB as its database.
You can interact with the database using the default command line or using a user interface tool that you download  to perform advanced tasks and troubleshooting.

## Interacting with the database
The default and most basic way to query the database is using the Mongo shell:

1.  Open a command line window and change the path to the MongoDB bin folder. The default path is : **C:\Program Files\Microsoft Advanced Threat Analytics\Center\MongoDB\bin**.

2.  Run: `mongo.exe ATA`. Make sure to type ATA with all capital letters.

|How to...|Syntax|Notes|
|-------------|----------|---------|
|Check for collections in the database.|`show collections`|Useful as an end-to-end test to see that traffic is being written to the database and that event 4776 is being received by ATA.|
|Get the details of a user/computer/group (UniqueEntities), such as user  ID.|`db.UniqueEntities.find({SearchNames: "<name of entity in lower case>"})`||
|Find Kerberos authentication traffic originating from a specific computer on a specific day.|`db.KerberosKdcs_<date>.find({SourceComputerId: "<Id of the source computer>"})`|To get the &lt;ID of the source computer&gt; you can query the UniqueEntity collections, as shown in the example.<br /><br />Each network activity type, for example Kerberos authentications, has its own collection per UTC date.|
|Find NTLM traffic originating from a specific computer related to a specific account on a specific day.|`db.Ntlms_<date>.find({SourceComputerId: "<Id of the source computer>", SourceAccountId: "<Id of the account>"})`|To get the &lt;ID of the source computer&gt; and &lt;ID of the account&gt; you can query the UniqueEntity collections, as shown in the example.<br /><br />Each network activity type, for example NTLM authentications, has its own collection per UTC date.|
|Search for advanced properties such as the active dates of an account. For example you may want to know if an account has at least 21 days of activity for the abnormal behavior machine learning algorithm to be able to run on it.|`db.Profiles.find({UniqueEntityId: "<Id of the account>")`|To get the &lt;ID of the account&gt; you can query the UniqueEntity collections, as shown in the example.<br /><br />The property name that shows the dates in which the account has been active is called: "ActiveDates".<br />|
|Make advanced configuration changes. In this example we change the send queue size for all ATA Gateways to 10,000.|`db.SystemProfiles.update( {_t: "GatewaySystemProfile"} ,`<br /><br />`{$set:{"Configuration.EntitySenderConfiguration.EntityBatchBlockMaxSize" : "10000"}})`|For example, if you are investigating a suspicious activity that occurred on the 20/10/2015 and want to learn more about the NTLM activities that "John Doe" performed on that day.<br /><br />First, find the ID of "John Doe"<br />db.UniqueEntities.find({Name: "John Doe"})<br /><br />Take a note of his ID as indicated by the value of "_id" in our example let's assume the ID is "123bdd24-b269-h6e1-9c72-7737as875351"<br /><br />Then, search for John Doe's account NTLM activities:<br /><br />`db.Ntlms_20151020.find({SourceAccountId: "123bdd24-b269-h6e1-9c72-7737as875351"})`|

## ATA Configuration
The configuration of ATA is stored in the "SystemProfiles" collection in the database.
This collection is backed up every hour by the ATA Center service to a file called: "SystemProfiles.json". This is located in a subfolder called "Backup". In the default ATA installed location it can be found here:  **C:\Program Files\Microsoft Advanced Threat Analytics\Center\Backup\SystemProfiles.json**. It is recommended that you back up this file somewhere when making major changes to ATA.
It is possible to restore all the settings by running the following command:

`mongoimport.exe --db ATA --collection SystemProfiles --file "<SystemProfiles.json backup file>" --upsert`

