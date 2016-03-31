---
title: Troubleshooting ATA using the ATA database | Microsoft Advanced Threat Analytics
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
|Get the details of a user/computer/group (UniqueEntity), such as user ID.|`db.UniqueEntity.find({SearchNames: "<name of entity in lower case>"})`||
|Find Kerberos authentication traffic originating from a specific computer on a specific day.|`db.KerberosAs_<date>.find({SourceComputerId: "<Id of the source computer>"})`|To get the &lt;ID of the source computer&gt; you can query the UniqueEntity collections, as shown in the example.<br /><br />Each network activity type, for example Kerberos authentications, has its own collection per UTC date.|
|Find NTLM traffic originating from a specific computer related to a specific account on a specific day.|`db.Ntlm_<date>.find({SourceComputerId: "<Id of the source computer>", SourceAccountId: "<Id of the account>"})`|To get the &lt;ID of the source computer&gt; and &lt;ID of the account&gt; you can query the UniqueEntity collections, as shown in the example.<br /><br />Each network activity type, for example NTLM authentications, has its own collection per UTC date.|
|Search for advanced properties such as the active dates of an account. For example you may want to know if an account has at least 21 days of activity for the abnormal behavior machine learning algorithm to be able to run on it.|`db.Profile.find({UniqueEntityId: "<Id of the account>")`|To get the &lt;ID of the account&gt; you can query the UniqueEntity collections, as shown in the example.<br>The property name that shows the dates in which the account has been active is called: "ActiveDates".|
|Make advanced configuration changes. In this example we change the send queue size for all ATA Gateways to 10,000.|`db.SystemProfile.update( {_t: "GatewaySystemProfile"} ,`<br>`{$set:{"Configuration.EntitySenderConfiguration.EntityBatchBlockMaxSize" : "10000"}})`|`|
For example, if you are investigating a suspicious activity that occurred on 20/10/2015 and want to learn more about the NTLM activities that "John Doe" performed on that day:<br /><br />First, find the ID of "John Doe"

`db.UniqueEntity.find({Name: "John Doe"})`<br>Take a note of his ID as indicated by the value of "`_id`" For our example, let's assume the ID is "`123bdd24-b269-h6e1-9c72-7737as875351`"<br>Then, search for the collection with the closest date that is before the date you are looking for, in our example 20/10/2015.<br>Then, search for John Doe's account NTLM activities:


    `db.Ntlms_<closest date>.find({SourceAccountId: "123bdd24-b269-h6e1-9c72-7737as875351"})
## ATA Configuration
The configuration of ATA is stored in the "SystemProfile" collection in the database.
This collection is backed up every hour by the ATA Center service to a file called: "SystemProfile.json". This is located in a subfolder called "Backup". In the default ATA installed location it can be found here:  **C:\Program Files\Microsoft Advanced Threat Analytics\Center\Backup\SystemProfile.json**. It is recommended that you back up this file somewhere when making major changes to ATA.
It is possible to restore all the settings by running the following command:

`mongoimport.exe --db ATA --collection SystemProfile --file "<SystemProfile.json backup file>" --upsert`
