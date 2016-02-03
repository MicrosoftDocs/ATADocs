---
title: ATA Database Management
ms.custom: na
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: 1d27dba8-fb30-4cce-a68a-f0b1df02b977
author: Rkarlin
---
# ATA Database Management
If you need to move, backup or restore the ATA database, use these procedures for working with MongoDB.

## Backing up the ATA database
Refer to the [relevant MongoDB documentation](http://docs.mongodb.org/manual/administration/backup/).

## Restoring the ATA database
Refer to the [relevant MongoDB documentation](http://docs.mongodb.org/manual/administration/backup/).

## Moving the ATA database to another drive

1.  Stop the **Microsoft Advanced Threat Analytics Center** service.

2.  Stop the **MongoDB** service.

3.  Open the Mongo configuration file located by default at: C:\Program Files\Microsoft Advanced Threat Analytics\Center\MongoDB\bin\mongod.cfg.

    Find the parameter `storage: dbPath`

4.  Move the folder listed in the `dbPath` parameter to the new location.

5.  Change the `dbPath` parameter inside the mongo configuration file to the new folder path and save and close the file.

    ![](../Image/ATA_mongoDB_moveDB.png)

6.  Start the **MongoDB** service.

7.  Open a command prompt and run the Mongo shell by running `mongo.exe ATA` .

    By default, the mongo.exe will be located in: C:\Program Files\Microsoft Advanced Threat Analytics\Center\MongoDB\bin

8.  Run the following command: `db.SystemProfiles.update( {_t: "CenterSystemProfile"} , {$set:{"Configuration.CenterDatabaseClientConfiguration.DataPath" : "<New DB Location>"}}) Instead of <New DB Location>` where &lt;New DB Location&gt; is the new folder path.

9. Start the **Microsoft Advanced Threat Analytics Center** service.

## See Also
[ATA Architecture](../Topic/ATA_Architecture.md)
 [ATA Prerequisites](../Topic/ATA_Prerequisites.md)
 [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)

