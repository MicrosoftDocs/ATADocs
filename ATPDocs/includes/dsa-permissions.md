---
title: include file
description: include file
author: batamig
ms.date: 06/08/2023
---

The DSA requires read permissions on all objects in Active Directory, including the **Deleted Objects** container.

The read-only permissions on the **Deleted Objects** container allows Defender for Identity to detect user deletions from your Active Directory.

Use the following code sample to help you grant the required read permissions on the **Deleted Objects** container, whether or not you're using a gMSA account.

```powershell
# Declare the identity that you want to add read access to the deleted objects container:
$Identity = 'mdiSvc01'

# If the identity is a gMSA, first to create a group and add the gMSA to it:
$groupName = 'mdiUsr01Group'
$groupDescription = 'Members of this group are allowed to read the objects in the Deleted Objects container in AD'
if(Get-ADServiceAccount -Identity $Identity -ErrorAction SilentlyContinue) {
    $groupParams = @{
        Name           = $groupName
        SamAccountName = $groupName
        DisplayName    = $groupName
        GroupCategory  = 'Security'
        GroupScope     = 'Universal'
        Description    = $groupDescription
    }
    $group = New-ADGroup @groupParams -PassThru
    Add-ADGroupMember -Identity $group -Members ('{0}$' -f $Identity)
    $Identity = $group.Name
}

# Get the deleted objects container's distinguished name:
$distinguishedName = ([adsi]'').distinguishedName.Value
$deletedObjectsDN = 'CN=Deleted Objects,{0}' -f $distinguishedName

# Take ownership on the deleted objects container:
$params = @("$deletedObjectsDN", '/takeOwnership')
C:\Windows\System32\dsacls.exe $params

# Grant the 'List Contents' and 'Read Property' permissions to the user or group:
$params = @("$deletedObjectsDN", '/G', ('{0}\{1}:LCRP' -f ([adsi]'').name.Value, $Identity))
C:\Windows\System32\dsacls.exe $params
  
# To remove the permissions, uncomment the next 2 lines and run them instead of the two prior ones:
# $params = @("$deletedObjectsDN", '/R', ('{0}\{1}' -f ([adsi]'').name.Value, $Identity))
# C:\Windows\System32\dsacls.exe $params
```

For more information, see [Changing permissions on a deleted object container](/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc816824(v=ws.10)).
