function Log-It() {
<#
.SYNOPSIS

Logs a message to stdout.

Author: Tobias Neitzel (@qtc_de)
License: GPLv3

.DESCRIPTION

Log function used by PowerEnum. Prints the specified string to stdout
prefixed with the timestamp of the call.

.PARAMETER Msg

The message to log

.EXAMPLE

Log-It "Log this message :)"
#>
    Param (
        [Parameter(Position = 0)]
        [String]
        $Msg
    )
    $Date = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    Write-Host "[$Date] :: $Msg"
}

function Get-UserSIDs {
<#
.SYNOPSIS

Helper function that obtains the SID values associated to the specified
principal.

Author: Tobias Neitzel (@qtc_de)
License: GPLv3

.DESCRIPTION

Obtains all SID values associated to the specified principal and returns them
as an array. If the Principal parameter is not used, returns the SID values
associated to the current user. The Principal parameter can either be a simple
user name for local user accounts or a User Principal Name (UPN: user@domain)
for domain accounts. Domain accounts can only be used when connected to the
associated domain. When an empty string is specified for the Principal
parameter, the function returns a set of SID values associated to groups
that low privileged users are usually member of.

.PARAMETER Principal

Principal to obtain SID values for. If the Principal parameter is not used,
obtain the SID values associated to the current user. The Principal parameter
can either be a simple user name for local user accounts or a User Principal
Name (UPN: user@domain) for domain accounts. Domain accounts can only be used
when connected to the associated domain. When an empty string is specified for
the Principal parameter, the function returns a set of SID values associated
to groups that low privileged users are usually member of. Optional.

.EXAMPLE

PS C:\> Get-UserSids -Principal Carlos
S-1-5-21-7623811015-3361044348-030300820-1005
S-1-5-32-545
S-1-1-0
S-1-2-0
S-1-5-4
S-1-5-11
S-1-5-15
S-1-5-113
S-1-5-64-10

#>
    Param (
        [String]
        $Principal
    )

    $CurrentUserSids = @()

    if ($PSBoundParameters.ContainsKey('Principal')) {

        if( $Principal -like "*@*" ) {
            # If the specified principal is a full UPN, we attempt to resolve it using WindowsIdentity.
            # This is the most reliable approach to get all available SID values, but seems only to work
            # for AD users while connected to the AD.
            try {
                $UserIdentity = New-Object System.Security.Principal.WindowsIdentity($Principal)
            } catch {
                Write-Error "Unable to obtain WindowsIdentity for $Principal. Are you connected to the domain?"
                break
            }

            $CurrentUserSids += $UserIdentity.Groups | Select-Object -ExpandProperty Value
            $CurrentUserSids += $UserIdentity.User.Value
        }

        else {

            if($Principal) {
                # If a username was specified we attempt to resolve the users SID and the SIDs of local
                # groups the user is member of.

                try {
                    $CurrentUserSids += @(Get-LocalUser $Principal -ErrorAction Stop | %{ $_.SID.Value })
                } catch {
                    Write-Error "User $Principal was not found on this system."
                    break
                }

                $CurrentUserSids += Get-LocalGroup | Where-Object {
                     Get-LocalGroupMember -Name $_.Name -Member $Principal -ErrorAction SilentlyContinue
                 } | %{ $_.SID.Value }
            }

            # In any case, we add some default groups low privileged users are usually members of
            $CurrentUserSids += "S-1-1-0"      # Everyone
            $CurrentUserSids += "S-1-2-0"      # Local
            $CurrentUserSids += "S-1-5-4"      # Interactive
            $CurrentUserSids += "S-1-5-11"     # Authenticated Users
            $CurrentUserSids += "S-1-5-15"     # This Organization
            $CurrentUserSids += "S-1-5-113"    # Local Account
            $CurrentUserSids += "S-1-5-64-10"  # NTLM Auth
        }

    } else {
        # If the -Principal parameter was not used, we take the easy route and just use WindowsIdentity::GetCurrent
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids += $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
    }

    $CurrentUserSids| Sort-Object -Unique
}

function Start-Watcher {
<#
.SYNOPSIS

Create a file system watcher.

Author: Tobias Neitzel (@qtc_de)
License: GPLv3
Required Dependencies: Log-It

.DESCRIPTION

Creates a file system watcher on the specified directory.
Optionally copies or moves modified files to a user specified
directory.

.PARAMETER Path

The file system path to create the watcher on. Must be a local
directory.

.PARAMETER Copy

Optional file system path to copy modified files to.

.PARAMETER Move

Optional file system path to move modified files to.

.PARAMETER Pattern

Optional file name pattern to watch for. Default is "*".

.PARAMETER Recursive

Whether to watch subdirectories too. Default is false.

.EXAMPLE

PS C:\Users\Carlos> Start-Watcher .\Desktop
[24/02/2022 07:42:58] :: Creating file system watcher.
[24/02/2022 07:42:58] :: Register event handlers.
[24/02/2022 07:42:58] :: Starting Watcher. Press Ctrl+C to stop watching.
[24/02/2022 07:43:03] :: C:\Users\Carlos\Desktop\New Text Document.txt was Created.
[24/02/2022 07:43:12] :: C:\Users\Carlos\Desktop\New Text Document.txt was renamed to C:\Users\Carlos\Desktop\Watcher-Test.txt.
[24/02/2022 07:43:16] :: Watcher removed.

.EXAMPLE

PS C:\Users\Carlos> Start-Watcher .\Desktop -Copy C:\Users\Carlos\Documents\ -Recursive
[24/02/2022 07:55:22] :: Creating file system watcher.
[24/02/2022 07:55:22] :: Register event handlers.
[24/02/2022 07:55:22] :: Starting Watcher. Press Ctrl+C to stop watching.
[24/02/2022 07:55:25] :: C:\Users\Carlos\Desktop\Internal\credentials.txt was Changed.
[24/02/2022 07:55:25] :: Copying C:\Users\Carlos\Desktop\Internal\credentials.txt to C:\Users\Carlos\Documents\
[24/02/2022 07:55:27] :: Watcher removed.
#>
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter()]
        [String]
        $Copy,

        [Parameter()]
        [String]
        $Move,

        [Parameter()]
        [String]
        $Pattern = "*",

        [Parameter()]
        [Switch]
        $Recursive
    )

    $Path = Resolve-Path $Path
    Log-It "Creating file system watcher."
    $Watcher = New-Object IO.FileSystemWatcher $Path, $Pattern -Property @{
        IncludeSubdirectories = $Recursive
        NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'
    }

    if ($PSBoundParameters.ContainsKey('Move')) {
        $PostProcessing = "Log-It `"Moving `$Path to $Move`";"
        $PostProcessing += "Move-Item `"`$Path`" '$Move';"
    } elseif ($PSBoundParameters.ContainsKey('Copy')) {
        $PostProcessing = "Log-It `"Copying `$Path to $Copy`";"
        $PostProcessing += "Copy-Item -Recurse `"`$Path`" '$Copy';"
    }

    $Action = [ScriptBlock]::Create(@(
        '$Path = $Event.SourceEventArgs.FullPath;'
        '$OldPath = $Event.SourceEventArgs.OldFullPath;'
        '$ChangeType = $Event.SourceEventArgs.ChangeType;'
        'switch ($ChangeType)'
        '{'
        '   "Deleted" { Log-It "$Path was deleted."; return }'
        '   "Renamed" { Log-It "$OldPath was renamed to $Path."; return }'
        '   default { Log-It "$Path was $ChangeType." }'
        '}'
        "$PostProcessing"
    ))

    Log-It "Register event handlers."
    $Handlers = . {
        Register-ObjectEvent $Watcher -EventName Created -Action $Action
        Register-ObjectEvent $Watcher -EventName Changed -Action $Action
        Register-ObjectEvent $Watcher -EventName Deleted -Action $Action
        Register-ObjectEvent $Watcher -EventName Renamed -Action $Action
    }

    try {
        Log-It "Starting Watcher. Press Ctrl+C to stop watching."
        Wait-Event
    }

    finally {
        $Watcher.Dispose()
        Log-It "Watcher removed."
    }
}

function Get-AccessiblePath {
<#
.SYNOPSIS

Checks for interesting access permissions within the file system.

Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: Get-UserSIDs
EditedBy: Clément Labro (@itm4n) and Tobias Neitzel (@qtc_de)

.DESCRIPTION

This is a slightly modified version of the Get-ModifiablePath function from the well known
PowerUp (https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1#L737)
tool by @harmj0y. It includes improvements from PrivescCheck by @itm4n
(https://github.com/itm4n/PrivescCheck/blob/master/src/02_Helpers.ps1#L1280) and some other
modifications from the @qtc_de PowerUp fork (https://github.com/qtc-de/PowerSploit/blob/master/Privesc/PowerUp.ps1#L791).

This function should be used together with Get-ChildItem as demonstrated in the example
section below. When using Get-ChildItem, it is recommended to use the -Force switch to
include hidden files and directories. It is always recommended to enumerate file permissions
with a high privileged user, because modifiable files may be contained within a folder
where low privileged users do not have access to. When running as a high privileged user,
you should use the -Principal option to compare file permissions against the actually
targeted principal. Accessible files within a protected folder are still accessible, due
to the SeChangeNotifyPrivilege.

Compared to the original version of the function, this version allows also checking for
readable files using the -Readable switch. This is interesting to enumerate accessible
files within protected folders, which are still accesible due to the SeChangeNotifyPrivilege.

.PARAMETER Path

String. The file system path to check for interesting access permissions. Required.

.PARAMETER Principal

String. The Principal to check for. This can be either a User Principal Name (UPN: user@domain)
or the name of a local user account. User Principal Names can only be used when the system is
connected to the associated domain. If this parameter is not specified, the ceck is executed against
the permission set of the current user. When the Principal parameter is used, but left empty, the
check is performed against a default list of groups where low privileged users are usually member
of. Optional.

.PARAMETER Principals

String[]. Same as the Principal parameter, but accepts an array of principals.

.PARAMETER Owner

String. Only process files that are owned by the specified owner.

.PARAMETER Owners

String[]. Same as the Owner parameter, but accepts an array of owners.

.PARAMETER ExcludeOwner

String. Do not process files when they are owned by the specified owner.

.PARAMETER ExcludeOwners

String. Same as the ExludeOwner parameter, but accepts an array of owners.

.PARAMETER AccessMaskValue

UInt32. Custom access mask to check permissions against. Optional.

.PARAMETER Readable

Switch. Also search for readable paths. This can be useful to audit folders where low privileged
users should not have access to. Readable or writable paths within a protected folder are still
accessible by users that are not able to traverse or list the folder due to the SeChangeNotifyPrivilege.
This is different from Unix file permissions and often overlooked. Therefore, it is worth looking
for. Optional.

.EXAMPLE

PS C:\> Get-ChildItem C:\ProgramData -Force -Recurse -ErrorAction SilentlyContinue | Get-AccessiblePath

AccessiblePath                                   Owner                  IdentityReference Permissions
--------------                                   -----                  ----------------- -----------
C:\ProgramData\chocolatey\logs\choco.summary.log BUILTIN\Administrators BUILTIN\Users     {WriteAttributes, Synchronize, AppendData/AddSubdirectory, WriteExtendedAttributes...}
C:\ProgramData\chocolatey\logs\chocolatey.log    BUILTIN\Administrators BUILTIN\Users     {WriteAttributes, Synchronize, AppendData/AddSubdirectory, WriteExtendedAttributes...}
...

.EXAMPLE

PS C:\> Get-ChildItem C:\Users\Administrator\ -Force -Recurse -ErrorAction SilentlyContinue | Get-AccessiblePath -Readable -Principal Carlos

AccessiblePath                   Owner                  IdentityReference Permissions
--------------                   -----                  ----------------- -----------
C:\Users\Administrator\creds.txt BUILTIN\Administrators BUILTIN\Users     {ReadData, ReadAttributes, WriteData, WriteAttributes}
...

.EXAMPLE

PS C:\Users\carlos> Get-ChildItem .\AppData\Local\ -Recurse -Force -ErrorAction SilentlyContinue | Get-AccessiblePath -ExcludeOwner Carlos

AccessiblePath                                                           Owner                  IdentityReference  Permissions
--------------                                                           -----                  -----------------  -----------
C:\Users\carlos\AppData\Local\Application Data                           BUILTIN\Administrators WINBOX\carlos      {WriteOwner, Delete, WriteAttributes, Synchronize...}
C:\Users\carlos\AppData\Local\History                                    BUILTIN\Administrators WINBOX\carlos      {WriteOwner, Delete, WriteAttributes, Synchronize...}
C:\Users\carlos\AppData\Local\Temporary Internet Files                   BUILTIN\Administrators WINBOX\carlos      {WriteOwner, Delete, WriteAttributes, Synchronize...}
C:\Users\carlos\AppData\Local\Microsoft\Windows\Temporary Internet Files BUILTIN\Administrators WINBOX\carlos      {WriteOwner, Delete, WriteAttributes, Synchronize...}
...

.OUTPUTS

PowerEnum.AccessiblePath

Custom PSObject containing the Permissions, Owner, AccesiblePath and IdentityReference for a accesible path.
#>
    [OutputType('PowerEnum.AccessiblePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [String]
        $Principal,

        [String[]]
        $Principals,

        [String]
        $Owner,

        [String[]]
        $Owners,

        [String]
        $ExcludeOwner,

        [String[]]
        $ExcludeOwners,

        [UInt32]
        $AccessMaskValue,

        [Switch]
        $Readable
    )

    BEGIN {
        $ErrorActionPreference = 'Stop'

        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [UInt32]'0x80000000' = 'GenericRead'
            [UInt32]'0x40000000' = 'GenericWrite'
            [UInt32]'0x20000000' = 'GenericExecute'
            [UInt32]'0x10000000' = 'GenericAll'
            [UInt32]'0x02000000' = 'MaximumAllowed'
            [UInt32]'0x01000000' = 'AccessSystemSecurity'
            [UInt32]'0x00100000' = 'Synchronize'
            [UInt32]'0x00080000' = 'WriteOwner'
            [UInt32]'0x00040000' = 'WriteDAC'
            [UInt32]'0x00020000' = 'ReadControl'
            [UInt32]'0x00010000' = 'Delete'
            [UInt32]'0x00000100' = 'WriteAttributes'
            [UInt32]'0x00000080' = 'ReadAttributes'
            [UInt32]'0x00000040' = 'DeleteChild'
            [UInt32]'0x00000020' = 'Execute/Traverse'
            [UInt32]'0x00000010' = 'WriteExtendedAttributes'
            [UInt32]'0x00000008' = 'ReadExtendedAttributes'
            [UInt32]'0x00000004' = 'AppendData/AddSubdirectory'
            [UInt32]'0x00000002' = 'WriteData/AddFile'
            [UInt32]'0x00000001' = 'ReadData/ListDirectory'
        }

        # this is an xor of GenericWrite, GenericAll, MaximumAllowed, WriteOwner, WriteDAC, AppendData/AddSubdirectory, WriteData/AddFile, Delete
        $MAccessMask = 0x520d0006

        if ($PSBoundParameters['Readable']) {
            # add GenericRead, Execute/Traverse and ReadData/ListDirectory permissions
            $MAccessMask = $MAccessMask -bxor 0x80000021

        } elseif ($PSBoundParameters['AccessMaskValue']) {
            $MAccessMask = $AccessMaskValue
        }

        $TargetOwners = @()
        $ExcludedOwners = @()
        $CurrentUserSids = @()

        ForEach ($Item in $( @($Principals, $Principal) |  ? { $_ } | sort -uniq )) {
            $CurrentUserSids += Get-UserSIDs -Principal $Item
        }

        if ($CurrentUserSids.Length -eq 0) {
            $CurrentUserSids += Get-UserSIDs
        }

        ForEach ($Item in $( @($Owners, $Owner) |  ? { $_ } | sort -uniq )) {
            $Tmp = New-Object System.Security.Principal.NTAccount($Item)
            $TargetOwners += $Tmp.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }

        ForEach ($Item in $( @($ExcludeOwners, $ExcludeOwner) |  ? { $_ } | sort -uniq )) {
            $Tmp = New-Object System.Security.Principal.NTAccount($Item)
            $ExcludedOwners += $Tmp.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }

        $TranslatedIdentityReferences = @{}

        function Get-Sid {

            Param(
                [String]$Identity
            )

            if ($Identity -match '^S-1-5.*' -or $Identity -match '^S-1-15-.*') {
                $Identity

            } else {

                if ($TranslatedIdentityReferences -notcontains $Identity) {

                    # When the SID translation fails, it is often because of identity names like
                    # "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES". These can often
                    # still be resolved after stripping the prefix.
                    try {
                        $IdentityUser = New-Object System.Security.Principal.NTAccount($Identity)
                        $TranslatedIdentityReferences[$Identity] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch [System.Security.Principal.IdentityNotMappedException] {
                        $IdentityUser = New-Object System.Security.Principal.NTAccount($Identity | Split-Path -Leaf)
                        $TranslatedIdentityReferences[$Identity] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                }

                $TranslatedIdentityReferences[$Identity]
            }
        }
    }

    PROCESS {
        $ErrorActionPreference = 'Continue'
        $Path | Sort-Object -Unique | ForEach-Object {

            $CandidatePath = $_

            try {

                $Acl = Get-Acl -LiteralPath $CandidatePath -ErrorAction Stop
                $Owner = $Acl.Owner;
                $OwnerSid = Get-Sid $Owner

                # If a desired owner was specified or if specific owners were excluded, just skip
                if ($TargetOwners.Length -ne 0 -and $TargetOwners -notcontains $OwnerSid) { return }
                if ($ExcludedOwners.Length -ne 0 -and $ExcludedOwners -contains $OwnerSid) { return }

                # If we are owner, we have implicit full control over the object. Only the Owner property is imporant here, as the security group of an object
                # gets ignored (https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961983(v=technet.10)?redirectedfrom=MSDN
                if ($CurrentUserSids -contains $OwnerSid) {
                    $Out = New-Object PSObject
                    $Out | Add-Member -MemberType "Noteproperty" -Name 'AccessiblePath' -Value $CandidatePath
                    $Out | Add-Member -MemberType "Noteproperty" -Name 'Owner' -Value $Owner
                    $Out | Add-Member -MemberType "Noteproperty" -Name 'IdentityReference' -Value $Owner
                    $Out | Add-Member -MemberType "Noteproperty" -Name 'Permissions' -Value @('Owner')
                    $Out.PSObject.TypeNames.Insert(0, 'PowerEnum.AccessiblePath')
                    return $Out
                }
                # Check for NULL DACL first. If no DACL is set, 'Everyone' has full access on the object.
                if ($null -eq $Acl.Access) {
                    $Out = New-Object -TypeName PSObject
                    $Out | Add-Member -MemberType "NoteProperty" -Name "AccessiblePath" -Value $CandidatePath
                    $Out | Add-Member -MemberType "Noteproperty" -Name 'Owner' -Value $Owner
                    $Out | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value "Everyone"
                    $Out | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value "GenericAll"
                    $Out.PSObject.TypeNames.Insert(0, 'PowerEnum.AccessiblePath')
                    return $Out
                }

            } catch [System.UnauthorizedAccessException] {
                Write-Verbose "Skipping: $CandidatePath [Access Denied]"
                return
            }

            $Acl | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                $FileSystemRights = $_.FileSystemRights.value__

                if( $FileSystemRights -band $MAccessMask )  {

                    $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }
                    $IdentitySid = Get-Sid $_.IdentityReference

                    if ($CurrentUserSids -contains $IdentitySID) {
                        $Out = New-Object PSObject
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'AccessiblePath' -Value $CandidatePath
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'Owner' -Value $Owner
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'IdentityReference' -Value $_.IdentityReference
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'Permissions' -Value $Permissions
                        $Out.PSObject.TypeNames.Insert(0, 'PowerEnum.AccessiblePath')
                        return $Out
                    }
                }
            }
        }
    }
}

function Get-AccessibleReg {
<#
.SYNOPSIS

Takes multiple strings containing registry paths and returns
the registry paths with interesting access permissions.

Author: Tobias Neitzel (@qtc_de)
License: BSD 3-Clause
Required Dependencies: Get-UserSIDs
Contains improvements by: Clément Labro (@itm4n)

.DESCRIPTION

Takes multiple registry paths and enumerates access permissions on them. Any path that
matches the desired access mask is returned in a custom object that contains the
accessible path, the owner, associated permission set, and the IdentityReference the
interesting access permissions belongs to.

The skeleton of this function is based on the implementation of the the PowerUp fork
by @qtc_de (https://github.com/qtc-de/PowerSploit/blob/master/Privesc/PowerUp.ps1#L3423).
It was developed before PrivescCheck by @itm4n became a well known tool, which implements
a similar function (https://github.com/itm4n/PrivescCheck/blob/master/src/02_Helpers.ps1#L1633).
The base functionality is obviously pretty similar to the Get-ModifiablePath from the original
PowerUp script (https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1#L737)
by Will Schroeder (@harmj0y).

.PARAMETER Path

The registry path to enumerate. Required

.PARAMETER Principal

String. The Principal to check for. This can be either a User Principal Name (UPN: user@domain)
or the name of a local user account. User Principal Names can only be used when the system is
connected to the associated domain. If this parameter is not specified, the ceck is executed against
the permission set of the current user. When the Principal parameter is used, but left empty, the
check is performed against a default list of groups where low privileged users are usually member
of. Optional.

.PARAMETER AccessMaskValue

UInt32. Custom access mask to check permissions against. Optional.

.PARAMETER Readable

Switch. Also search for readable paths. This can be useful to audit keys where low privileged
users should not have access to. Readable or writable paths within a protected key are still
accessible by users that are not able to traverse or list the key due to the SeChangeNotifyPrivilege.
This is different from Unix file permissions and often overlooked. Therefore, it is worth looking
for. Optional.

.EXAMPLE

PS C:\> Get-ChildItem -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ -Recurse -ErrorAction SilentlyContinue | Get-AccessibleReg -Principal Carlos

AccessiblePath                                                                       Owner                       IdentityReference                Permissions
--------------                                                                       -----                       -----------------                -----------
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters\Settings NT SERVICE\TrustedInstaller NT AUTHORITY\INTERACTIVE         {CreateSubKey, SetValue, ReadPermissions}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters\Settings NT SERVICE\TrustedInstaller NT AUTHORITY\Authenticated Users {CreateSubKey, SetValue, ReadPermissions}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters         NT AUTHORITY\SYSTEM         NT AUTHORITY\INTERACTIVE         {CreateSubKey, ReadPermissions, EnumerateSubKeys, QueryValue}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters         NT AUTHORITY\SYSTEM         NT AUTHORITY\Authenticated Users {CreateSubKey, ReadPermissions, Notify, EnumerateSubKeys...}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds\Alignment                   NT AUTHORITY\SYSTEM         NT AUTHORITY\Authenticated Users {CreateSubKey, ReadPermissions, EnumerateSubKeys, QueryValue}

.OUTPUTS

PowerEnum.AccessiblePath

Custom PSObject containing the Permissions, Owner, AccessiblePath and IdentityReference for
a accessible registry path.
#>
    [OutputType('PowerEnum.AccessiblePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('PSPath')]
        [String[]]
        $Path,

        [String]
        $Principal,

        [UInt32]
        $AccessMaskValue,

        [Switch]
        $Readable
    )

    BEGIN {
        $AccessMask = @{
             [uint32]'0x80000000' = 'GenericRead'
             [uint32]'0x40000000' = 'GenericWrite'
             [uint32]'0x20000000' = 'GenericExecute'
             [uint32]'0x10000000' = 'GenericAll'
             [uint32]'0x02000000' = 'MaximumAllowed'
             [uint32]'0x00080000' = 'WriteOwner'
             [uint32]'0x00040000' = 'WriteDAC'
             [uint32]'0x00020000' = 'ReadPermissions'
             [uint32]'0x00010000' = 'Delete'
             [uint32]'0x00000020' = 'CreateLink'
             [uint32]'0x00000010' = 'Notify'
             [uint32]'0x00000008' = 'EnumerateSubKeys'
             [uint32]'0x00000004' = 'CreateSubKey'
             [uint32]'0x00000002' = 'SetValue'
             [uint32]'0x00000001' = 'QueryValue'
        }

        # this is an xor of GenericWrite, GenericAll, MaximumAllowed, WriteOwner, WriteDAC, CreateSubKey, SetValue, CreateLink, Delete
        $MAccessMask = 0x520d0026

        if ($PSBoundParameters['Readable']) {
            # add GenericRead, EnumerateSubkeys and QueryValue permissions
            $MAccessMask = $MAccessMask -bxor 0x80000009

        } elseif ($PSBoundParameters['AccessMaskValue']) {
            $MAccessMask = $AccessMaskValue
        }

        if ($PSBoundParameters.ContainsKey('Principal')) {
            $CurrentUserSids = Get-UserSIDs -Principal $Principal
        } else {
            $CurrentUserSids = Get-UserSIDs
        }

        $TranslatedIdentityReferences = @{}

        function Get-Sid {

            Param(
                [String]$Identity
            )

            if ($Identity -match '^S-1-5.*' -or $Identity -match '^S-1-15-.*') {
                $Identity

            } else {

                if ($TranslatedIdentityReferences -notcontains $Identity) {

                    # When the SID translation fails, it is often because of identity names like
                    # "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES". These can often
                    # still be resolved after stripping the prefix.
                    try {
                        $IdentityUser = New-Object System.Security.Principal.NTAccount($Identity)
                        $TranslatedIdentityReferences[$Identity] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch [System.Security.Principal.IdentityNotMappedException] {
                        $IdentityUser = New-Object System.Security.Principal.NTAccount($Identity | Split-Path -Leaf)
                        $TranslatedIdentityReferences[$Identity] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                }

                $TranslatedIdentityReferences[$Identity]
            }
        }
    }

    PROCESS {

        $Path | Sort-Object -Unique | ForEach-Object {

            $CandidatePath = $_

            if( -not ($CandidatePath.StartsWith("Microsoft.") -or $CandidatePath.StartsWith("Registry::"))  ) {
                $CandidatePath = "Microsoft.PowerShell.Core\Registry::$($CandidatePath.replace(':',''))"
            }

            try {
                # Get-Acl fails on paths containing special characters like '/' or '*'. Therefore, we use Get-Item.
                $Key = Get-Item -LiteralPath $CandidatePath -ErrorAction Stop
                $Acl = $Key.GetAccessControl()
                $Owner = $Acl.Owner

                if ($null -eq $Acl.Access) {
                    $Out = New-Object -TypeName PSObject
                    $Out | Add-Member -MemberType "NoteProperty" -Name "AccessiblePath" -Value ($CandidatePath -replace '.+::')
                    $Out | Add-Member -MemberType "Noteproperty" -Name 'Owner' -Value $Owner
                    $Out | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value "Everyone"
                    $Out | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value "GenericAll"
                    $Out.PSObject.TypeNames.Insert(0, 'PowerEnum.AccessiblePath')
                    return $Out
                }

                else {
                    $OwnerSid = Get-Sid $Owner

                    # If we are owner, we have implicit full control over the object. Only the Owner property is imporant here, as the security group of an object
                    # gets ignored (https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961983(v=technet.10)?redirectedfrom=MSDN
                    if( $CurrentUserSids -contains $OwnerSid ) {
                        $Out = New-Object PSObject
                        $Out | Add-Member -MemberType "NoteProperty" -Name "AccessiblePath" -Value ($CandidatePath -replace '.+::')
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'Owner' -Value $Owner
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'IdentityReference' -Value $Owner
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'Permissions' -Value @('Owner')
                        $Out.PSObject.TypeNames.Insert(0, 'PowerEnum.AccessiblePath')
                        return $Out
                    }
                }

            } catch [System.UnauthorizedAccessException] {
                Write-Verbose "Skipping: $CandidatePath [Access Denied]"
                continue
            }

            $Acl | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                $RegistryRights = $_.RegistryRights.value__

                if( $RegistryRights -band $MAccessMask )  {

                    $Permissions = $AccessMask.Keys | Where-Object { $RegistryRights -band $_ } | ForEach-Object { $AccessMask[$_] }
                    $IdentitySid = Get-Sid $_.IdentityReference

                    if ($CurrentUserSids -contains $IdentitySID) {
                        $Out = New-Object PSObject
                        $Out | Add-Member -MemberType "NoteProperty" -Name "AccessiblePath" -Value ($CandidatePath -replace '.+::')
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'Owner' -Value $Owner
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'IdentityReference' -Value $_.IdentityReference
                        $Out | Add-Member -MemberType "Noteproperty" -Name 'Permissions' -Value $Permissions
                        $Out.PSObject.TypeNames.Insert(0, 'PowerEnum.ModifiableReg')
                        return $Out
                    }
                }
            }
        }
    }
}
