function Set-DSSRawObject {
    <#
    .SYNOPSIS
        Make a modification to a specific object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific object and then performs a modification to it.

        This is not meant to be used as an interactive function; it is used as a worker function by most of the other higher-level functions.
    .EXAMPLE
        Set-DSSRawObject -SetType Remove -ObjectSID 'S-1-5-21-3515480276-2049723633-1306762111-1103'

        Removes (deletes) the object with the above SID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/remove-adobject
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # The type of modification to make.
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enable', 'Disable', 'Remove', 'Unlock')]
        [Alias('Type')]
        [String]
        $SetType,

        # The SAMAccountName of the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

        # The DistinguishedName of the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

        # The server to connect to.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        # The credential to use for access.
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Common_Search_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
        }

        if ($PSBoundParameters.ContainsKey('SAMAccountName')) {
            $Specific_Group_LDAPFilter = '(samaccountname={0})' -f $SAMAccountName
            $Directory_Search_Type = 'SAMAccountName'
            $Directory_Search_Value = $SAMAccountName
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $Specific_Group_LDAPFilter = '(distinguishedname={0})' -f $DistinguishedName
            $Directory_Search_Type = 'DistinguishedName'
            $Directory_Search_Value = $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $Specific_Group_LDAPFilter = '(objectsid={0})' -f $ObjectSID
            $Directory_Search_Type = 'ObjectSID'
            $Directory_Search_Value = $ObjectSID
        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            $Specific_Group_LDAPFilter = '(objectguid={0})' -f (Convert-GuidToHex -Guid $ObjectGUID)
            $Directory_Search_Type = 'ObjectGUID'
            $Directory_Search_Value = $ObjectGUID
        }
        $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_Group_LDAPFilter, $Specific_Group_LDAPFilter
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $Directory_Search_LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        if ($SetType -eq 'Remove') {
            $ShouldProcess_Setting = 'Remove'
        } else {
            $ShouldProcess_Setting = 'Set'
        }

        Write-Verbose ('{0}|Calling Find-DSSRawObject to get DirectoryEntry' -f $Function_Name)
        $global:Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            if ($PSCmdlet.ShouldProcess($Object_Directory_Entry.distinguishedname, $ShouldProcess_Setting)) {
                try {
                    if ($SetType -eq 'Enable') {
                        Write-Verbose ('{0}|Found object, attempting enable' -f $Function_Name)

                    } elseif ($SetType -eq 'Remove') {
                        Write-Verbose ('{0}|Found object, attempting delete' -f $Function_Name)
                        if ($Object_Directory_Entry.objectclass -contains 'Group') {
                            Write-Verbose ('{0}|Object is a group, getting parent OU first' -f $Function_Name)
                            $Group_Directory_Entry_Parent_OU = Get-DSSDirectoryEntry @Common_Search_Parameters -Path $Object_Directory_Entry.Parent
                            $Group_Directory_Entry_Parent_OU.Delete('Group', ('CN={0}' -f $Object_Directory_Entry.cn.Value))
                        } else {
                            $Object_Directory_Entry.DeleteTree()
                        }
                        Write-Verbose ('{0}|Delete successful' -f $Function_Name)
                    }
                } catch [System.UnauthorizedAccessException] {
                    $Terminating_ErrorRecord_Parameters = @{
                        'Exception'      = 'System.UnauthorizedAccessException'
                        'ID'             = 'DSS-{0}' -f $Function_Name
                        'Category'       = 'AuthenticationError'
                        'TargetObject'   = $Object_Directory_Entry
                        'Message'        = 'Insufficient access rights to perform the operation'
                        'InnerException' = $_.Exception
                    }
                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                }
            }
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Entry
                'Message'      = 'Cannot find object with {0} of "{1}"' -f $Directory_Search_Type, $Directory_Search_Value
            }
            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        }
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
