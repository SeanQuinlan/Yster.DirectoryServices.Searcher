function Remove-DSSGroup {
    <#
    .SYNOPSIS
        Removes a specific group object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific group object and then deletes it, based on one of the following specified parameters:
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName
    .EXAMPLE
        Remove-DSSGroup -ObjectSID 'S-1-5-21-3515480276-2049723633-1306762111-1103'

        Deletes the group with the above SID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/remove-adgroup
    #>

    [CmdletBinding(DefaultParameterSetName = 'SAM', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        # The SAMAccountName of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

        # The DistinguishedName of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
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
            'Context'      = $Context
            'OutputFormat' = 'DirectoryEntry'
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
        }

        $Default_Group_LDAPFilter = '(objectcategory=group)'
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
            'LDAPFilter' = $Directory_Search_LDAPFilter
        }

        Write-Verbose ('{0}|Calling Find-DSSRawObject to get DirectoryEntry' -f $Function_Name)
        $global:Group_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Group_Directory_Entry) {
            if ($PSCmdlet.ShouldProcess($Group_Directory_Entry.distinguishedname, 'Remove')) {
                Write-Verbose ('{0}|Found group, attempting delete' -f $Function_Name)
                try {
                    $Directory_Search_Parent_OU_Parameters = @{
                        'LDAPFilter' = '(&(|(objectclass=organizationalunit)(objectclass=container))(distinguishedname={0}))' -f ($Group_Directory_Entry.Parent.Split('/'))[-1]
                    }
                    $Group_Directory_Entry_Parent_OU = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parent_OU_Parameters
                    $Group_Directory_Entry_Parent_OU.Delete('Group', ('CN={0}' -f $Group_Directory_Entry.cn.Value))
                    Write-Verbose ('{0}|Delete successful' -f $Function_Name)
                } catch [System.UnauthorizedAccessException] {
                    $Terminating_ErrorRecord_Parameters = @{
                        'Exception'      = 'System.UnauthorizedAccessException'
                        'ID'             = 'DSS-{0}' -f $Function_Name
                        'Category'       = 'AuthenticationError'
                        'TargetObject'   = $Group_Directory_Entry
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
                'TargetObject' = $Group_Directory_Entry
                'Message'      = 'Cannot find group with {0} of "{1}"' -f $Directory_Search_Type, $Directory_Search_Value
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
