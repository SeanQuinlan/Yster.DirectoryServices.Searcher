function Remove-DSSObjectWrapper {
    <#
    .SYNOPSIS
        A wrapper function to reduce code duplication for all Remove-DSS cmdlets
    .DESCRIPTION
        This will perform some validation on the incoming parameters.
        If all tests pass, it will call Set-DSSRawObject to actually perform the removal of the object from Active Directory.

        This is not meant to be used as an interactive function; it is a wrapper function around the Set-DSS cmdlets, in order to reduce reuse of code.
    .EXAMPLE
        Remove-DSSObjectWrapper -ObjectType 'User' -BoundParameters $PSBoundParameters

        Removes the user object with the supplied parameters.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # A hashtable of the PSBoundParameters that were passed from the calling function.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $BoundParameters,

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

        # The credential to use for access.
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        # The type of AD object that has been wrapped.
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'Computer',
            'Group',
            'GroupMember',
            'Object',
            'OrganizationalUnit',
            'PrincipalGroupMembership',
            'User'
        )]
        [String]
        $ObjectType,

        # The server to connect to.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        switch ($ObjectType) {
            'Computer' {
                $Default_LDAPFilter = '(objectclass=computer)'
                $Set_Action = 'RemoveObject'
            }
            'Group' {
                $Default_LDAPFilter = '(objectclass=group)'
                $Set_Action = 'RemoveObject'
            }
            'GroupMember' {
                $Default_LDAPFilter = '(objectclass=group)'
                $Set_Action = 'RemoveGroupMember'
            }
            'Object' {
                $Default_LDAPFilter = ''
                $Set_Action = 'RemoveObject'
            }
            'OrganizationalUnit' {
                $Default_LDAPFilter = '(objectclass=organizationalunit)'
                $Set_Action = 'RemoveObject'
            }
            'PrincipalGroupMembership' {
                $Default_LDAPFilter = ''
                $Set_Action = 'RemovePrincipalGroupMembership'
            }
            'User' {
                $Default_LDAPFilter = '(objectclass=user)'
                $Set_Action = 'RemoveObject'
            }
        }

        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
                [void]$BoundParameters.Remove($Parameter)
            }
        }

        $Identity_Parameters = @('SAMAccountName', 'DistinguishedName', 'ObjectSID', 'ObjectGUID')
        foreach ($Parameter in $Identity_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                $Directory_Search_Type = $Parameter
                $Directory_Search_Value = $BoundParameters[$Parameter]
                if (($Directory_Search_Type -eq 'SAMAccountName') -and ($Directory_Search_Value -match '\*')) {
                    $Terminating_ErrorRecord_Parameters = @{
                        'Exception'    = 'System.ArgumentException'
                        'ID'           = 'DSS-{0}' -f $Function_Name
                        'Category'     = 'SyntaxError'
                        'TargetObject' = $Directory_Search_Type
                        'Message'      = 'SAMAccountName cannot include wildcards'
                    }
                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                } else {
                    $LDAPFilter = '(&{0}({1}={2}))' -f $Default_LDAPFilter, $Directory_Search_Type, $Directory_Search_Value
                    [void]$BoundParameters.Remove($Parameter)
                }
            }
        }
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        $Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            $Set_Parameters = @{
                'Action' = $Set_Action
                'Object' = $Object_Directory_Entry
            }
            Write-Verbose ('{0}|Calling Set-DSSRawObject' -f $Function_Name)
            Set-DSSRawObject @$Common_Search_Parameters @Set_Parameters @BoundParameters
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Entry
                'Message'      = 'Cannot find {0} with {1} of "{2}"' -f $ObjectType, $Directory_Search_Type, $Directory_Search_Value
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
