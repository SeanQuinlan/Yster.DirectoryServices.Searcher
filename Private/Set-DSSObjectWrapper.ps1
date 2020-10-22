function Set-DSSObjectWrapper {
    <#
    .SYNOPSIS
        A wrapper function to check any Set-DSS cmdlet for valid parameters and then perform the modification to Active Directory.
    .DESCRIPTION
        This will check through the PSBoundParameters of the calling function and confirm their validity and that the referenced object to modify exists.
        If all tests pass, it will call Set-DSSRawObject to actually perform the modification of the property or properties in Active Directory.

        This is not meant to be used as an interactive function; it is a wrapper function around the Set-DSS cmdlets, in order to reduce reuse of code.
    .EXAMPLE
        Set-DSSObjectWrapper -ObjectType 'User' -BoundParameters $PSBoundParameters

        Sets the user object with the supplied parameters.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # A hashtable of the PSBoundParameters that were passed from the calling function.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $BoundParameters,

        # The type of AD object that has been wrapped.
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'Computer',
            'Group',
            'Object',
            'OrganizationalUnit',
            'User'
        )]
        [String]
        $ObjectType
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        switch ($ObjectType) {
            'Computer' {
                $Default_LDAPFilter = '(objectclass=computer)'
            }
            'Group' {
                $Default_LDAPFilter = '(objectclass=group)'
            }
            'Object' {
                $Default_LDAPFilter = ''
            }
            'OrganizationalUnit' {
                $Default_LDAPFilter = '(objectclass=organizationalunit)'
            }
            'User' {
                $Default_LDAPFilter = '(objectclass=user)'
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
                $LDAPFilter = '(&{0}({1}={2}))' -f $Default_LDAPFilter, $Directory_Search_Type, $Directory_Search_Value
                [void]$BoundParameters.Remove($Parameter)
            }
        }
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        $Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            $Set_Parameters = Confirm-DSSObjectParameters -BoundParameters $BoundParameters -Type 'Set'

            if ($Set_Parameters.Count) {
                $Set_Parameters['Action'] = 'Set'
                $Set_Parameters['Object'] = $Object_Directory_Entry
                Write-Verbose ('{0}|Calling Set-DSSRawObject' -f $Function_Name)
                Set-DSSRawObject @$Common_Search_Parameters @Set_Parameters
            } else {
                Write-Verbose ('{0}|No Set parameters provided, so doing nothing' -f $Function_Name)
            }
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
