function Get-DSSGroupMemberWrapper {
    <#
    .SYNOPSIS
        A wrapper function to reduce code duplication between Get-DSSGroupMember and Get-DSSPrincipalGroupMembership cmdlets.
    .DESCRIPTION
        This will parse the PSBoundParameters of the calling function and pass the relevant values to Find-DSSRawObject to return the requested properties.

        This is not meant to be used as an interactive function; it is a wrapper function for the Get-DSSGroupMember and Get-DSSPrincipalGroupMembership cmdlets, in order to reduce reuse of code.
    .EXAMPLE
        Get-DSSGroupMemberWrapper -ObjectType 'PrincipalGroupMembership' -BoundParameters $PSBoundParameters

        Finds the group membership of the object specified within the BoundParameters.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # A hashtable of the PSBoundParameters that were passed from the calling function.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $BoundParameters,

        # The type of AD object that has been wrapped.
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'GroupMember',
            'PrincipalGroupMembership'
        )]
        [String]
        $ObjectType,

        # The format of the output.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Hashtable', 'Object')]
        [String]
        $OutputFormat = 'Object'
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        if ($_.Value -is [Hashtable]) {
            Write-Verbose ("{0}|Arguments: {1}:`n{2}" -f $Function_Name, $_.Key, ($_.Value | Format-Table -AutoSize | Out-String).Trim())
        } else {
            Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' '))
        }
    }

    try {
        $Basic_Parameters = @('Credential', 'Server')
        $Common_Parameters = @('Context')

        $Basic_Search_Parameters = @{}
        foreach ($Parameter in $Basic_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Basic Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $BoundParameters[$Parameter])
                $Basic_Search_Parameters[$Parameter] = $BoundParameters[$Parameter]
            }
        }
        $Common_Search_Parameters = $Basic_Search_Parameters.PSBase.Clone()
        foreach ($Parameter in $Common_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Common Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $BoundParameters[$Parameter])
                $Common_Search_Parameters[$Parameter] = $BoundParameters[$Parameter]
            }
        }

        # We need the DistinguishedName to perform the LDAP_MATCHING_RULE_IN_CHAIN search, so if another identity is given, perform a search to retrieve the DistinguishedName.
        if (-not $BoundParameters.ContainsKey('DistinguishedName')) {
            $Identity_Parameters = @('SAMAccountName', 'ObjectSID', 'ObjectGUID')
            foreach ($Parameter in $Identity_Parameters) {
                if ($BoundParameters.ContainsKey($Parameter)) {
                    $DN_Search_Object = $Parameter
                    $DN_Search_Value = $BoundParameters[$Parameter]
                    $DN_Search_LDAPFilter = '({0}={1})' -f $DN_Search_Object, $DN_Search_Value
                }
            }
            $DN_Search_Parameters = @{}
            Write-Verbose ('{0}|DN Search:LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
            $DN_Search_Parameters['LDAPFilter'] = $DN_Search_LDAPFilter

            switch ($ObjectType) {
                'GroupMember' {
                    Write-Verbose ('{0}|DN Search:Calling Find-DSSGroup' -f $Function_Name)
                    $DN_Search_Return = Find-DSSGroup @Common_Search_Parameters @DN_Search_Parameters
                    $DN_Search_Type = 'group'
                }

                'PrincipalGroupMembership' {
                    Write-Verbose ('{0}|DN Search:Calling Find-DSSObject' -f $Function_Name)
                    $DN_Search_Return = Find-DSSObject @Common_Search_Parameters @DN_Search_Parameters
                    $DN_Search_Type = 'account'
                }
            }

            if (-not $DN_Search_Return) {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'    = 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
                    'ID'           = 'DSS-{0}' -f $Function_Name
                    'Category'     = 'ObjectNotFound'
                    'TargetObject' = $DN_Search_Return
                    'Message'      = ('Cannot find {0} with {1}: {2}' -f $DN_Search_Type, $DN_Search_Object, $DN_Search_Value)
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } else {
                $DistinguishedName = $DN_Search_Return.'distinguishedname'
            }
        }

        $Directory_Parameters = @('PageSize', 'Properties')
        $Directory_Search_Parameters = @{}
        foreach ($Parameter in $Directory_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Directory Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $BoundParameters[$Parameter])
                $Directory_Search_Parameters[$Parameter] = $BoundParameters[$Parameter]
            }
        }

        switch ($ObjectType) {
            'GroupMember' {
                if ($BoundParameters.ContainsKey('Recursive')) {
                    $Directory_Search_LDAPFilter = '(memberof:1.2.840.113556.1.4.1941:={0})' -f $DistinguishedName
                } else {
                    $Directory_Search_LDAPFilter = '(memberof={0})' -f $DistinguishedName
                }
            }

            'PrincipalGroupMembership' {
                if ($BoundParameters.ContainsKey('Recursive')) {
                    $Directory_Search_LDAPFilter = '(member:1.2.840.113556.1.4.1941:={0})' -f $DistinguishedName
                } else {
                    $Directory_Search_LDAPFilter = '(member={0})' -f $DistinguishedName
                }
            }
        }

        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSRawObject' -f $Function_Name)
        $Objects_To_Return = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($OutputFormat -eq 'Object') {
            $Objects_To_Return | ConvertTo-SortedPSObject
        } else {
            $Objects_To_Return
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
