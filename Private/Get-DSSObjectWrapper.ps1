function Get-DSSObjectWrapper {
    <#
    .SYNOPSIS
        A wrapper function to reduce code duplication between Get-DSS cmdlets.
    .DESCRIPTION
        This will parse the PSBoundParameters of the calling function and pass the relevant values to an appropriate Find-DSSxxx cmdlet to search and return the requested properties.

        This is not meant to be used as an interactive function; it is a wrapper function around the Get-DSS cmdlets, in order to reduce reuse of code.
    .EXAMPLE
        Get-DSSObjectWrapper -ObjectType 'User' -BoundParameters $PSBoundParameters

        Finds the user object specified within the BoundParameters.
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
            'DomainController',
            'Group',
            'Object',
            'OptionalFeature',
            'OrganizationalUnit',
            'User'
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
        # $Common_Parameters = @('Context', 'Credential', 'Server')
        # $Common_Search_Parameters = @{}
        # foreach ($Parameter in $Common_Parameters) {
        #     if ($BoundParameters.ContainsKey($Parameter)) {
        #         Write-Verbose ('{0}|Adding Common Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $BoundParameters[$Parameter])
        #         $Common_Search_Parameters[$Parameter] = $BoundParameters[$Parameter]
        #     }
        # }

        $Identity_Parameters = @('SAMAccountName', 'DistinguishedName', 'ObjectSID', 'ObjectGUID')
        foreach ($Parameter in $Identity_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                $Directory_Search_Type = $Parameter
                $Directory_Search_Value = $BoundParameters[$Parameter]
                if ($Parameter -eq 'objectguid') {
                    $Directory_Search_Value = Convert-GuidToHex -Guid $Directory_Search_Value
                }
                $LDAPFilter = '(&{0}({1}={2}))' -f $Default_LDAPFilter, $Directory_Search_Type, $Directory_Search_Value
                [void]$BoundParameters.Remove($Parameter)
            }
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $LDAPFilter)
        $BoundParameters['LDAPFilter'] = $LDAPFilter

        switch ($ObjectType) {
            'Computer' {
                Write-Verbose ('{0}|Calling Find-DSSComputer' -f $Function_Name)
                Find-DSSComputer @BoundParameters
            }
            'OrganizationalUnit' {
                Write-Verbose ('{0}|Calling Find-DSSOrganizationalUnit' -f $Function_Name)
                Find-DSSOrganizationalUnit @BoundParameters
            }
            'User' {
                Write-Verbose ('{0}|Calling Find-DSSUser' -f $Function_Name)
                Find-DSSUser @BoundParameters
            }
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
