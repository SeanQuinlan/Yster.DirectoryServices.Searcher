function Find-DSSObjectWrapper {
    <#
    .SYNOPSIS
        A wrapper function to reduce code duplication between Find-DSS cmdlets.
    .DESCRIPTION
        This will parse the PSBoundParameters of the calling function and pass the relevant values to Find-DSSRawObject to search and return the requested properties.

        This is not meant to be used as an interactive function; it is a wrapper function around the Find-DSS cmdlets, in order to reduce reuse of code.
    .EXAMPLE
        Find-DSSObjectWrapper -ObjectType 'User' -BoundParameters $PSBoundParameters

        Finds the user object specified within the BoundParameters
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
        $ObjectType
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
        switch ($ObjectType) {
            'Computer' {
            }
            'DomainController' {
            }
            'Group' {
            }
            'Object' {
            }
            'OptionalFeature' {
            }
            'OrganizationalUnit' {
            }
            'User' {
                # SAMAccountType is the fastest method of searching for users - http://www.selfadsi.org/extended-ad/search-user-accounts.htm.
                # However this property is not available on groups that have been deleted. So set the filter to use ObjectClass if IncludeDeletedObjects is set to $true.
                $Default_LDAPFilter = '(samaccounttype=805306368)'
                $Default_LDAPFilter_With_DeletedObjects = '(objectclass=user)'
            }
        }

        $Common_Parameters = @('Context', 'Credential', 'IncludeDeletedObjects', 'PageSize', 'Properties', 'SearchBase', 'SearchScope', 'Server')
        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Common Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $BoundParameters[$Parameter])
                $Common_Search_Parameters[$Parameter] = $BoundParameters[$Parameter]
            }
        }

        $Directory_Search_Parameters = @{}
        if ($BoundParameters['IncludeDeletedObjects']) {
            $Directory_Search_LDAPFilter = $Default_LDAPFilter_With_DeletedObjects
        } else {
            $Directory_Search_LDAPFilter = $Default_LDAPFilter
        }
        if ($BoundParameters.ContainsKey('LDAPFilter')) {
            $Directory_Search_Parameters['LDAPFilter'] = '(&{0}{1})' -f $Directory_Search_LDAPFilter, $BoundParameters['LDAPFilter']
        } else {
            if ($BoundParameters['Name'] -eq '*') {
                $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter
            } else {
                $Directory_Search_Parameters['LDAPFilter'] = '(&{0}(ANR={1}))' -f $Directory_Search_LDAPFilter, $BoundParameters['Name']
            }
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_Parameters['LDAPFilter'])

        Write-Verbose ('{0}|Calling Find-DSSRawObject' -f $Function_Name)
        Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters | ConvertTo-SortedPSObject

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}