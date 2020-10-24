function Find-DSSObjectWrapper {
    <#
    .SYNOPSIS
        A wrapper function to reduce code duplication between Find-DSS cmdlets.
    .DESCRIPTION
        This will parse the PSBoundParameters of the calling function and pass the relevant values to Find-DSSRawObject to search and return the requested properties.

        This is not meant to be used as an interactive function; it is a wrapper function around the Find-DSS cmdlets, in order to reduce reuse of code.
    .EXAMPLE
        Find-DSSObjectWrapper -ObjectType 'User' -BoundParameters $PSBoundParameters

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
        $Common_Parameters = @('Context', 'Credential', 'Server')
        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Common Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $BoundParameters[$Parameter])
                $Common_Search_Parameters[$Parameter] = $BoundParameters[$Parameter]
            }
        }

        # The Default_LDAPFilter should be the fastest method of searching for those types of objects.
        # However certain properties are not available on deleted objects, so the LDAP filter needs to be adjusted in that case.
        switch ($ObjectType) {
            'Computer' {
                $Default_LDAPFilter = '(objectcategory=computer)'
                $Default_LDAPFilter_With_DeletedObjects = '(objectclass=computer)'
            }
            'DomainController' {
                $Default_LDAPFilter = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
            }
            'Group' {
                $Default_LDAPFilter = '(objectcategory=group)'
                $Default_LDAPFilter_With_DeletedObjects = '(objectclass=group)'

                # Add any filtering on GroupScope and/or GroupCategory.
                # See: https://ldapwiki.com/wiki/Active%20Directory%20Group%20Related%20Searches
                if ($BoundParameters.ContainsKey('GroupScope')) {
                    Write-Verbose ('{0}|GroupScope: {1}' -f $Function_Name, $BoundParameters['GroupScope'])
                    $Addtional_LDAPFilter = ('(grouptype:1.2.840.113556.1.4.804:={0})' -f [int]$ADGroupTypes[$BoundParameters['GroupScope']])
                }
                if ($BoundParameters.ContainsKey('GroupCategory')) {
                    Write-Verbose ('{0}|GroupCategory: {1}' -f $Function_Name, $BoundParameters['GroupCategory'])
                    if ($BoundParameters['GroupCategory'] -eq 'Security') {
                        $Addtional_LDAPFilter = $Addtional_LDAPFilter + '(groupType:1.2.840.113556.1.4.803:=2147483648)'
                    } else {
                        $Addtional_LDAPFilter = $Addtional_LDAPFilter + '(!(groupType:1.2.840.113556.1.4.803:=2147483648))'
                    }
                }
                if ($Addtional_LDAPFilter) {
                    $Default_LDAPFilter = '(&{0}{1})' -f $Default_LDAPFilter, $Addtional_LDAPFilter
                }
            }
            'Object' {
                # Find any object with a GUID.
                $Default_LDAPFilter = '(objectguid=*)'
                $Default_LDAPFilter_With_DeletedObjects = '(objectguid=*)'
            }
            'OptionalFeature' {
                $Default_LDAPFilter = '(objectclass=msds-optionalfeature)'
                if (-not $BoundParameters.ContainsKey('SearchBase')) {
                    Write-Verbose ('{0}|Calling Get-DSSRootDSE to get configuration SearchBase' -f $Function_Name)
                    $DSE_Return_Object = Get-DSSRootDSE @Common_Search_Parameters
                    Write-Verbose ('{0}|DSE: Configuration Path: {1}' -f $Function_Name, $DSE_Return_Object.'configurationnamingcontext')
                    $BoundParameters['SearchBase'] = $DSE_Return_Object.'configurationnamingcontext'
                }
            }
            'OrganizationalUnit' {
                $Default_LDAPFilter = '(objectclass=organizationalunit)'
                $Default_LDAPFilter_With_DeletedObjects = '(objectclass=organizationalunit)'
            }
            'User' {
                # SAMAccountType is the fastest method of searching for users - http://www.selfadsi.org/extended-ad/search-user-accounts.htm.
                $Default_LDAPFilter = '(samaccounttype=805306368)'
                $Default_LDAPFilter_With_DeletedObjects = '(objectclass=user)'
            }
        }

        $Directory_Parameters = @('IncludeDeletedObjects', 'PageSize', 'Properties', 'SearchBase', 'SearchScope')
        $Directory_Search_Parameters = @{}
        foreach ($Parameter in $Directory_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Directory Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $BoundParameters[$Parameter])
                $Directory_Search_Parameters[$Parameter] = $BoundParameters[$Parameter]
            }
        }

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
