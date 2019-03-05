function Find-DSSGroup {
    <#
    .SYNOPSIS
        Finds a group object(s) in Active Directory.
    .DESCRIPTION
        Performs an Ambiguous Name Recognition (ANR) search through Active Directory for the supplied group Name, or uses a custom LDAPFilter.
    .EXAMPLE
        Find-DSSGroup "domain admins"

    .EXAMPLE

    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adgroup
        https://social.technet.microsoft.com/wiki/contents/articles/12079.active-directory-get-adgroup-default-and-extended-properties.aspx
    #>

    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param(
        # The name to use in the search.
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        # The LDAP filter to use for the search.
        [Parameter(Mandatory = $true, ParameterSetName = 'LDAPFilter')]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The base OU to start the search from.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        # The scope to search. Must be one of: Base, OneLevel, Subtree.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope,

        # The group scope to search. Must be one of: DomainLocal, Global, Universal.
        [Parameter(Mandatory = $false)]
        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        [String]
        $GroupScope,

        # The group type to search. Must be one of: Security, Distribution.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Security', 'Distribution')]
        [String]
        $GroupType,

        # The properties of any results to return.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        # The number of results per page that is returned from the server. This is primarily to save server memory and bandwidth and does not affect the total number of results returned.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ResultPageSize')]
        [Int]
        $PageSize = 500,

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

    # Default properties as per Get-ADGroup. These properties are always returned, in addition to any specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'groupcategory'
        'groupscope'
        'name'
        'objectclass'
        'objectguid'
        'objectsid'
        'samaccountname'
    )

    # Full list of all properties returned with a wildcard.
    # Due to some constructed properties not being returned when search results include a wildcard, simply replace the wildcard with the full array of properties.
    # See http://www.rlmueller.net/UserAttributes.htm
    [String[]]$Wildcard_Properties = @(
        'canonicalname'
        'cn'
        'description'
        'displayname'
        'dscorepropagationdata'
        'grouptype'
        'info'
        'instancetype'
        'mail'
        'managedby'
        'ntsecuritydescriptor'
        'objectcategory'
        'protectedfromaccidentaldeletion'
        'samaccounttype'
        'sdrightseffective'
        'sidhistory'
        'usnchanged'
        'usncreated'
        'whenchanged'
        'whencreated'
    )

    try {
        $Directory_Search_Parameters = @{
            'Context'  = $Context
            'PageSize' = $PageSize
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            $Directory_Search_Parameters['SearchBase'] = $SearchBase
        }
        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            $Directory_Search_Parameters['SearchScope'] = $SearchScope
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Search_Parameters['Credential'] = $Credential
        }

        $Function_Search_Properties = New-Object -TypeName 'System.Collections.Generic.List[String]'
        if ($PSBoundParameters.ContainsKey('Properties')) {
            Write-Verbose ('{0}|Adding default properties first' -f $Function_Name)
            $Function_Search_Properties.AddRange($Default_Properties)
            if ($Properties -contains '*') {
                Write-Verbose ('{0}|Adding other wildcard properties' -f $Function_Name)
                $Function_Search_Properties.AddRange($Wildcard_Properties)
            }
            foreach ($Property in $Properties) {
                if (($Property -ne '*') -and ($Function_Search_Properties -notcontains $Property)) {
                    Write-Verbose ('{0}|Adding Property: {1}' -f $Function_Name, $Property)
                    $Function_Search_Properties.Add($Property)
                }
            }
        } else {
            Write-Verbose ('{0}|No properties specified, adding default properties only' -f $Function_Name)
            $Function_Search_Properties.AddRange($Default_Properties)
        }
        Write-Verbose ('{0}|Properties: {1}' -f $Function_Name, ($Function_Search_Properties -join ' '))
        $Directory_Search_Parameters['Properties'] = $Function_Search_Properties

        $Default_Group_LDAPFilter = '(objectcategory=group)'

        # Add any filtering on GroupScope and/or GroupType
        # See: https://haczela.wordpress.com/2012/03/07/how-to-search-for-groups-of-different-type-and-scope/
        if ($PSBoundParameters.ContainsKey('GroupScope')) {
            Write-Verbose ('{0}|GroupScope: {1}' -f $Function_Name, $GroupScope)
            if ($GroupScope -eq 'DomainLocal') {
                $Addtional_LDAPFilter = '(grouptype:1.2.840.113556.1.4.804:=4)'
            } elseif ($GroupScope -eq 'Global') {
                $Addtional_LDAPFilter = '(grouptype:1.2.840.113556.1.4.804:=2)'
            } else {
                $Addtional_LDAPFilter = '(grouptype:1.2.840.113556.1.4.804:=8)'
            }
        }
        if ($PSBoundParameters.ContainsKey('GroupType')) {
            Write-Verbose ('{0}|GroupType: {1}' -f $Function_Name, $GroupType)
            if ($GroupType -eq 'Security') {
                $Addtional_LDAPFilter = $Addtional_LDAPFilter + '(|(samaccounttype=268435456)(samaccounttype=536870912))'
            } else {
                $Addtional_LDAPFilter = $Addtional_LDAPFilter + '(|(samaccounttype=268435457)(samaccounttype=536870913))'
            }
        }
        if ($Addtional_LDAPFilter) {
            $Default_Group_LDAPFilter = '(&{0}{1})' -f $Default_Group_LDAPFilter, $Addtional_LDAPFilter
        }

        if ($Name -eq '*') {
            $Directory_Search_LDAPFilter = $Default_Group_LDAPFilter
        } elseif ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_Group_LDAPFilter, $LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_Group_LDAPFilter, $Name
        }

        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding group using Find-DSSObject' -f $Function_Name)
        Find-DSSObject @Directory_Search_Parameters | ConvertTo-SortedPSObject
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
