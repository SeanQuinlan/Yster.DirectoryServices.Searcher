function Find-DSSOrganizationalUnit {
    <#
    .SYNOPSIS
        Finds an Organizational Unit (OU) in Active Directory.
    .DESCRIPTION

    .EXAMPLE
        Find-DSSOrganizationalUnit -Name "Sales"

        Finds all the OUs that match "Sales".
    .EXAMPLE
        Find-DSSOrganizationalUnit -LDAPFilter '(name=UK*)' -Properties *

        Finds all the OUs that have a "name" starting with "UK", and return all properties for each result.
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
        [ValidateSet('Base','OneLevel','Subtree')]
        [String]
        $SearchScope,

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
        [ValidateSet('Domain','Forest')]
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
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name,$_.Key,($_.Value -join ' ')) }

    try {
        $Directory_Search_Parameters = @{
            'Context'   = $Context
            'PageSize'  = $PageSize
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            $Directory_Search_Parameters.SearchBase = $SearchBase
        }
        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            $Directory_Search_Parameters.SearchScope = $SearchScope
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Search_Parameters.Server = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Search_Parameters.Credential = $Credential
        }

        # Default properties as per Get-ADOrganizationalUnit. Used when no Properties is specified.
        [String[]]$Default_Properties = @(
            'c'
            'country'
            'distinguishedname'
            'l'
            'linkedgrouppolicyobjects'
            'managedby'
            'name'
            'objectclass'
            'objectguid'
            'postalcode'
            'st'
            'street'
        )
        # Full list of all properties returned with a wildcard.
        # Due to some constructed properties not being returned when search results include a wildcard, simply replace the wildcard with the full array of properties.
        [String[]]$Wildcard_Properties = @(
            'canonicalname'
            'cn'
            'co'
            'countrycode'
            'description'
            'displayname'
            'instancetype'
            'ntsecuritydescriptor'
            'objectcategory'
            'ou'
            'postalcode'
            'protectedfromaccidentaldeletion'
            'sdrightseffective'
            'usnchanged'
            'usncreated'
            'whenchanged'
            'whencreated'
        )

        $Directory_Search_Properties = New-Object -TypeName 'System.Collections.Generic.List[String]'
        if ($PSBoundParameters.ContainsKey('Properties')) {
            Write-Verbose ('{0}|Adding default properties first' -f $Function_Name)
            $Directory_Search_Properties.AddRange($Default_Properties)
            if ($Properties -contains '*') {
                $Directory_Search_Properties.Add('*')
                Write-Verbose ('{0}|Adding other wildcard properties' -f $Function_Name)
                $Directory_Search_Properties.AddRange($Wildcard_Properties)
            }
            foreach ($Property in $Properties) {
                if (($Property -ne '*') -and ($Directory_Search_Properties -notcontains $Property)) {
                    Write-Verbose ('{0}|Adding Property: {1}' -f $Function_Name,$Property)
                    $Directory_Search_Properties.Add($Property)
                }
            }
        } else {
            Write-Verbose ('{0}|No properties specified, adding default properties only' -f $Function_Name)
            $Directory_Search_Properties.AddRange($Default_Properties)
        }
        Write-Verbose ('{0}|Properties: {1}' -f $Function_Name,($Directory_Search_Properties -join ' '))
        $Directory_Search_Parameters.Properties = $Directory_Search_Properties

        $Default_OU_LDAPFilter = '(objectclass=organizationalUnit)'
        if ($Name -eq '*') {
            $Directory_Search_LDAPFilter = $Default_OU_LDAPFilter
        } elseif ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_OU_LDAPFilter,$LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_OU_LDAPFilter,$Name
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name,$Directory_Search_LDAPFilter)
        $Directory_Search_Parameters.LDAPFilter = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding OUs using Find-DSSObject' -f $Function_Name)
        Find-DSSObject @Directory_Search_Parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}