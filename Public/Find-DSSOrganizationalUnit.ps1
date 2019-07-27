function Find-DSSOrganizationalUnit {
    <#
    .SYNOPSIS
        Searches for Organizational Units (OU) in Active Directory.
    .DESCRIPTION
        Performs an LDAP search for all Organizational Units that match the Name or LDAPFilter supplied properties.
    .EXAMPLE
        Find-DSSOrganizationalUnit -Name "Sales"

        Finds all the OUs that match "Sales".
    .EXAMPLE
        Find-DSSOrganizationalUnit -LDAPFilter '(name=UK*)' -SearchBase 'OU=RootOU,DC=root,DC=lab' -Properties *

        Finds all the OUs that have a "name" starting with "UK", under the above OU, and return all properties for each result.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adorganizationalunit
        https://social.technet.microsoft.com/wiki/contents/articles/12089.active-directory-get-adorganizationalunit-default-and-extended-properties.aspx
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

        # Whether to return deleted objects in the search results.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $IncludeDeletedObjects,

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

    # Default properties as per Get-ADOrganizationalUnit. Used when no Properties is specified.
    [String[]]$Default_Properties = @(
        'city'
        'country'
        'distinguishedname'
        'linkedgrouppolicyobjects'
        'managedby'
        'name'
        'objectclass'
        'objectguid'
        'postalcode'
        'state'
        'streetaddress'
    )

    # Full list of all properties returned with a wildcard.
    # Due to some constructed properties not being returned when search results include a wildcard, simply replace the wildcard with the full array of properties.
    [String[]]$Wildcard_Properties = @(
        'c'
        'canonicalname'
        'cn'
        'co'
        'countrycode'
        'created'
        'createtimestamp'
        'deleted'
        'description'
        'displayname'
        'dscorepropagationdata'
        'instancetype'
        'isdeleted'
        'l'
        'lastknownparent'
        'modified'
        'modifytimestamp'
        'msds-lastknownrdn'
        'ntsecuritydescriptor'
        'objectcategory'
        'ou'
        'protectedfromaccidentaldeletion'
        'sdrightseffective'
        'st'
        'street'
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
        if ($PSBoundParameters.ContainsKey('IncludeDeletedObjects')) {
            $Directory_Search_Parameters['IncludeDeletedObjects'] = $true
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
                $Function_Search_Properties.Add('*')
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

        $Default_OU_LDAPFilter = '(objectclass=organizationalunit)'
        if ($Name -eq '*') {
            $Directory_Search_LDAPFilter = $Default_OU_LDAPFilter
        } elseif ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_OU_LDAPFilter, $LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_OU_LDAPFilter, $Name
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding OUs using Find-DSSRawObject' -f $Function_Name)
        Find-DSSRawObject @Directory_Search_Parameters | ConvertTo-SortedPSObject
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
