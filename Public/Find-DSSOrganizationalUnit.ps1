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
        Find-DSSOrganizationalUnit -LDAPFilter '(name=UK*)' -SearchBase 'OU=RootOU,DC=contoso,DC=com' -Properties *

        Finds all the OUs that have a "name" starting with "UK", under the above OU, and return all properties for each result.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adorganizationalunit
        https://social.technet.microsoft.com/wiki/contents/articles/12089.active-directory-get-adorganizationalunit-default-and-extended-properties.aspx
    #>

    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param(
        # The directory context to search - Domain or Forest. By default this will search within the domain only.
        # If you want to search the entire directory, specify "Forest" for this parameter and the search will be performed on a Global Catalog server, targetting the entire forest.
        # An example of using this property is:
        #
        # -Context 'Forest'
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

        # The credential to use for access to perform the required action.
        # This credential can be provided in the form of a username, DOMAIN\username or as a PowerShell credential object.
        # In the case of a username or DOMAIN\username, you will be prompted to supply the password.
        # Some examples of using this property are:
        #
        # -Credential jsmith
        # -Credential 'CONTOSO\jsmith'
        #
        # $Creds = Get-Credential
        # -Credential $Creds
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        # Whether to return deleted objects in the search results.
        # An example of using this property is:
        #
        # -IncludeDeletedObjects
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $IncludeDeletedObjects,

        # The LDAP filter to use for the search. Use this option to specify a more targetted LDAP query.
        # Some examples of using this property are:
        #
        # -LDAPFilter '(description=Marketing Users)'
        # -LDAPFilter '(&(description=ESXi Servers)(location=London))'
        [Parameter(Mandatory = $true, ParameterSetName = 'LDAPFilter')]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The name to use in the search. The name will be used in an Ambiguous Name Recognition (ANR) search, so it will match on any commonly indexed property.
        # An example of using this property is:
        #
        # -Name 'Service Accounts'
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        # Whether or not to include default properties. By setting this switch, only the explicitly specified properties will be returned.
        [Parameter(Mandatory = $false)]
        [Switch]
        $NoDefaultProperties,

        # The number of results per page that is returned from the server. This is primarily to save server memory and bandwidth and does not affect the total number of results returned.
        # An example of using this property is:
        #
        # -PageSize 250
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ResultPageSize')]
        [Int]
        $PageSize = 500,

        # The properties of any results to return.
        # Some examples of using this property are:
        #
        # -Properties 'mail'
        # -Properties 'created','enabled','displayname'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Property')]
        [String[]]
        $Properties,

        # The base OU to start the search from. If no base is provided, the search will start at the Active Directory root.
        # An example of using this property is:
        #
        # -SearchBase 'OU=Computers,OU=Company,DC=contoso,DC=com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        # The scope to search. Must be one of: Base, OneLevel, Subtree.
        #
        # ..Base will search within the given DistinguishedName. This is only used to verify the base exists. Mostly useless.
        # ..OneLevel will search only in the OU/Container specified and will not look through child OUs.
        # ..Subtree will search in the OU/Container specified and will recursively search through all child OUs.
        #
        # If no SearchScope is provided, the default is Subtree.
        # An example of using this property is:
        #
        # -SearchScope Base
        [Parameter(Mandatory = $false)]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope,

        # The server or domain to connect to.
        # See below for some examples:
        #
        # -Server DC01
        # -Server 'dc01.contoso.com'
        # -Server CONTOSO
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server
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
        'city'
        'cn'
        'co'
        'country'
        'countrycode'
        'created'
        'createtimestamp'
        'deleted'
        'description'
        'displayname'
        'distinguishedname'
        'dscorepropagationdata'
        'instancetype'
        'isdeleted'
        'l'
        'lastknownparent'
        'linkedgrouppolicyobjects'
        'managedby'
        'modified'
        'modifytimestamp'
        'msds-lastknownrdn'
        'name'
        'ntsecuritydescriptor'
        'objectcategory'
        'objectclass'
        'objectguid'
        'ou'
        'postalcode'
        'protectedfromaccidentaldeletion'
        'sdrightseffective'
        'st'
        'state'
        'street'
        'streetaddress'
        'usnchanged'
        'usncreated'
        'whenchanged'
        'whencreated'
    )

    try {
        $Function_Search_Properties = New-Object -TypeName 'System.Collections.Generic.List[String]'
        if ($PSBoundParameters.ContainsKey('Properties')) {
            if ($Properties -contains '*') {
                Write-Verbose ('{0}|Adding wildcard properties' -f $Function_Name)
                $Function_Search_Properties.AddRange($Wildcard_Properties)
            } elseif (-not $NoDefaultProperties) {
                Write-Verbose ('{0}|Adding default properties first' -f $Function_Name)
                $Function_Search_Properties.AddRange($Default_Properties)
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
        $PSBoundParameters['Properties'] = $Function_Search_Properties

        Write-Verbose ('{0}|Calling Find-DSSObjectWrapper' -f $Function_Name)
        Find-DSSObjectWrapper -ObjectType 'OrganizationalUnit' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
