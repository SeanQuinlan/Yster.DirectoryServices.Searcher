function Find-DSSUser {
    <#
    .SYNOPSIS
        Finds a user object(s) in Active Directory.
    .DESCRIPTION
        Long description
    .EXAMPLE
        Example of how to use this script
    .EXAMPLE
        Another example of how to use this script
    #>

    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param(
        # The name to use in the search.
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        # An LDAP filter to use for the search.
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
            'Context' = $Context
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

        # Default properties as per Get-ADUser
        $Default_Properties = @(
            'distinguishedname'
            'enabled'
            'givenname'
            'name'
            'objectclass'
            'objectguid'
            'samaccountname'
            'sid'
            'sn'
            'userprincipalname'
        )
        if ($Properties -eq '*') {
            $Directory_Search_Parameters.Properties = '*'
        } else {
            $Directory_Search_Properties = New-Object -TypeName 'System.Collections.ArrayList'
            [void]$Directory_Search_Properties.AddRange($Default_Properties)
            foreach ($Property in $Properties) {
                if ($Directory_Search_Properties -notcontains $Property) {
                    [void]$Directory_Search_Properties.Add($Property)
                }
            }
            $Directory_Search_Parameters.Properties = $Directory_Search_Properties
        }

        $Default_User_LDAPFilter = '(sAMAccountType=805306368)'     # sAMAccountType is best method to search just user accounts - http://www.selfadsi.org/extended-ad/search-user-accounts.htm
        if ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_User_LDAPFilter,$LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_User_LDAPFilter,$Name
        }
        $Directory_Search_Parameters.LDAPFilter = $Directory_Search_LDAPFilter

        Find-DSSObject @Directory_Search_Parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}