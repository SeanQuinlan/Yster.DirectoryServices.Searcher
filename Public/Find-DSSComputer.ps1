function Find-DSSComputer {
    <#
    .SYNOPSIS
        Finds a computer object(s) in Active Directory.
    .DESCRIPTION
        Performs an Ambiguous Name Recognition (ANR) search through Active Directory for the supplied Name, or uses a custom LDAPFilter.
    .EXAMPLE
        Find-DSSComputer -Name 'srv'

        Finds all the computers that match "srv" on one of the commonly indexed attributes. Wildcard is not required.
    .EXAMPLE
        Find-DSSComputer -LDAPFilter '(name=appserver*)' -SearchBase 'DC=Mkt_Servers,DC=contoso,DC=com' -SearchScope 'OneLevel'

        Finds all computers that have a name starting with "appserver", in the "Mkt_Servers" OU or the immediate children of that OU.
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

    try {
        $Directory_Search_Parameters = @{
            'Context'  = $Context
            'PageSize' = $PageSize
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

        # Default properties as per Get-ADComputer. These are always returned, in addition to any specified in the Properties parameter.
        [String[]]$Default_Properties = @(
            'distinguishedname'
            'dnshostname'
            'enabled'
            'name'
            'objectclass'
            'objectguid'
            'objectsid'
            'samaccountname'
            'userprincipalname'
        )
        # Full list of all properties returned with a wildcard.
        # Due to some constructed properties not being returned when search results include a wildcard, simply replace the wildcard with the full array of properties.
        # See http://www.rlmueller.net/UserAttributes.htm
        [String[]]$Wildcard_Properties = @(
            'accountexpirationdate'
            'accountexpires'
            'accountlockouttime'
            'accountnotdelegated'
            'allowreversiblepasswordencryption'
            'badpasswordtime'
            'badpwdcount'
            'cannotchangepassword'
            'canonicalname'
            'certificates'
            'codepage'
            'compoundidentitysupported'
            'countrycode'
            'cn'
            'description'
            'displayname'
            'doesnotrequirepreauth'
            'dscorepropagationdata'
            'homedirrequired'
            'instancetype'
            'ipv4address'
            'ipv6address'
            'iscriticalsystemobject'
            'kerberosencryptiontype'
            'lastbadpasswordattempt'
            'lastknownparent'
            'lastlogoff'
            'lastlogon'
            'lastlogondate'
            'lastlogontimestamp'
            'localpolicyflags'
            'location'
            'lockedout'
            'lockouttime'
            'logoncount'
            'managedby'
            'memberof'
            'msdfsr-computerreferencebl'
            'msds-generationid'
            'msds-supportedencryptiontypes'
            'msds-user-account-control-computed'
            'mnslogonaccount'
            'ntsecuritydescriptor'
            'objectcategory'
            'operatingsystem'
            'operatingsystemhotfix'
            'operatingsystemservicepack'
            'operatingsystemversion'
            'passwordexpired'
            'passwordlastset'
            'passwordneverexpires'
            'passwordnotrequired'
            'principalsallowedtodelegatetoaccount'
            'primarygroup'
            'primarygroupid'
            'protectedfromaccidentaldeletion'
            'pwdlastset'
            'ridsetreferences'
            'samaccounttype'
            'sdrightseffective'
            'serverreferencebl'
            'serviceprincipalname'
            'sidhistory'
            'trustedfordelegation'
            'trustedtoauthfordelegation'
            'usedeskeyonly'
            'useraccountcontrol'
            'usnchanged'
            'usncreated'
            'whenchanged'
            'whencreated'
            'wwwhomepage'
        )

        [String[]]$Wildcard_Properties_Not_Yet_Added = @(
            'authenticationpolicy'
            'authenticationpolicysilo'
            'deleted'
            'isdeleted'
            'serviceaccount'
        )

        [String[]]$Microsoft_Alias_Properties = @(
            'badlogoncount'
            'created'
            'createtimestamp'
            'homepage'
            'modified'
            'modifytimestamp'
            'serviceprincipalnames'
            'sid'
            'usercertificate'
        )

        $Directory_Search_Properties = New-Object -TypeName 'System.Collections.Generic.List[String]'
        if ($PSBoundParameters.ContainsKey('Properties')) {
            Write-Verbose ('{0}|Adding default properties first' -f $Function_Name)
            $Directory_Search_Properties.AddRange($Default_Properties)
            if ($Properties -contains '*') {
                Write-Verbose ('{0}|Adding other wildcard properties' -f $Function_Name)
                $Directory_Search_Properties.AddRange($Wildcard_Properties)
            }
            foreach ($Property in $Properties) {
                if (($Property -ne '*') -and ($Directory_Search_Properties -notcontains $Property)) {
                    Write-Verbose ('{0}|Adding Property: {1}' -f $Function_Name, $Property)
                    $Directory_Search_Properties.Add($Property)
                }
            }
        } else {
            Write-Verbose ('{0}|No properties specified, adding default properties only' -f $Function_Name)
            $Directory_Search_Properties.AddRange($Default_Properties)
        }
        Write-Verbose ('{0}|Properties: {1}' -f $Function_Name, ($Directory_Search_Properties -join ' '))
        $Directory_Search_Parameters.Properties = $Directory_Search_Properties

        $Default_Computer_LDAPFilter = '(objectcategory=computer)'
        if ($Name -eq '*') {
            $Directory_Search_LDAPFilter = $Default_Computer_LDAPFilter
        } elseif ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_Computer_LDAPFilter, $LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_Computer_LDAPFilter, $Name
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters.LDAPFilter = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding computers using Find-DSSObject' -f $Function_Name)
        $Computer_Results_To_Return = Find-DSSObject @Directory_Search_Parameters

        # Useful post here: https://www.myotherpcisacloud.com/post/IPv4Address-Attribute-In-Get-ADComputer
        $Non_LDAP_Network_Properties = @('ipv4address', 'ipv6address')
        $Non_LDAP_Network_Properties_To_Process = $Directory_Search_Properties | Where-Object { $Non_LDAP_Network_Properties -contains $_ }

        if ($Non_LDAP_Network_Properties_To_Process) {
            # Try and get the IP address(es) from DNS or just return null if any error.
            try {
                $Host_IP_Addresses = [System.Net.Dns]::GetHostEntry($Computer_Results_To_Return.'dnshostname').AddressList
            } catch {
                $Host_IP_Addresses = $null
            }
            foreach ($Non_LDAP_Network_Property in $Non_LDAP_Network_Properties_To_Process) {
                $Non_LDAP_Network_Property_AddressList = $null
                if ($Non_LDAP_Network_Property -eq 'ipv4address') {
                    $Non_LDAP_Network_Property_AddressList = ($Host_IP_Addresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' }).IPAddressToString
                } elseif ($Non_LDAP_Network_Property -eq 'ipv6address') {
                    $Non_LDAP_Network_Property_AddressList = ($Host_IP_Addresses | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' }).IPAddressToString
                }
                $Non_LDAP_Network_Property_To_Add = New-Object -TypeName 'System.Management.Automation.PSNoteProperty' -ArgumentList @($Non_LDAP_Network_Property, $Non_LDAP_Network_Property_AddressList)
                $Computer_Results_To_Return.PSObject.Properties.Add($Non_LDAP_Network_Property_To_Add)
            }
        }

        # Return the full computer object after sorting.
        ConvertTo-SortedPSObject -InputObject $Computer_Results_To_Return
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
