function Find-DSSComputer {
    <#
    .SYNOPSIS
        Searches for computer objects in Active Directory.
    .DESCRIPTION
        Performs an Ambiguous Name Recognition (ANR) search through Active Directory for the supplied Name, or uses a custom LDAPFilter.
    .EXAMPLE
        Find-DSSComputer -Name 'srv'

        Finds all the computers that match "srv" on one of the commonly indexed attributes. Wildcard is not required.
    .EXAMPLE
        Find-DSSComputer -LDAPFilter '(name=appserver*)' -SearchBase 'OU=Mkt_Servers,DC=contoso,DC=com' -SearchScope 'OneLevel'

        Finds all computers that have a name starting with "appserver", in the "Mkt_Servers" OU or the immediate children of that OU.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adcomputer
        https://social.technet.microsoft.com/wiki/contents/articles/12056.active-directory-get-adcomputer-default-and-extended-properties.aspx
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
        # -LDAPFilter '(description=Marketing Server)'
        # -LDAPFilter '(&(description=ESXi Server)(location=London))'
        [Parameter(Mandatory = $true, ParameterSetName = 'LDAPFilter')]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The name to use in the search. The name will be used in an Ambiguous Name Recognition (ANR) search, so it will match on any commonly indexed property.
        # An example of using this property is:
        #
        # -Name 'srv01'
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

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
        # ..Base will search only in the OU/Container specified and will not look through child OUs.
        # ..OneLevel will search in the OU/Container specified, and the immediate child OUs.
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

    # Default properties as per Get-ADComputer. These are always returned, in addition to any specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'dnshostname'
        'enabled'
        'name'
        'objectclass'
        'objectguid'
        'sid'
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
        'authenticationpolicy'
        'authenticationpolicysilo'
        'badlogoncount'
        'badpasswordtime'
        'badpwdcount'
        'cannotchangepassword'
        'canonicalname'
        'certificates'
        'codepage'
        'compoundidentitysupported'
        'countrycode'
        'created'
        'createtimestamp'
        'cn'
        'deleted'
        'description'
        'displayname'
        'doesnotrequirepreauth'
        'dscorepropagationdata'
        'homedirrequired'
        'homepage'
        'instancetype'
        'ipv4address'
        'ipv6address'
        'iscriticalsystemobject'
        'isdeleted'
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
        'modified'
        'modifytimestamp'
        'msdfsr-computerreferencebl'
        'msds-assignedauthnpolicy'
        'msds-assignedauthnpolicysilo'
        'msds-generationid'
        'msds-lastknownrdn'
        'msds-supportedencryptiontypes'
        'msds-user-account-control-computed'
        'mnslogonaccount'
        'ntsecuritydescriptor'
        'objectcategory'
        'objectsid'
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
        'serviceaccount'
        'serviceprincipalname'
        'serviceprincipalnames'
        'sidhistory'
        'trustedfordelegation'
        'trustedtoauthfordelegation'
        'usedeskeyonly'
        'useraccountcontrol'
        'usercertificate'
        'usnchanged'
        'usncreated'
        'whenchanged'
        'whencreated'
        'wwwhomepage'
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

        # ObjectCategory is the fastest method of searching for computer objects.
        # However this property is not available on objects that have been deleted. So set the filter to use ObjectClass instead, if $IncludeDeletedObjects is set to $true.
        if ($IncludeDeletedObjects) {
            $Default_Computer_LDAPFilter = '(objectclass=computer)'
        } else {
            $Default_Computer_LDAPFilter = '(objectcategory=computer)'
        }

        if ($Name -eq '*') {
            $Directory_Search_LDAPFilter = $Default_Computer_LDAPFilter
        } elseif ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_Computer_LDAPFilter, $LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_Computer_LDAPFilter, $Name
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding computers using Find-DSSRawObject' -f $Function_Name)
        $Results_To_Return = Find-DSSRawObject @Directory_Search_Parameters

        if ($Results_To_Return) {
            # Useful post here: https://www.myotherpcisacloud.com/post/IPv4Address-Attribute-In-Get-ADComputer
            $Non_LDAP_Network_Properties = @('ipv4address', 'ipv6address')
            $Non_LDAP_Network_Properties_To_Process = $Function_Search_Properties | Where-Object { $Non_LDAP_Network_Properties -contains $_ }

            if ($Non_LDAP_Network_Properties_To_Process) {
                foreach ($Result_To_Return in $Results_To_Return) {
                    # Try and get the IP address(es) from DNS or just return null if any error.
                    try {
                        $Host_IP_Addresses = [System.Net.Dns]::GetHostEntry($Result_To_Return['dnshostname']).AddressList
                    } catch {
                        $Host_IP_Addresses = $null
                    }
                    foreach ($Non_LDAP_Network_Property in $Non_LDAP_Network_Properties_To_Process) {
                        $Non_LDAP_Network_Property_AddressList = $null
                        if ($Non_LDAP_Network_Property -eq 'ipv4address') {
                            $Non_LDAP_Network_Property_AddressList = ($Host_IP_Addresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' }).'IPAddressToString'
                        } elseif ($Non_LDAP_Network_Property -eq 'ipv6address') {
                            $Non_LDAP_Network_Property_AddressList = ($Host_IP_Addresses | Where-Object { ($_.AddressFamily -eq 'InterNetworkV6') -and (-not $_.IsIPv6LinkLocal) -and (-not $_.IsIPv6SiteLocal) }).'IPAddressToString'
                        }

                        Write-Verbose ('{0}|Non_LDAP: Adding Property: {1} = {2}' -f $Function_Name, $Non_LDAP_Network_Property, $Non_LDAP_Network_Property_AddressList)
                        $Result_To_Return[$Non_LDAP_Network_Property] = $Non_LDAP_Network_Property_AddressList
                    }
                }
            }

            $Results_To_Return | ConvertTo-SortedPSObject
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
