function Find-DSSUser {
    <#
    .SYNOPSIS
        Finds a user object(s) in Active Directory.
    .DESCRIPTION
        Performs an Ambiguous Name Recognition (ANR) search through Active Directory for the supplied Name, or uses a custom LDAPFilter.
    .EXAMPLE
        Find-DSSUser "administrator"

        Finds all the users that match "administrator" on one of the common indexed attributes.
    .EXAMPLE
        Find-DSSUser -LDAPFilter '(samaccountname=test*)' -SearchBase 'CN=Users,DC=contoso,DC=com' -SearchScope 'OneLevel'

        Finds all users that have the samaccountname starting with "test", in the Users container or the immediate children of Users.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-aduser
        https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
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

    # Default properties as per Get-ADUser. These are always returned, in addition to any specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'enabled'
        'givenname'
        'name'
        'objectclass'
        'objectguid'
        'sid'
        'samaccountname'
        'surname'
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
        'c'
        'cannotchangepassword'
        'canonicalname'
        'certificates'
        'city'
        'cn'
        'co'
        'codepage'
        'company'
        'compoundidentitysupported'
        'country'
        'countrycode'
        'created'
        'createtimestamp'
        'deleted'
        'department'
        'description'
        'displayname'
        'division'
        'doesnotrequirepreauth'
        'dscorepropagationdata'
        'emailaddress'
        'employeeid'
        'employeenumber'
        'facsimiletelephonenumber'
        'fax'
        'homedirectory'
        'homedirrequired'
        'homedrive'
        'homepage'
        'homephone'
        'initials'
        'instancetype'
        'ipphone'
        'kerberosencryptiontype'
        'l'
        'lastbadpasswordattempt'
        'lastlogoff'
        'lastlogon'
        'lastlogondate'
        'lastlogontimestamp'
        'lockedout'
        'lockouttime'
        'logoncount'
        'logonhours'
        'logonworkstations'
        'mail'
        'manager'
        'mnslogonaccount'
        'mobile'
        'mobilephone'
        'modified'
        'modifytimestamp'
        'msds-allowedtoactonbehalfofotheridentity'
        'msds-assignedauthnpolicy'
        'msds-assignedauthnpolicysilo'
        'msds-supportedencryptiontypes'
        'msds-user-account-control-computed'
        'ntsecuritydescriptor'
        'o'
        'objectcategory'
        'objectsid'
        'office'
        'officephone'
        'organization'
        'otherfacsimiletelephonenumber'
        'otherhomephone'
        'otheripphone'
        'otherloginworkstations'
        'othermailbox'
        'othermobile'
        'otherpager'
        'othertelephone'
        'pager'
        'passwordexpired'
        'passwordlastset'
        'passwordneverexpires'
        'passwordnotrequired'
        'physicaldeliveryofficename'
        'pobox'
        'postalcode'
        'postofficebox'
        'primarygroup'
        'primarygroupid'
        'profilepath'
        'protectedfromaccidentaldeletion'
        'pwdlastset'
        'samaccounttype'
        'scriptpath'
        'sdrightseffective'
        'sidhistory'
        'smartcardlogonrequired'
        'sn'
        'st'
        'state'
        'streetaddress'
        'telephonenumber'
        'title'
        'trustedfordelegation'
        'trustedtoauthfordelegation'
        'usedeskeyonly'
        'useraccountcontrol'
        'usercertificate'
        'userworkstations'
        'usnchanged'
        'usncreated'
        'wwwhomepage'
        'whenchanged'
        'whencreated'

        #todo not yet added
        #'lastknownparent'
        #'memberof'
        #'principalsallowedtodelegatetoaccount'
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

        $Default_User_LDAPFilter = '(samaccounttype=805306368)'     # sAMAccountType is best method to search just user accounts - http://www.selfadsi.org/extended-ad/search-user-accounts.htm
        if ($Name -eq '*') {
            $Directory_Search_LDAPFilter = $Default_User_LDAPFilter
        } elseif ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_User_LDAPFilter, $LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_User_LDAPFilter, $Name
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding users using Find-DSSObject' -f $Function_Name)
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
