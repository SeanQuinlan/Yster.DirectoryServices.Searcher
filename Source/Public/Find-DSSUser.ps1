function Find-DSSUser {
    <#
    .SYNOPSIS
        Searches for user objects in Active Directory.
    .DESCRIPTION
        Performs an Ambiguous Name Recognition (ANR) search through Active Directory for users with the supplied Name, or uses a custom LDAPFilter.
    .EXAMPLE
        Find-DSSUser "administrator"

        Finds all the users that match "administrator" on one of the common indexed attributes.
    .EXAMPLE
        Find-DSSUser -LDAPFilter '(samaccountname=test*)' -SearchBase 'CN=Users,DC=contoso,DC=com' -SearchScope 'OneLevel'

        Finds all users that have the samaccountname starting with "test", in the Users container.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-aduser
        https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
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
        # -LDAPFilter '(description=Service Account)'
        # -LDAPFilter '(&(description=Marketing User)(location=London))'
        [Parameter(Mandatory = $true, ParameterSetName = 'LDAPFilter')]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The name to use in the search. The name will be used in an Ambiguous Name Recognition (ANR) search, so it will match on any commonly indexed property.
        # An example of using this property is:
        #
        # -Name 'rsmith'
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
        # -SearchBase 'OU=Users,OU=Company,DC=contoso,DC=com'
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
        # -SearchScope OneLevel
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

    # Default properties as per Get-ADUser. These are always returned, in addition to any specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'enabled'
        'givenname'
        'name'
        'objectclass'
        'objectguid'
        'samaccountname'
        'sid'
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
        'distinguishedname'
        'division'
        'doesnotrequirepreauth'
        'dscorepropagationdata'
        'emailaddress'
        'employeeid'
        'employeenumber'
        'enabled'
        'facsimiletelephonenumber'
        'fax'
        'givenname'
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
        'lastknownparent'
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
        'memberof'
        'mnslogonaccount'
        'mobile'
        'mobilephone'
        'modified'
        'modifytimestamp'
        'msds-allowedtoactonbehalfofotheridentity'
        'msds-assignedauthnpolicy'
        'msds-assignedauthnpolicysilo'
        'msds-lastknownrdn'
        'msds-supportedencryptiontypes'
        'msds-user-account-control-computed'
        'name'
        'ntsecuritydescriptor'
        'o'
        'objectcategory'
        'objectclass'
        'objectguid'
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
        'principalsallowedtodelegatetoaccount'
        'profilepath'
        'protectedfromaccidentaldeletion'
        'pwdlastset'
        'samaccountname'
        'samaccounttype'
        'scriptpath'
        'sdrightseffective'
        'sid'
        'sidhistory'
        'smartcardlogonrequired'
        'sn'
        'st'
        'state'
        'streetaddress'
        'surname'
        'telephonenumber'
        'title'
        'trustedfordelegation'
        'trustedtoauthfordelegation'
        'usedeskeyonly'
        'useraccountcontrol'
        'usercertificate'
        'userprincipalname'
        'userworkstations'
        'usnchanged'
        'usncreated'
        'wwwhomepage'
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
                if ($Function_Search_Properties -notcontains $Property) {
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
        Find-DSSObjectWrapper -ObjectType 'User' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}