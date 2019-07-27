function Get-DSSPrincipalGroupMembership {
    <#
    .SYNOPSIS
        Returns all the groups that an account is a member of.
    .DESCRIPTION
        Queries Active Directory for the direct group membership a specific account, based on one of the following specified parameters:
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName
    .EXAMPLE
        Get-DSSPrincipalGroupMembership -ObjectSID 'S-1-5-21-3515480276-2049723633-1306762111-1103'

        Returns all the groups that the account with the above SID is a direct member of.
    .EXAMPLE
        Get-DSSPrincipalGroupMembership -SAMAccountName 'Administrator'

        Returns all the groups that the Administrator account is a member of.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adprincipalgroupmembership
        https://social.technet.microsoft.com/Forums/ie/en-US/f238d2b0-a1d7-48e8-8a60-542e7ccfa2e8/recursive-retrieval-of-all-ad-group-memberships-of-a-user?forum=ITCG
        https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
    #>

    [CmdletBinding(DefaultParameterSetName = 'SAM')]
    param(
        # The SAMAccountName of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM', Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'SAM')]
        [String]
        $SAMAccountName,

        # The DistinguishedName of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # Perform a recursive search for all groups.
        [Parameter(Mandatory = $false)]
        [Alias('Recurse')]
        [Switch]
        $Recursive,

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

    # Default properties when none are specified. Otherwise the specified properties override these.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'groupcategory'
        'groupscope'
        'name'
        'objectclass'
        'objectguid'
        'samaccountname'
        'sid'
    )

    try {
        $Common_Search_Parameters = @{
            'Context'  = $Context
            'PageSize' = $PageSize
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
        }

        # We need the DistinguishedName to perform the LDAP_MATCHING_RULE_IN_CHAIN search, so if another identity is given, perform a search to retrieve the DistinguishedName
        if (-not $PSBoundParameters.ContainsKey('DistinguishedName')) {
            $DN_Search_Parameters = @{}
            if ($PSBoundParameters.ContainsKey('ObjectSID')) {
                $DN_Search_Object = $ObjectSID
                $DN_Search_LDAPFilter = '(objectsid={0})' -f $ObjectSID
            } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
                $DN_Search_Object = $ObjectGUID
                $DN_Search_LDAPFilter = '(objectguid={0})' -f (Convert-GuidToHex -Guid $ObjectGUID)
            } elseif ($PSBoundParameters.ContainsKey('SAMAccountName')) {
                $DN_Search_Object = $SAMAccountName
                $DN_Search_LDAPFilter = '(samaccountname={0})' -f $SAMAccountName
            }
            Write-Verbose ('{0}|DN Search:LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
            $DN_Search_Parameters['LDAPFilter'] = $DN_Search_LDAPFilter

            Write-Verbose ('{0}|DN Search:Calling Find-DSSObject' -f $Function_Name)
            $DN_Search_Return = Find-DSSObject @Common_Search_Parameters @DN_Search_Parameters
            if (-not $DN_Search_Return) {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'    = 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
                    'ID'           = 'DSS-{0}' -f $Function_Name
                    'Category'     = 'ObjectNotFound'
                    'TargetObject' = $DN_Search_Return
                    'Message'      = ('Cannot find account with identity: {0}' -f $DN_Search_Object)
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } else {
                $DistinguishedName = $DN_Search_Return.'distinguishedname'
            }
        }

        $Directory_Search_Parameters = @{}
        if ($PSBoundParameters.ContainsKey('Properties')) {
            $Directory_Search_Parameters['Properties'] = $Properties
        } else {
            $Directory_Search_Parameters['Properties'] = $Default_Properties
        }
        if ($PSBoundParameters.ContainsKey('Recursive')) {
            $Directory_Search_LDAPFilter = '(member:1.2.840.113556.1.4.1941:={0})' -f $DistinguishedName
        } else {
            $Directory_Search_LDAPFilter = '(member={0})' -f $DistinguishedName
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSRawObject' -f $Function_Name)
        Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters | ConvertTo-SortedPSObject
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
