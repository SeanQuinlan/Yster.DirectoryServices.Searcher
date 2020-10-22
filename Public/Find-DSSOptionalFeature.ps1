function Find-DSSOptionalFeature {
    <#
    .SYNOPSIS
        Searches for optional features in Active Directory.
    .DESCRIPTION
        Performs a search within Active Directory for the optional feature with the supplied Name, or uses a custom LDAPFilter.
    .EXAMPLE
        Find-DSSOptionalFeature "Recycle Bin Feature"

        Finds the "Recycle Bin Feature" of Active Directory.
    .EXAMPLE
        Find-DSSOptionalFeature -Name *

        Finds all optional features within Active Directory.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adoptionalfeature
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
        # -LDAPFilter '(&(objectclass=Computer)(description=ESXi Server)(location=London))'
        [Parameter(Mandatory = $true, ParameterSetName = 'LDAPFilter')]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The name to use in the search. The name will be used in an Ambiguous Name Recognition (ANR) search, so it will match on any commonly indexed property.
        # An example of using this property is:
        #
        # -Name 'Recycle Bin'
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

    # Default properties as per Get-ADOptionalFeature. These are always returned, in addition to any specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'enabledscopes'
        'featurescope'
        'isdisableable'
        'featureguid'
        'name'
        'objectclass'
        'objectguid'
        'requireddomainmode'
        'requiredforestmode'
    )

    # Full list of all properties returned with a wildcard.
    # Due to some constructed properties not being returned when search results include a wildcard, simply replace the wildcard with the full array of properties.
    [String[]]$Wildcard_Properties = @(
        'canonicalname'
        'cn'
        'created'
        'createtimestamp'
        'deleted'
        'description'
        'displayname'
        'dscorepropagationdata'
        'instancetype'
        'isdeleted'
        'lastknownparent'
        'modified'
        'modifytimestamp'
        'msds-optionalfeatureflags'
        'msds-optionalfeatureguid'
        'msds-requireddomainbehaviorversion'
        'msds-requiredforestbehaviorversion'
        'ntsecuritydescriptor'
        'objectcategory'
        'protectedfromaccidentaldeletion'
        'sdrightseffective'
        'showinadvancedviewonly'
        'systemflags'
        'usnchanged'
        'usncreated'
        'whenchanged'
        'whencreated'
    )

    try {
        $Common_Search_Parameters = @{}
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
        }
        if (-not $PSBoundParameters.ContainsKey('SearchBase')) {
            Write-Verbose ('{0}|Calling Get-DSSRootDSE' -f $Function_Name)
            $DSE_Return_Object = Get-DSSRootDSE @Common_Search_Parameters
            $SearchBase = $DSE_Return_Object.'configurationnamingcontext'
            Write-Verbose ('{0}|DSE: Configuration Path: {1}' -f $Function_Name, $SearchBase)
        }

        $Directory_Search_Parameters = @{}
        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            $Directory_Search_Parameters['SearchScope'] = $SearchScope
        }
        $Directory_Search_Parameters['Context'] = $Context
        $Directory_Search_Parameters['PageSize'] = $PageSize
        $Directory_Search_Parameters['SearchBase'] = $SearchBase

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

        $Default_LDAPFilter = '(objectclass=msds-optionalfeature)'
        if ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_LDAPFilter, $LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(name={1}))' -f $Default_LDAPFilter, $Name
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding optional features using Find-DSSRawObject' -f $Function_Name)
        $Results_To_Return = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters

        if ($Results_To_Return) {
            foreach ($Result_To_Return in $Results_To_Return) {
                if ($Function_Search_Properties -contains 'enabledscopes') {
                    Write-Verbose ('{0}|EnabledScopes: Searching for EnabledScopes for: {1}' -f $Function_Name, $Result_To_Return['name'])
                    $EnabledScopes_Search_Parameters = @{}
                    $EnabledScopes_Search_Parameters['Context'] = $Context
                    $EnabledScopes_Search_Parameters['PageSize'] = $PageSize
                    $EnabledScopes_Search_Parameters['SearchBase'] = $SearchBase
                    $EnabledScopes_Search_Parameters['Properties'] = @('distinguishedname')
                    $EnabledScopes_Search_Parameters['LDAPFilter'] = '(msds-enabledfeature={0})' -f $Result_To_Return['distinguishedname']

                    Write-Verbose ('{0}|EnabledScopes: Calling Find-DSSRawObject' -f $Function_Name)
                    $EnabledScopes_Search_Results = Find-DSSRawObject @Common_Search_Parameters @EnabledScopes_Search_Parameters

                    if ($EnabledScopes_Search_Results) {
                        $EnabledScopes_Property = 'enabledscopes'
                        $EnabledScopes_Property_Value = $EnabledScopes_Search_Results.'distinguishedname'
                        Write-Verbose ('{0}|EnabledScopes: Adding Property: {1} = {2}' -f $Function_Name, $EnabledScopes_Property, $EnabledScopes_Property_Value)
                        $Result_To_Return[$EnabledScopes_Property] = $EnabledScopes_Property_Value
                    }
                }

                if ($Function_Search_Properties -contains 'isdisableable') {
                    # This is $false for both available Optional Features and I can't find out how it's derived, so just statically assign it here.
                    $Result_To_Return['isdisableable'] = $false
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
