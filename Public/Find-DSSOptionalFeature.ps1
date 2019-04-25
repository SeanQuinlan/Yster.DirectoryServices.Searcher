function Find-DSSOptionalFeature {
    <#
    .SYNOPSIS
        Finds an optional feature in Active Directory.
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
            $DSE_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
            Write-Verbose ('{0}|Calling Get-DSSRootDSE' -f $Function_Name)
            $DSE_Return_Object = Get-DSSRootDSE @DSE_Search_Parameters
            $SearchBase = $DSE_Return_Object.'configurationnamingcontext'
            Write-Verbose ('{0}|DSE: Configuration Path: {1}' -f $Function_Name, $SearchBase)
        }

        $Directory_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
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
            $Directory_Search_LDAPFilter = $Default_LDAPFilter
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding optional features using Find-DSSRawObject' -f $Function_Name)
        $Results_To_Return = Find-DSSRawObject @Directory_Search_Parameters

        if ($Results_To_Return) {
            foreach ($Result_To_Return in $Results_To_Return) {
                if ($Function_Search_Properties -contains 'enabledscopes') {
                    Write-Verbose ('{0}|EnabledScopes: Searching for EnabledScopes for: {1}' -f $Function_Name, $Result_To_Return['name'])
                    $EnabledScopes_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                    $EnabledScopes_Search_Parameters['Context'] = $Context
                    $EnabledScopes_Search_Parameters['PageSize'] = $PageSize
                    $EnabledScopes_Search_Parameters['SearchBase'] = $SearchBase
                    $EnabledScopes_Search_Parameters['Properties'] = @('distinguishedname')
                    $EnabledScopes_Search_Parameters['LDAPFilter'] = '(msds-enabledfeature={0})' -f $Result_To_Return['distinguishedname']

                    Write-Verbose ('{0}|EnabledScopes: Calling Find-DSSRawObject' -f $Function_Name)
                    $EnabledScopes_Search_Results = Find-DSSRawObject @EnabledScopes_Search_Parameters

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
