function Find-DSSDomainController {
    <#
    .SYNOPSIS
        Finds a domain controller object(s) in Active Directory.
    .DESCRIPTION
        Performs an search for domain controller objects in Active Directory, using the Name or a custom LDAPFilter.
    .EXAMPLE
        Find-DSSDomainController -Name *

        Finds all domain controllers for the current domain.
    .EXAMPLE

    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-addomaincontroller
        http://www.selfadsi.org/extended-ad/search-domain-controllers.htm
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

    # A small number of default properties. These are always returned, in addition to any specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'enabled'
        'name'
        'site'
    )

    # Full list of all properties returned with a wildcard. Taken from Get-ADDomainController output.
    # Due to some constructed properties not being returned when search results include a wildcard, simply replace the wildcard with the full array of properties.
    [String[]]$Wildcard_Properties = @(
        'defaultpartition'
        'invocationid'
        'ipv4address'
        'ipv6address'
        'isglobalcatalog'
        'isreadonly'
        'ntdssettingsobjectdn'
        'operatingsystem'
        'operatingsystemhotfix'
        'operatingsystemservicepack'
        'operatingsystemversion'
        'partitions'
        'primarygroupid'
        'serverobjectdn'
        'serverobjectguid'
    )

    [String[]]$Wildcard_Properties_Not_Yet_Added = @(
        'domain'
        'forest'
        'ldapport'
        'operationmasterroles'
        'sslport'
    )

    [String[]]$Microsoft_Alias_Properties = @(
        'computerobjectdn' # distinguishedname
        'hostname' # dnshostname
    )

    # These are the properties that will be returned from a call to Get-DSSComputer.
    $Computer_Properties = @(
        'distinguishedname'
        'enabled'
        'ipv4address'
        'ipv6address'
        'name'
        'operatingsystem'
        'operatingsystemhotfix'
        'operatingsystemservicepack'
        'operatingsystemversion'
        'primarygroupid'
    )

    $Partition_Properties = @(
        'invocationid'
        'isglobalcatalog'
        'ntdssettingsobjectdn'
        'serverobjectdn'
        'serverobjectguid'
        'site'
    )

    try {
        $Common_Search_Parameters = @{}
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
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

        $Computer_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
        $Computer_Search_Parameters['Context'] = $Context
        $Computer_Search_Parameters['PageSize'] = $PageSize
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            $Computer_Search_Parameters['SearchBase'] = $SearchBase
        }
        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            $Computer_Search_Parameters['SearchScope'] = $SearchScope
        }
        $Directory_Search_Properties = $Function_Search_Properties | Where-Object { $Computer_Properties -contains $_ }
        $Computer_Search_Parameters['Properties'] = $Directory_Search_Properties

        $Default_Computer_LDAPFilter = '(&(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        if ($Name -eq '*') {
            $Directory_Search_LDAPFilter = $Default_Computer_LDAPFilter
        } elseif ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_Computer_LDAPFilter, $LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_Computer_LDAPFilter, $Name
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Computer_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding domain controllers using Find-DSSComputer' -f $Function_Name)
        $DomainController_Results = Find-DSSComputer @Computer_Search_Parameters

        if ($DomainController_Results) {
            $Partition_Properties_To_Process = $Function_Search_Properties | Where-Object { $Partition_Properties -contains $_ }
            if ($Partition_Properties_To_Process) {
                Write-Verbose ('{0}|Calculating DSE properties' -f $Function_Name)
                $DSE_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                Write-Verbose ('{0}|Calling Get-DSSRootDSE' -f $Function_Name)
                $DSE_Return_Object = Get-DSSRootDSE @DSE_Search_Parameters
                $Sites_Path = 'CN=Sites,{0}' -f $DSE_Return_Object.'configurationnamingcontext'
                Write-Verbose ('{0}|DSE: Sites_Path: {1}' -f $Function_Name, $Partitions_Path)

                $Site_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                $Site_Search_Parameters['Context'] = $Context
                $Site_Search_Parameters['PageSize'] = $PageSize
                $Site_Search_Parameters['SearchBase'] = $Sites_Path
                $Site_Search_Parameters['LDAPFilter'] = '(|(objectclass=site)(objectclass=server)(objectclass=ntdsdsa))'
                $Site_Search_Parameters['Properties'] = @('cn', 'distinguishedname', 'objectclass', 'objectguid', 'options', 'serverreference')

                Write-Verbose ('{0}|Sites: Calling Find-DSSObject' -f $Function_Name)
                $Site_Results = Find-DSSObject @Site_Search_Parameters
            }

            foreach ($DomainController_Result in $DomainController_Results) {
                if ($Partition_Properties_To_Process) {
                    $Server_Object = $Site_Results | Where-Object { $_.'ServerReference' -eq $DomainController_Result.'distinguishedname' }
                    $NTDS_Settings = $Site_Results | Where-Object { ($_.'objectclass' -contains 'ntdsdsa') -and ($_.'distinguishedname' -match $Server_Object.'distinguishedname') }

                    # Add any properties gathered from the Partitions object.
                    foreach ($Partition_Property in $Partition_Properties_To_Process) {
                        switch ($Partition_Property) {
                            'invocationid' {
                                $Partition_Property_To_Add_Arguments = @($Partition_Property, $NTDS_Settings.'objectguid')
                            }
                            'isglobalcatalog' {
                                $NTDS_Options_Flags = [Enum]::Parse('NTDSDSAOption', $NTDS_Settings.'options')
                                if ($NTDS_Options_Flags -match 'IS_GC') {
                                    $Partition_Property_To_Add_Arguments = @($Partition_Property, $true)
                                } else {
                                    $Partition_Property_To_Add_Arguments = @($Partition_Property, $false)
                                }
                            }
                            'ntdssettingsobjectdn' {
                                $Partition_Property_To_Add_Arguments = @($Partition_Property, $NTDS_Settings.'distinguishedname')
                            }
                            'serverobjectdn' {
                                $Partition_Property_To_Add_Arguments = @($Partition_Property, $Server_Object.'distinguishedname')
                            }
                            'serverobjectguid' {
                                $Partition_Property_To_Add_Arguments = @($Partition_Property, $Server_Object.'objectguid')
                            }
                            'site' {
                                $Current_Site = $Site_Results | Where-Object { ($_.'objectclass' -contains 'site') -and ($Server_Object -match $_.'distinguishedname') }
                                $Partition_Property_To_Add_Arguments = @($Partition_Property, $Current_Site.cn)
                            }
                        }

                        $Partition_Property_To_Add = New-Object -TypeName 'System.Management.Automation.PSNoteProperty' -ArgumentList $Partition_Property_To_Add_Arguments
                        Write-Verbose ('{0}|Partition: Adding Property: {1} = {2}' -f $Function_Name, $Partition_Property_To_Add_Arguments[0], $Partition_Property_To_Add_Arguments[1])
                        $DomainController_Result.PSObject.Properties.Add($Partition_Property_To_Add)
                    }
                }

                $Other_Properties = $Function_Search_Properties | Where-Object { ($Computer_Properties -notcontains $_) -and ($Partition_Properties -notcontains $_) }
                foreach ($Other_Property in $Other_Properties) {
                    switch -Regex ($Other_Property) {
                        'isreadonly' {
                            if ($DomainController_Result.'primarygroupid' -eq 521) {
                                $Other_Property_To_Add_Arguments = @($Other_Property, $true)
                            } else {
                                $Other_Property_To_Add_Arguments = @($Other_Property, $false)
                            }
                        }
                        'defaultpartition|partitions' {
                            $DSE_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                            $DSE_Search_Parameters['Server'] = $DomainController_Result.'dnshostname'
                            Write-Verbose ('{0}|Calling Get-DSSRootDSE on server: {1}' -f $Function_Name, $DSE_Search_Parameters['Server'])
                            $DSE_Return_Object = Get-DSSRootDSE @DSE_Search_Parameters
                            if ($Other_Property -eq 'defaultpartition') {
                                $Other_Property_To_Add_Arguments = @($Other_Property, $DSE_Return_Object.'defaultnamingcontext')
                            } elseif ($Other_Property -eq 'partitions') {
                                $Other_Property_To_Add_Arguments = @($Other_Property, $DSE_Return_Object.'namingcontexts')
                            }
                        }
                    }

                    $Other_Property_To_Add = New-Object -TypeName 'System.Management.Automation.PSNoteProperty' -ArgumentList $Other_Property_To_Add_Arguments
                    Write-Verbose ('{0}|Other: Adding Property: {1} = {2}' -f $Function_Name, $Other_Property_To_Add_Arguments[0], $Other_Property_To_Add_Arguments[1])
                    $DomainController_Result.PSObject.Properties.Add($Other_Property_To_Add)
                }
            }

            # Return the full computer object after sorting.
            ConvertTo-SortedPSObject -InputObject $DomainController_Results
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

# From: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ebf2419-1169-4413-88e2-12a5ad499cf5
Add-Type -TypeDefinition @"
    [System.Flags]
    public enum NTDSDSAOption {
        IS_GC                    = 0x01,
        DISABLE_INBOUND_REPL     = 0x02,
        DISABLE_OUTBOUND_REPL    = 0x04,
        DISABLE_NTDSCONN_XLATE   = 0x08,
        DISABLE_SPN_REGISTRATION = 0x10
    }
"@
