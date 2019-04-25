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
        'dnshostname'
        'enabled'
        'name'
        'site'
    )

    # Full list of all properties returned with a wildcard. Taken from Get-ADDomainController output.
    # Due to some constructed properties not being returned when search results include a wildcard, simply replace the wildcard with the full array of properties.
    [String[]]$Wildcard_Properties = @(
        'computerobjectdn'
        'defaultpartition'
        'hostname'
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
        'operationmasterroles'
        'partitions'
        'primarygroupid'
        'serverobjectdn'
        'serverobjectguid'

        #todo not yet added
        #'domain'
        #'forest'
        #'ldapport'
        #'sslport'
    )

    # These are the properties that will be returned from a call to Get-DSSComputer.
    $Computer_Properties = @(
        'distinguishedname'
        'dnshostname'
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
        'operationmasterroles'
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

        $Directory_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
        $Directory_Search_Parameters['Context'] = $Context
        $Directory_Search_Parameters['PageSize'] = $PageSize
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            $Directory_Search_Parameters['SearchBase'] = $SearchBase
        }
        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            $Directory_Search_Parameters['SearchScope'] = $SearchScope
        }
        $Directory_Search_Properties = $Function_Search_Properties | Where-Object { $Computer_Properties -contains $_ }
        $Directory_Search_Parameters['Properties'] = $Directory_Search_Properties

        $Default_DomainController_LDAPFilter = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        if ($Name -eq '*') {
            $Directory_Search_LDAPFilter = $Default_DomainController_LDAPFilter
        } elseif ($LDAPFilter) {
            $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_DomainController_LDAPFilter, $LDAPFilter
        } else {
            $Directory_Search_LDAPFilter = '(&{0}(ANR={1}))' -f $Default_DomainController_LDAPFilter, $Name
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Finding domain controllers using Find-DSSRawObject' -f $Function_Name)
        $Results_To_Return = Find-DSSRawObject @Directory_Search_Parameters

        if ($Results_To_Return) {
            $Partition_Properties_To_Process = $Function_Search_Properties | Where-Object { $Partition_Properties -contains $_ }
            $Other_Properties_To_Process = $Function_Search_Properties | Where-Object { ($Computer_Properties -notcontains $_) -and ($Partition_Properties -notcontains $_) }
            if ($Partition_Properties_To_Process) {
                Write-Verbose ('{0}|Calculating DSE properties' -f $Function_Name)
                $DSE_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                Write-Verbose ('{0}|Calling Get-DSSRootDSE' -f $Function_Name)
                $DSE_Return_Object = Get-DSSRootDSE @DSE_Search_Parameters
                $Sites_Path = 'CN=Sites,{0}' -f $DSE_Return_Object.'configurationnamingcontext'
                Write-Verbose ('{0}|DSE: Sites_Path: {1}' -f $Function_Name, $Sites_Path)

                $Site_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                $Site_Search_Parameters['Context'] = $Context
                $Site_Search_Parameters['PageSize'] = $PageSize
                $Site_Search_Parameters['SearchBase'] = $Sites_Path
                $Site_Search_Parameters['LDAPFilter'] = '(|(objectclass=site)(objectclass=server)(objectclass=ntdsdsa))'
                $Site_Search_Parameters['Properties'] = @('cn', 'distinguishedname', 'objectclass', 'objectguid', 'options', 'serverreference')

                Write-Verbose ('{0}|Sites: Calling Find-DSSRawObject' -f $Function_Name)
                $Site_Results = Find-DSSRawObject @Site_Search_Parameters
            }

            if ($Function_Search_Properties -contains 'operationmasterroles') {
                Write-Verbose ('{0}|Getting operationmasterroles' -f $Function_Name)
                # Domain roles - Infrastructure Master, PDC Emulator, RID Master
                $FSMO_Domain_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                $FSMO_Domain_Search_Parameters['Context'] = $Context
                $FSMO_Domain_Search_Parameters['PageSize'] = $PageSize
                $FSMO_Domain_Search_Parameters['SearchBase'] = $DSE_Return_Object.'defaultnamingcontext'
                $FSMO_Domain_Search_Parameters['LDAPFilter'] = '(fsmoroleowner=*)'
                $FSMO_Domain_Search_Parameters['Properties'] = @('fsmoroleowner', 'objectclass')
                Write-Verbose ('{0}|FSMO_Domain: Calling Find-DSSRawObject' -f $Function_Name)
                $FSMO_Domain_Results = Find-DSSRawObject @FSMO_Domain_Search_Parameters

                # Forest Domain Naming Master
                $FSMO_Forest_DomainNaming_Search_Parameters = $FSMO_Domain_Search_Parameters.PSObject.Copy()
                $FSMO_Forest_DomainNaming_Search_Parameters['SearchBase'] = $DSE_Return_Object.'configurationnamingcontext'
                Write-Verbose ('{0}|FSMO_Forest_DomainNaming: Calling Find-DSSRawObject' -f $Function_Name)
                $FSMO_Forest_DomainNaming_Results = Find-DSSRawObject @FSMO_Forest_DomainNaming_Search_Parameters

                # Forest Schema Master
                $FSMO_Forest_Schema_Search_Parameters = $FSMO_Domain_Search_Parameters.PSObject.Copy()
                $FSMO_Forest_Schema_Search_Parameters['SearchBase'] = $DSE_Return_Object.'schemanamingcontext'
                Write-Verbose ('{0}|FSMO_Forest_Schema: Calling Find-DSSRawObject' -f $Function_Name)
                $FSMO_Forest_Schema_Search_Results = Find-DSSRawObject @FSMO_Forest_Schema_Search_Parameters

                $OperationsMaster_Roles = @{}
                $OperationsMaster_Roles['InfrastructureMaster'] = ($FSMO_Domain_Results | Where-Object { $_.'objectclass' -eq 'infrastructureupdate' }).'fsmoroleowner'
                $OperationsMaster_Roles['PDCEmulator'] = ($FSMO_Domain_Results | Where-Object { $_.'objectclass' -eq 'domain' }).'fsmoroleowner'
                $OperationsMaster_Roles['RIDMaster'] = ($FSMO_Domain_Results | Where-Object { $_.'objectclass' -eq 'ridmanager' }).'fsmoroleowner'
                $OperationsMaster_Roles['DomainNamingMaster'] = $FSMO_Forest_DomainNaming_Results.'fsmoroleowner'
                $OperationsMaster_Roles['SchemaMaster'] = $FSMO_Forest_Schema_Search_Results.'fsmoroleowner'
            }

            foreach ($Result_To_Return in $Results_To_Return) {
                if ($Partition_Properties_To_Process) {
                    $Server_Object = $Site_Results | Where-Object { $_['ServerReference'] -eq $Result_To_Return['distinguishedname'] }
                    $NTDS_Settings = $Site_Results | Where-Object { ($_['objectclass'] -contains 'ntdsdsa') -and ($_['distinguishedname'] -match $Server_Object['distinguishedname']) }

                    # Add any properties gathered from the Partitions object.
                    foreach ($Partition_Property in $Partition_Properties_To_Process) {
                        switch ($Partition_Property) {
                            'invocationid' {
                                $Partition_Property_Value = $NTDS_Settings['objectguid']
                            }
                            'isglobalcatalog' {
                                $NTDS_Options_Flags = [Enum]::Parse('NTDSDSAOption', $NTDS_Settings['options'])
                                if ($NTDS_Options_Flags -match 'IS_GC') {
                                    $Partition_Property_Value = $true
                                } else {
                                    $Partition_Property_Value = $false
                                }
                            }
                            'ntdssettingsobjectdn' {
                                $Partition_Property_Value = $NTDS_Settings['distinguishedname']
                            }
                            'serverobjectdn' {
                                $Partition_Property_Value = $Server_Object['distinguishedname']
                            }
                            'serverobjectguid' {
                                $Partition_Property_Value = $Server_Object['objectguid']
                            }
                            'site' {
                                $Current_Site = $Site_Results | Where-Object { ($_['objectclass'] -contains 'site') -and ($Server_Object['distinguishedname'] -match $_['distinguishedname']) }
                                $Partition_Property_Value = $Current_Site['cn']
                            }
                        }

                        Write-Verbose ('{0}|Partition: Adding Property: {1} = {2}' -f $Function_Name, $Partition_Property, $Partition_Property_Value)
                        $Result_To_Return[$Partition_Property] = $Partition_Property_Value
                    }
                }

                if ($Function_Search_Properties -contains 'operationmasterroles') {
                    $Server_OperationsMaster_Roles = New-Object -TypeName 'System.Collections.Generic.List[String]'
                    $OperationsMaster_Roles.GetEnumerator() | ForEach-Object {
                        if ($_.Value -match $Results_To_Return['serverobjectdn']) {
                            $Server_OperationsMaster_Roles.Add($_.Name)
                        }
                    }
                    if ($OperationsMaster_Roles) {
                        Write-Verbose ('{0}|OperationMasterRoles: Adding Property: {1} = {2}' -f $Function_Name, 'operationmasterroles', ($Server_OperationsMaster_Roles -join ','))
                        $Result_To_Return['operationmasterroles'] = $Server_OperationsMaster_Roles
                    }
                }

                foreach ($Other_Property in $Other_Properties_To_Process) {
                    switch -Regex ($Other_Property) {
                        'isreadonly' {
                            # 521 is the group ID for "Read-only Domain Controllers"
                            if ($Result_To_Return['primarygroupid'] -eq 521) {
                                $Other_Property_Value = $true
                            } else {
                                $Other_Property_Value = $false
                            }
                        }
                        'defaultpartition|partitions' {
                            $DSE_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                            $DSE_Search_Parameters['Server'] = $Result_To_Return['dnshostname']
                            Write-Verbose ('{0}|Calling Get-DSSRootDSE on server: {1}' -f $Function_Name, $DSE_Search_Parameters['Server'])
                            $DSE_Return_Object = Get-DSSRootDSE @DSE_Search_Parameters
                            if ($Other_Property -eq 'defaultpartition') {
                                $Other_Property_Value = $DSE_Return_Object.'defaultnamingcontext'
                            } elseif ($Other_Property -eq 'partitions') {
                                $Other_Property_Value = $DSE_Return_Object.'namingcontexts'
                            }
                        }
                    }

                    Write-Verbose ('{0}|Other: Adding Property: {1} = {2}' -f $Function_Name, $Other_Property, $Other_Property_Value)
                    $Result_To_Return[$Other_Property] = $Other_Property_Value
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
