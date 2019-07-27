function Find-DSSDomainController {
    <#
    .SYNOPSIS
        Searches for domain controller objects in Active Directory.
    .DESCRIPTION
        Performs a search for domain controller objects in Active Directory, using the Name or a custom LDAPFilter.
    .EXAMPLE
        Find-DSSDomainController -Name 'dc'

        Finds all domain controllers that have "dc" in their name.
    .EXAMPLE
        Find-DSSDomainController -Name * -Context forest

        Finds all domain controllers in the current forest.
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
        'domain'
        'forest'
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
    )

    # These are the computer object properties that will returned.
    $Computer_Properties = @(
        'computerobjectdn'
        'distinguishedname'
        'dnshostname'
        'enabled'
        'hostname'
        'name'
        'operatingsystem'
        'operatingsystemhotfix'
        'operatingsystemservicepack'
        'operatingsystemversion'
        'primarygroupid'
    )

    # These are properties gathered from the Partitions object in Active Directory.
    $Partition_Properties = @(
        'invocationid'
        'isglobalcatalog'
        'ntdssettingsobjectdn'
        'operationmasterroles'
        'serverobjectdn'
        'serverobjectguid'
        'site'
    )

    # Returned from a query to the domain/forest.
    $Domain_Properties = @(
        'domain'
        'forest'
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

        $Directory_Search_Parameters = @{}
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
        $Results_To_Return = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters

        if ($Results_To_Return) {
            $Partition_Properties_To_Process = $Function_Search_Properties | Where-Object { $Partition_Properties -contains $_ }
            $Domain_Properties_To_Process = $Function_Search_Properties | Where-Object { $Domain_Properties -contains $_ }
            $OperationsMaster_Roles_Domain = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
            $Other_Properties_To_Process = $Function_Search_Properties | Where-Object { ($Computer_Properties -notcontains $_) -and ($Partition_Properties -notcontains $_) -and ($Domain_Properties -notcontains $_) }

            if ($Partition_Properties_To_Process) {
                Write-Verbose ('{0}|Sites: Calculating DSE properties' -f $Function_Name)
                Write-Verbose ('{0}|Sites: Calling Get-DSSRootDSE' -f $Function_Name)
                $DSE_Return_Object = Get-DSSRootDSE @Common_Search_Parameters
                $Sites_Path = 'CN=Sites,{0}' -f $DSE_Return_Object.'configurationnamingcontext'
                Write-Verbose ('{0}|Sites: Sites_Path: {1}' -f $Function_Name, $Sites_Path)

                $Site_Search_Parameters = @{}
                # Some of the below properties are not held within the global catalog, so we have to look these up using a domain query.
                $Site_Search_Parameters['Context'] = 'Domain'
                $Site_Search_Parameters['PageSize'] = $PageSize
                $Site_Search_Parameters['SearchBase'] = $Sites_Path
                $Site_Search_Parameters['LDAPFilter'] = '(|(objectclass=site)(objectclass=server)(objectclass=ntdsdsa))'
                $Site_Search_Parameters['Properties'] = @(
                    'cn'
                    'distinguishedname'
                    'invocationid'
                    'objectclass'
                    'objectguid'
                    'options'
                    'serverreference'
                )

                Write-Verbose ('{0}|Sites: Calling Find-DSSRawObject' -f $Function_Name)
                $Site_Results = Find-DSSRawObject @Common_Search_Parameters @Site_Search_Parameters
            }

            foreach ($Result_To_Return in $Results_To_Return) {
                if ($Partition_Properties_To_Process) {
                    $Server_Object = $Site_Results | Where-Object { $_['ServerReference'] -eq $Result_To_Return['distinguishedname'] }
                    $NTDS_Settings = $Site_Results | Where-Object { ($_['objectclass'] -contains 'ntdsdsa') -and ($_['distinguishedname'] -match $Server_Object['distinguishedname']) }

                    # Add any properties gathered from the Partitions object.
                    foreach ($Partition_Property in $Partition_Properties_To_Process) {
                        switch ($Partition_Property) {
                            'invocationid' {
                                $Partition_Property_Value = $NTDS_Settings['invocationid']
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

                if (($Domain_Properties_To_Process) -or ($Function_Search_Properties -contains 'operationmasterroles')) {
                    $Domain_Search_Parameters = @{}
                    $Domain_Search_Parameters['Properties'] = @('dnsroot', 'forest')
                    $Domain_Search_Parameters['DistinguishedName'] = $Result_To_Return['distinguishedname'] -replace '.*,OU=Domain Controllers,'
                    Write-Verbose ('{0}|Domain: Calling Get-DSSDomain for: {1}' -f $Function_Name, $Result_To_Return['distinguishedname'])
                    $Domain_Result = Get-DSSDomain @Common_Search_Parameters @Domain_Search_Parameters

                    foreach ($Domain_Property in $Domain_Properties_To_Process) {
                        if ($Domain_Property -eq 'domain') {
                            $Domain_Property_Value = $Domain_Result.'dnsroot'
                        } elseif ($Domain_Property -eq 'forest') {
                            $Domain_Property_Value = $Domain_Result.'forest'
                        }
                        Write-Verbose ('{0}|Domain: Adding Property: {1} = {2}' -f $Function_Name, $Domain_Property, $Domain_Property_Value)
                        $Result_To_Return[$Domain_Property] = $Domain_Property_Value
                    }

                    if ($Function_Search_Properties -contains 'operationmasterroles') {
                        if (-not $OperationsMaster_Roles_Forest) {
                            Write-Verbose ('{0}|FSMO: Getting operationmasterroles for Forest: {1}' -f $Function_Name, $Result_To_Return['forest'])

                            # Forest Domain Naming Master
                            $FSMO_Forest_DomainNaming_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                            $FSMO_Forest_DomainNaming_Search_Parameters['Context'] = 'Domain'
                            $FSMO_Forest_DomainNaming_Search_Parameters['Server'] = $Result_To_Return['forest']
                            $FSMO_Forest_DomainNaming_Search_Parameters['PageSize'] = $PageSize
                            $FSMO_Forest_DomainNaming_Search_Parameters['SearchBase'] = $DSE_Return_Object.'configurationnamingcontext'
                            $FSMO_Forest_DomainNaming_Search_Parameters['LDAPFilter'] = '(fsmoroleowner=*)'
                            $FSMO_Forest_DomainNaming_Search_Parameters['Properties'] = @('fsmoroleowner')
                            Write-Verbose ('{0}|FSMO_Forest_DomainNaming: Calling Find-DSSRawObject' -f $Function_Name)
                            $FSMO_Forest_DomainNaming_Results = Find-DSSRawObject @FSMO_Forest_DomainNaming_Search_Parameters

                            # Forest Schema Master
                            $FSMO_Forest_Schema_Search_Parameters = $FSMO_Forest_DomainNaming_Search_Parameters.PSObject.Copy()
                            $FSMO_Forest_Schema_Search_Parameters['SearchBase'] = $DSE_Return_Object.'schemanamingcontext'
                            Write-Verbose ('{0}|FSMO_Forest_Schema: Calling Find-DSSRawObject' -f $Function_Name)
                            $FSMO_Forest_Schema_Search_Results = Find-DSSRawObject @FSMO_Forest_Schema_Search_Parameters

                            $OperationsMaster_Roles_Forest_Properties = @{
                                'DomainNamingMaster' = $FSMO_Forest_DomainNaming_Results.'fsmoroleowner'
                                'SchemaMaster'       = $FSMO_Forest_Schema_Search_Results.'fsmoroleowner'
                            }
                            $OperationsMaster_Roles_Forest = New-Object -TypeName 'System.Management.Automation.PSObject' -Property $OperationsMaster_Roles_Forest_Properties
                        }

                        $OperationsMaster_Roles_CurrentDomain = $OperationsMaster_Roles_Domain | Where-Object { $_.'Domain' -eq $Result_To_Return['domain'] }
                        if (-not $OperationsMaster_Roles_CurrentDomain) {
                            Write-Verbose ('{0}|FSMO: Getting operationmasterroles for Domain: {1}' -f $Function_Name, $Result_To_Return['domain'])

                            # Domain roles - Infrastructure Master, PDC Emulator, RID Master
                            $FSMO_Domain_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                            $FSMO_Domain_Search_Parameters['Context'] = 'Domain'
                            $FSMO_Domain_Search_Parameters['Server'] = $Result_To_Return['domain']
                            $FSMO_Domain_Search_Parameters['PageSize'] = $PageSize
                            $FSMO_Domain_Search_Parameters['LDAPFilter'] = '(fsmoroleowner=*)'
                            $FSMO_Domain_Search_Parameters['Properties'] = @('fsmoroleowner', 'objectclass')
                            Write-Verbose ('{0}|FSMO_Domain: Calling Find-DSSRawObject' -f $Function_Name)
                            $FSMO_Domain_Results = Find-DSSRawObject @FSMO_Domain_Search_Parameters

                            $OperationsMaster_Roles_Domain_Properties = @{
                                'Domain'               = $Result_To_Return['domain']
                                'InfrastructureMaster' = ($FSMO_Domain_Results | Where-Object { $_.'objectclass' -eq 'infrastructureupdate' }).'fsmoroleowner'
                                'PDCEmulator'          = ($FSMO_Domain_Results | Where-Object { $_.'objectclass' -eq 'domain' }).'fsmoroleowner'
                                'RIDMaster'            = ($FSMO_Domain_Results | Where-Object { $_.'objectclass' -eq 'ridmanager' }).'fsmoroleowner'
                            }
                            $OperationsMaster_Roles_Domain.Add((New-Object -TypeName 'System.Management.Automation.PSObject' -Property $OperationsMaster_Roles_Domain_Properties))
                            $OperationsMaster_Roles_CurrentDomain = $OperationsMaster_Roles_Domain | Where-Object { $_.'Domain' -eq $Result_To_Return['domain'] }
                        }

                        $Server_OperationsMaster_Roles = New-Object -TypeName 'System.Collections.Generic.List[String]'
                        $OperationsMaster_Roles_CurrentDomain, $OperationsMaster_Roles_Forest | ForEach-Object {
                            foreach ($FSMO_Role in $_.PSObject.Properties) {
                                if ($FSMO_Role.Value -match $Result_To_Return['serverobjectdn']) {
                                    $Server_OperationsMaster_Roles.Add($FSMO_Role.Name)
                                }
                            }
                        }

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
                                $Non_LDAP_Network_Property_AddressList = ($Host_IP_Addresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' }).IPAddressToString
                            } elseif ($Non_LDAP_Network_Property -eq 'ipv6address') {
                                $Non_LDAP_Network_Property_AddressList = ($Host_IP_Addresses | Where-Object { ($_.AddressFamily -eq 'InterNetworkV6') -and (-not $_.IsIPv6LinkLocal) -and (-not $_.IsIPv6SiteLocal) }).IPAddressToString
                            }

                            Write-Verbose ('{0}|Non_LDAP: Adding Property: {1} = {2}' -f $Function_Name, $Non_LDAP_Network_Property, $Non_LDAP_Network_Property_AddressList)
                            $Result_To_Return[$Non_LDAP_Network_Property] = $Non_LDAP_Network_Property_AddressList
                        }
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
