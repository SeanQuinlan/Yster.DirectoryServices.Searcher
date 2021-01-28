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

        # The LDAP filter to use for the search. Use this option to specify a more targetted LDAP query.
        # Some examples of using this property are:
        #
        # -LDAPFilter '(description=Domain Controller)'
        # -LDAPFilter '(&(description=ESXi Server)(location=London))'
        [Parameter(Mandatory = $true, ParameterSetName = 'LDAPFilter')]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The name to use in the search. The name will be used in an Ambiguous Name Recognition (ANR) search, so it will match on any commonly indexed property.
        # An example of using this property is:
        #
        # -Name 'dcsrv01'
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
        # -SearchBase 'OU=Domain Controllers,DC=contoso,DC=com'
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
        'distinguishedname'
        'dnshostname'
        'domain'
        'enabled'
        'forest'
        'hostname'
        'invocationid'
        'ipv4address'
        'ipv6address'
        'isglobalcatalog'
        'isreadonly'
        'name'
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
        'site'
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

    # Returned from DSE query.
    $DSE_Properties = @(
        'defaultpartition'
        'partitions'
    )

    try {
        $Basic_Parameters = @('Credential', 'Server')
        $Common_Parameters = @('Context')
        $Basic_Search_Parameters = @{}
        foreach ($Parameter in $Basic_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Basic Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $PSBoundParameters[$Parameter])
                $Basic_Search_Parameters[$Parameter] = $PSBoundParameters[$Parameter]
            }
        }
        $Common_Search_Parameters = $Basic_Search_Parameters.PSBase.Clone()
        foreach ($Parameter in $Common_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Common Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $PSBoundParameters[$Parameter])
                $Common_Search_Parameters[$Parameter] = $PSBoundParameters[$Parameter]
            }
        }

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
        $PSBoundParameters['Properties'] = $Function_Search_Properties

        Write-Verbose ('{0}|Calling Find-DSSObjectWrapper' -f $Function_Name)
        $Results_To_Return = Find-DSSObjectWrapper -ObjectType 'DomainController' -BoundParameters $PSBoundParameters -OutputFormat 'Hashtable'

        if ($Results_To_Return) {
            $Partition_Properties_To_Process = $Function_Search_Properties | Where-Object { $Partition_Properties -contains $_ }
            $Domain_Properties_To_Process = $Function_Search_Properties | Where-Object { $Domain_Properties -contains $_ }
            $DSE_Properties_To_Process = $Function_Search_Properties | Where-Object { $DSE_Properties -contains $_ }
            $OperationsMaster_Roles_Domain = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

            if ($Partition_Properties_To_Process) {
                Write-Verbose ('{0}|Sites: Calculating DSE properties' -f $Function_Name)
                if (-not $DSE_Return_Object) {
                    Write-Verbose ('{0}|Sites: Calling Get-DSSRootDSE' -f $Function_Name)
                    $DSE_Return_Object = Get-DSSRootDSE @Basic_Search_Parameters
                }

                $Sites_Path = 'CN=Sites,{0}' -f $DSE_Return_Object.'configurationnamingcontext'
                Write-Verbose ('{0}|Sites: Sites_Path: {1}' -f $Function_Name, $Sites_Path)

                $Site_Search_Parameters = $Common_Search_Parameters.PSBase.Clone()
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
                $Site_Results = Find-DSSRawObject @Site_Search_Parameters
            }

            foreach ($Result_To_Return in $Results_To_Return) {
                if ($Partition_Properties_To_Process) {
                    $Server_Object = $Site_Results | Where-Object { $_['serverreference'] -eq $Result_To_Return['distinguishedname'] }
                    $NTDS_Settings = $Site_Results | Where-Object { ($_['objectclass'] -contains 'ntdsdsa') -and ($_['distinguishedname'] -match $Server_Object['distinguishedname']) }

                    # Add any properties gathered from the Partitions object.
                    foreach ($Partition_Property in $Partition_Properties_To_Process) {
                        switch ($Partition_Property) {
                            'invocationid' {
                                $Partition_Property_Value = $NTDS_Settings['invocationid']
                            }
                            'isglobalcatalog' {
                                $NTDS_Options_Flags = [Enum]::Parse('NTDSDSAOption', $NTDS_Settings['options'], $true)
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
                    $Domain_Search_Parameters['NoDefaultProperties'] = $true
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

                if ($DSE_Properties_To_Process) {
                    $DSE_Search_Parameters = $Basic_Search_Parameters.PSObject.Copy()
                    $DSE_Search_Parameters['Server'] = $Result_To_Return['dnshostname']
                    Write-Verbose ('{0}|DSE: Calling Get-DSSRootDSE on server: {1}' -f $Function_Name, $DSE_Search_Parameters['Server'])
                    $DSE_Special_Return_Object = Get-DSSRootDSE @DSE_Search_Parameters

                    foreach ($DSE_Property in $DSE_Properties_To_Process) {
                        switch ($DSE_Property) {
                            'defaultpartition' {
                                $DSE_Property_Value = $DSE_Special_Return_Object.'defaultnamingcontext'
                            }
                            'partitions' {
                                $DSE_Property_Value = $DSE_Special_Return_Object.'namingcontexts'
                            }
                        }

                        Write-Verbose ('{0}|DSE: Adding Property: {1} = {2}' -f $Function_Name, $DSE_Property, $DSE_Property_Value)
                        $Result_To_Return[$DSE_Property] = $DSE_Property_Value
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
