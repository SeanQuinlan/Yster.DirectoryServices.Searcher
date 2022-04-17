function Get-DSSDomain {
    <#
    .SYNOPSIS
        Returns information on a domain from Active Directory.
    .DESCRIPTION
        Returns some domain-specific properties including FSMO roles, child/parent domains, and key container paths.
    .EXAMPLE
        Get-DSSDomain -DNSName 'sales.contoso.com'

        Returns basic information for the domain 'sales.contoso.com'
    .EXAMPLE
        Get-DSSDomain -NetBIOSName 'CONTOSO' -Properties *

        Returns all properties for the domain 'CONTOSO'
    .NOTES
        The ObjectSID and ObjectGUID properties can only reference domains/subdomains from the currently connected domain.

        References:
        https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-addomain
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.directorycontext
    #>

    [CmdletBinding(DefaultParameterSetName = 'DNSName')]
    param(
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

        # The DistinguishedName of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The DNSName of the domain.
        # An example of using this property is:
        #
        # -DNSName 'contoso.com'
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'DNSName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DNS')]
        [String]
        $DNSName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,

        # The ObjectGUID of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The ObjectSID of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The NetBIOS Name of the domain.
        # An example of using this property is:
        #
        # -NetBIOSName 'contoso'
        [Parameter(Mandatory = $true, ParameterSetName = 'NetBIOSName')]
        [ValidateNotNullOrEmpty()]
        [Alias('NetBIOS')]
        [String]
        $NetBIOSName,

        # Whether or not to include default properties. By setting this switch, only the explicitly specified properties will be returned.
        [Parameter(Mandatory = $false)]
        [Switch]
        $NoDefaultProperties,

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

    # A couple of default properties. These are always returned, in addition to any others specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'name'
        'objectclass'
        'objectguid'
    )

    # All the remaining properties as per Get-ADDomain.
    [String[]]$Wildcard_Properties = @(
        'alloweddnssuffixes'
        'childdomains'
        'computerscontainer'
        'deletedobjectscontainer'
        'distinguishedname'
        'dnsroot'
        'domaincontrollerscontainer'
        'domainmode'
        'domainsid'
        'foreignsecurityprincipalscontainer'
        'forest'
        'infrastructurecontainer'
        'infrastructuremaster'
        'lastlogonreplicationinterval'
        'linkedgrouppolicyobjects'
        'lostandfoundcontainer'
        'keyscontainer'
        'managedby'
        'managedserviceaccountscontainer'
        'microsoftprogramdatacontainer'
        'msds-alloweddnssuffixes'
        'msds-logontimesyncinterval'
        'name'
        'netbiosname'
        'objectclass'
        'objectguid'
        'objectsid'
        'parentdomain'
        'pdcemulator'
        'programdatacontainer'
        'quotascontainer'
        'readonlyreplicadirectoryservers'
        'replicadirectoryservers'
        'ridmaster'
        'subordinatereferences'
        'subrefs'
        'systemscontainer'
        'userscontainer'
    )

    $Network_Properties = @(
        'dnsroot'
        'domainmode'
        'netbiosname'
    )
    $Domain_Properties = @(
        'childdomains'
        'forest'
        'infrastructuremaster'
        'parentdomain'
        'pdcemulator'
        'ridmaster'
    )
    $Replica_Properties = @(
        'readonlyreplicadirectoryservers'
        'replicadirectoryservers'
    )

    try {
        $Basic_Search_Parameters = @{}
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Basic_Search_Parameters['Server'] = $Server
        } elseif ($PSBoundParameters.ContainsKey('DNSName')) {
            Write-Verbose ('{0}|Adding DNSName as Server Name: {1}' -f $Function_Name, $DNSName)
            $Basic_Search_Parameters['Server'] = $DNSName
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Basic_Search_Parameters['Credential'] = $Credential
        }
        $Common_Search_Parameters = $Basic_Search_Parameters.PSBase.Clone()
        # Only domain context makes sense in this function, so we set it statically here.
        $Common_Search_Parameters['Context'] = 'Domain'

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

        $Directory_Search_Parameters = @{}
        $Directory_Search_Parameters['Properties'] = $Function_Search_Properties

        $Default_Domain_LDAPFilter = '(objectclass=domain)'
        if ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
            $Directory_Search_Parameters['SearchBase'] = $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $Directory_Search_LDAPFilter = '(&({0})(objectsid={1}))' -f $Default_Domain_LDAPFilter, $ObjectSID
        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            $Directory_Search_LDAPFilter = '(&({0})(objectguid={1}))' -f $Default_Domain_LDAPFilter, $ObjectGUID
        } elseif ($PSBoundParameters.ContainsKey('NetBIOSName')) {
            Write-Verbose ('{0}|NetBIOSName: Calculating DSE properties' -f $Function_Name)
            Write-Verbose ('{0}|NetBIOSName: Calling Get-DSSRootDSE' -f $Function_Name)
            $DSE_Return_Object = Get-DSSRootDSE @Basic_Search_Parameters

            $Partitions_Path = 'CN=Partitions,{0}' -f $DSE_Return_Object.'configurationnamingcontext'
            Write-Verbose ('{0}|NetBIOSName: Partitions_Path: {1}' -f $Function_Name, $Partitions_Path)

            $NetBIOSName_Search_Parameters = @{
                'SearchBase' = $Partitions_Path
                'LDAPFilter' = '(netbiosname={0})' -f $NetBIOSName
                'Properties' = @('ncname')
            }

            Write-Verbose ('{0}|NetBIOSName: Calling Find-DSSRawObject' -f $Function_Name)
            $NetBIOSName_Result_To_Return = Find-DSSRawObject @Common_Search_Parameters @NetBIOSName_Search_Parameters

            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
            $Directory_Search_Parameters['SearchBase'] = $NetBIOSName_Result_To_Return['ncname']
            Write-Verbose ('{0}|NetBIOSName: Using DN: {1}' -f $Function_Name, $NetBIOSName_Result_To_Return['ncname'])
        } else {
            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSRawObject' -f $Function_Name)
        $Result_To_Return = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters

        if ($Result_To_Return) {
            # Some properties need to be gathered via different methods.
            $Network_Properties_To_Process = $Function_Search_Properties | Where-Object { $Network_Properties -contains $_ }
            $Domain_Properties_To_Process = $Function_Search_Properties | Where-Object { $Domain_Properties -contains $_ }
            $Replica_Properties_To_Process = $Function_Search_Properties | Where-Object { $Replica_Properties -contains $_ }

            if ($Network_Properties_To_Process -or $Domain_Properties_To_Process) {
                if (-not $DSE_Return_Object) {
                    Write-Verbose ('{0}|Network/Domain: Calculating DSE properties' -f $Function_Name)
                    Write-Verbose ('{0}|Network/Domain: Calling Get-DSSRootDSE' -f $Function_Name)
                    $DSE_Return_Object = Get-DSSRootDSE @Basic_Search_Parameters
                }

                $Partitions_Path = 'CN=Partitions,{0}' -f $DSE_Return_Object.'configurationnamingcontext'
                Write-Verbose ('{0}|Network/Domain: Partitions_Path: {1}' -f $Function_Name, $Partitions_Path)

                $Network_Search_Parameters = @{
                    'SearchBase' = $Partitions_Path
                    'LDAPFilter' = '(&(objectclass=crossref)(netbiosname=*)(ncname={0}))' -f $Result_To_Return['distinguishedname']
                    'Properties' = $Network_Properties
                }
                Write-Verbose ('{0}|Network/Domain: Calling Find-DSSRawObject' -f $Function_Name)
                $Network_Result_To_Return = Find-DSSRawObject @Common_Search_Parameters @Network_Search_Parameters

                if ($Network_Result_To_Return) {
                    foreach ($Network_Property in $Network_Properties_To_Process) {
                        if ($Network_Property -eq 'domainmode') {
                            $Network_Property_Value = $DSE_Return_Object.'domainfunctionality'
                        } else {
                            $Network_Property_Value = $Network_Result_To_Return[$Network_Property]
                        }
                        Write-Verbose ('{0}|Network: Adding: {1} - {2}' -f $Function_Name, $Network_Property, $Network_Property_Value)
                        $Result_To_Return[$Network_Property] = $Network_Property_Value
                    }
                }

                if ($Domain_Properties_To_Process) {
                    Write-Verbose ('{0}|Domain: Calculating Domain properties for: {1}' -f $Function_Name, $Network_Result_To_Return['dnsroot'])
                    $Domain_Context_Arguments = $Common_Search_Parameters.PSObject.Copy()
                    if ($PSBoundParameters.ContainsKey('Server')) {
                        $Domain_Context_Arguments['Context'] = 'Server'
                    } else {
                        $Domain_Context_Arguments['Server'] = $Network_Result_To_Return['dnsroot']
                    }
                    Write-Verbose ('{0}|Domain: Getting domain details' -f $Function_Name)
                    $Domain_Context = Get-DSSDirectoryContext @Domain_Context_Arguments
                    $Current_Domain_Properties = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($Domain_Context)

                    foreach ($Domain_Property in $Domain_Properties_To_Process) {
                        if ($Domain_Property -eq 'childdomains') {
                            $Domain_Property_Value = $Current_Domain_Properties.'Children'.Name
                        } elseif ($Domain_Property -eq 'infrastructuremaster') {
                            $Domain_Property_Value = $Current_Domain_Properties.'InfrastructureRoleOwner'
                        } elseif ($Domain_Property -eq 'parentdomain') {
                            $Domain_Property_Value = $Current_Domain_Properties.'Parent'
                        } elseif ($Domain_Property -eq 'pdcemulator') {
                            $Domain_Property_Value = $Current_Domain_Properties.'PdcRoleOwner'
                        } elseif ($Domain_Property -eq 'ridmaster') {
                            $Domain_Property_Value = $Current_Domain_Properties.'RidRoleOwner'
                        } else {
                            $Domain_Property_Value = $Current_Domain_Properties.$Domain_Property
                        }
                        Write-Verbose ('{0}|Domain: Adding: {1} - {2}' -f $Function_Name, $Domain_Property, $Domain_Property_Value)
                        $Result_To_Return[$Domain_Property] = $Domain_Property_Value
                    }
                }

                if ($Replica_Properties_To_Process) {
                    Write-Verbose ('{0}|Replica: Calculating Replica properties for: {1}' -f $Function_Name, $Network_Result_To_Return['dnsroot'])
                    $Replica_Search_Parameters = @{
                        'Name'                = '*'
                        'Properties'          = @('dnshostname', 'isreadonly')
                        'NoDefaultProperties' = $true
                    }

                    Write-Verbose ('{0}|Replica: Calling Find-DSSDomainController' -f $Function_Name)
                    $Replica_Results = Find-DSSDomainController @Common_Search_Parameters @Replica_Search_Parameters
                    foreach ($Replica_Property in $Replica_Properties) {
                        if ($Replica_Property -eq 'replicadirectoryservers') {
                            $Replica_Property_Value = ($Replica_Results | Where-Object { $_.'isreadonly' -eq $false }).'dnshostname'
                        } elseif ($Replica_Property -eq 'readonlyreplicadirectoryservers') {
                            $Replica_Property_Value = ($Replica_Results | Where-Object { $_.'isreadonly' -eq $true }).'dnshostname'
                        }
                        Write-Verbose ('{0}|Replica: Adding: {1} - {2}' -f $Function_Name, $Replica_Property, $Replica_Property_Value)
                        $Result_To_Return[$Replica_Property] = $Replica_Property_Value
                    }
                }
            }

            $Result_To_Return | ConvertTo-SortedPSObject
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
