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
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-addomain
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.directorycontext
    #>

    [CmdletBinding(DefaultParameterSetName = 'DNSName')]
    param(
        # The DNSName of the domain.
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'DNSName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DNS')]
        [String]
        $DNSName,

        # The DistinguishedName of the domain.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the domain.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the domain.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The NetBIOS Name of the domain.
        [Parameter(Mandatory = $true, ParameterSetName = 'NetBIOSName')]
        [ValidateNotNullOrEmpty()]
        [Alias('NetBIOS')]
        [String]
        $NetBIOSName,

        # The properties of any results to return.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

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

    # A couple of default properties. These are always returned, in addition to any others specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'name'
        'objectclass'
        'objectguid'
    )

    # All the remaining properties as per Get-ADDomain.
    [String[]]$Wildcard_Properties = @(
        'childdomains'
        'computerscontainer'
        'deletedobjectscontainer'
        'dnsroot'
        'domaincontrollerscontainer'
        'domainmode'
        'foreignsecurityprincipalscontainer'
        'forest'
        'infrastructurecontainer'
        'infrastructuremaster'
        'linkedgrouppolicyobjects'
        'lostandfoundcontainer'
        'keyscontainer'
        'managedby'
        'managedserviceaccountscontainer'
        'microsoftprogramdatacontainer'
        'msds-alloweddnssuffixes'
        'netbiosname'
        'objectsid'
        'parentdomain'
        'pdcemulator'
        'programdatacontainer'
        'quotascontainer'
        'ridmaster'
        'subrefs'
        'systemscontainer'
        'userscontainer'
    )

    [String[]]$Default_Properties_Not_Yet_Added = @(
        'lastlogonreplicationinterval'
        'publickeyrequiredpasswordrolling'
        'readonlyreplicadirectoryservers'
        'replicadirectoryservers'
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

    try {
        $Common_Search_Parameters = @{}
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        } else {
            if ($PSBoundParameters.ContainsKey('DNSName')) {
                Write-Verbose ('{0}|Adding DNSName as Server Name: {1}' -f $Function_Name, $DNSName)
                $Common_Search_Parameters['Server'] = $DNSName
            } elseif ($PSBoundParameters.ContainsKey('NetBIOSName')) {
                Write-Verbose ('{0}|Adding NetBIOSName as Server Name: {1}' -f $Function_Name, $NetBIOSName)
                $Common_Search_Parameters['Server'] = $NetBIOSName
            }
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
        }

        $Directory_Search_Properties = New-Object -TypeName 'System.Collections.Generic.List[String]'
        if ($PSBoundParameters.ContainsKey('Properties')) {
            Write-Verbose ('{0}|Adding default properties first' -f $Function_Name)
            $Directory_Search_Properties.AddRange($Default_Properties)
            if ($Properties -contains '*') {
                Write-Verbose ('{0}|Adding other wildcard properties' -f $Function_Name)
                $Directory_Search_Properties.AddRange($Wildcard_Properties)
            }
            foreach ($Property in $Properties) {
                if (($Property -ne '*') -and ($Directory_Search_Properties -notcontains $Property)) {
                    Write-Verbose ('{0}|Adding Property: {1}' -f $Function_Name, $Property)
                    $Directory_Search_Properties.Add($Property)
                }
            }
        } else {
            Write-Verbose ('{0}|No properties specified, adding default properties only' -f $Function_Name)
            $Directory_Search_Properties.AddRange($Default_Properties)
        }
        Write-Verbose ('{0}|Properties: {1}' -f $Function_Name, ($Directory_Search_Properties -join ' '))

        $Directory_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
        $Directory_Search_Parameters['Context'] = $Context
        $Directory_Search_Parameters.Properties = $Directory_Search_Properties

        $Default_Domain_LDAPFilter = '(objectclass=domain)'
        if ($PSBoundParameters.ContainsKey('DNSName')) {
            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
            $Directory_Search_Parameters.SearchBase = $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $Directory_Search_LDAPFilter = '(&({0})(objectsid={1}))' -f $Default_Domain_LDAPFilter, $ObjectSID
        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            $Directory_Search_LDAPFilter = '(&({0})(objectguid={1}))' -f $Default_Domain_LDAPFilter, (Convert-GuidToHex -Guid $ObjectGUID)
            #        } elseif ($PSBoundParameters.ContainsKey('NetBIOSName')) {
            #            $Directory_Search_LDAPFilter = '(x={0})' -f $NetBIOSName
        }

        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters.LDAPFilter = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSObject' -f $Function_Name)
        $Domain_Results_To_Return = Find-DSSObject @Directory_Search_Parameters

        # Some properties need to be gathered via different methods.
        $Network_Properties_To_Process = $Directory_Search_Properties | Where-Object { $Network_Properties -contains $_ }
        $Domain_Properties_To_Process = $Directory_Search_Properties | Where-Object { $Domain_Properties -contains $_ }

        if ($Network_Properties_To_Process -or $Domain_Properties_To_Process) {
            Write-Verbose ('{0}|Calculating DSE properties' -f $Function_Name)
            $DSE_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
            Write-Verbose ('{0}|Calling Get-DSSRootDSE' -f $Function_Name)
            $DSE_Return_Object = Get-DSSRootDSE @DSE_Search_Parameters

            $Configuration_Path = 'CN=Partitions,{0}' -f $DSE_Return_Object.'configurationNamingContext'
            Write-Verbose ('{0}|DSE: Configuration_Path: {1}' -f $Function_Name, $Configuration_Path)

            $Network_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
            $Network_Search_Parameters['Context'] = $Context
            $Network_Search_Parameters['SearchBase'] = $Configuration_Path
            $Network_Search_Parameters['LDAPFilter'] = '(&(objectclass=crossref)(netbiosname=*))'
            $Network_Search_Parameters['Properties'] = $Network_Properties

            Write-Verbose ('{0}|Network: Calling Find-DSSObject' -f $Function_Name)
            $Network_Return_Object = Find-DSSObject @Network_Search_Parameters

            foreach ($Network_Property in $Network_Properties_To_Process) {
                if ($Network_Property -eq 'domainmode') {
                    $Network_Property_ArgumentList = @($Network_Property, $DSE_Return_Object.'domainfunctionality')
                } else {
                    $Network_Property_ArgumentList = @($Network_Property, $Network_Return_Object.$Network_Property)
                }
                Write-Verbose ('{0}|Network: Adding: {1} - {2}' -f $Function_Name, $Network_Property_ArgumentList[0], $Network_Property_ArgumentList[1])
                $Network_Property_To_Add = New-Object -TypeName 'System.Management.Automation.PSNoteProperty' -ArgumentList $Network_Property_ArgumentList
                $Domain_Results_To_Return.PSObject.Properties.Add($Network_Property_To_Add)
            }
            if ($Domain_Properties_To_Process) {
                Write-Verbose ('{0}|Calculating Domain properties for: {1}' -f $Function_Name, $Domain_Results_To_Return.'dnsroot')
                $Domain_Context_Arguments = $Common_Search_Parameters.PSObject.Copy()
                if ($PSBoundParameters.ContainsKey('Server')) {
                    $Forest_Context_Arguments['Context'] = 'Server'
                } else {
                    $Forest_Context_Arguments['Context'] = 'Forest'
                }
                Write-Verbose ('{0}|Domain: Getting domain details' -f $Function_Name)
                $Domain_Context = Get-DSSDirectoryContext @Domain_Context_Arguments
                $Current_Domain_Properties = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($Domain_Context)

                foreach ($Domain_Property in $Domain_Properties_To_Process) {
                    if ($Domain_Property -eq 'childdomains') {
                        $Domain_Property_To_Add_Arguments = @($Domain_Property, $Current_Domain_Properties.'Children')
                    } elseif ($Domain_Property -eq 'infrastructuremaster') {
                        $Domain_Property_To_Add_Arguments = @($Domain_Property, $Current_Domain_Properties.'InfrastructureRoleOwner')
                    } elseif ($Domain_Property -eq 'parentdomain') {
                        $Domain_Property_To_Add_Arguments = @($Domain_Property, $Current_Domain_Properties.'Parent')
                    } elseif ($Domain_Property -eq 'pdcemulator') {
                        $Domain_Property_To_Add_Arguments = @($Domain_Property, $Current_Domain_Properties.'PdcRoleOwner')
                    } elseif ($Domain_Property -eq 'ridmaster') {
                        $Domain_Property_To_Add_Arguments = @($Domain_Property, $Current_Domain_Properties.'RidRoleOwner')
                    } else {
                        $Domain_Property_To_Add_Arguments = @($Domain_Property, $Current_Domain_Properties.$Domain_Property)
                    }
                    Write-Verbose ('{0}|Domain: Adding: {1} - {2}' -f $Function_Name, $Domain_Property, $Domain_Property_To_Add_Arguments[1])
                    $Domain_Property_To_Add = New-Object -TypeName 'System.Management.Automation.PSNoteProperty' -ArgumentList $Domain_Property_To_Add_Arguments
                    $Domain_Results_To_Return.PSObject.Properties.Add($Domain_Property_To_Add)
                }
            }
        }

        # Return the full domain object after sorting.
        ConvertTo-SortedPSObject -InputObject $Domain_Results_To_Return
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
