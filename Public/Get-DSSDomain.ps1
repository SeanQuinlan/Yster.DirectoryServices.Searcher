function Get-DSSDomain {
    <#
    .SYNOPSIS
        Returns information on a domain from Active Directory.
    .DESCRIPTION

    .EXAMPLE

    .NOTES
        The ObjectSID and ObjectGUID properties can only reference domains/subdomains from the currently connected domain.

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

    # Default properties as per Get-ADDomain. These are always returned, in addition to any others specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'distinguishedname'
        'name'
        'objectclass'
        'objectguid'
    )

    # All the remaining properties as per Get-ADDomain.
    [String[]]$Wildcard_Properties = @(
        'computerscontainer'
        'deletedobjectscontainer'
        'dnsroot'
        'domaincontrollerscontainer'
        'foreignsecurityprincipalscontainer'
        'infrastructurecontainer'
        'linkedgrouppolicyobjects'
        'lostandfoundcontainer'
        'keyscontainer'
        'managedserviceaccountscontainer'
        'microsoftprogramdatacontainer'
        'netbiosname'
        'objectsid'
        'programdatacontainer'
        'quotascontainer'
        'subrefs'
        'systemscontainer'
        'userscontainer'
    )

    [String[]]$Default_Properties1 = @(
        'alloweddnssuffixes'
        'childdomains'
        'domainmode'
        'forest'
        'infrastructuremaster'
        'lastlogonreplicationinterval'
        'managedby'
        'parentdomain'
        'pdcemulator'
        'publickeyrequiredpasswordrolling'
        'readonlyreplicadirectoryservers'
        'ridmaster'
    )

    try {
        $Directory_Search_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Search_Parameters.Server = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Search_Parameters.Credential = $Credential
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
        $Directory_Search_Parameters.Properties = $Directory_Search_Properties

        $Default_Domain_LDAPFilter = '(objectclass=domain)'
        if ($PSBoundParameters.ContainsKey('DNSName')) {
            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
            $Directory_Search_Parameters.SearchBase = $DNSName
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
            $Directory_Search_Parameters.SearchBase = $DistinguishedName

            #        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            #            $Directory_Search_LDAPFilter = '(&({0})(objectsid={1}))' -f $Default_Domain_LDAPFilter, $ObjectSID
            #        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            #            $Directory_Search_LDAPFilter = '(&({0})(objectguid={1}))' -f $Default_Domain_LDAPFilter, $ObjectGUID
            #        } elseif ($PSBoundParameters.ContainsKey('NetBIOSName')) {
            #            $Directory_Search_LDAPFilter = '(x={0})' -f $NetBIOSName
        }

        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters.LDAPFilter = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSObject' -f $Function_Name)
        $Domain_Results_To_Return = Find-DSSObject @Directory_Search_Parameters

        # Some properties need to be gathered via different methods.
        $Network_Properties = @('netbiosname', 'dnsroot')
        $Network_Properties_To_Process = $Directory_Search_Properties | Where-Object { $Network_Properties -contains $_ }

        if ($Network_Properties_To_Process) {
            Write-Verbose ('{0}|Calculating Network properties' -f $Function_Name)
            $Network_Search_Parameters = @{}
            if ($PSBoundParameters.ContainsKey('Server')) {
                $Network_Search_Parameters.Server = $Server
            }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $Network_Search_Parameters.Credential = $Credential
            }
            Write-Verbose ('{0}|Network: Calling Get-DSSRootDSE' -f $Function_Name)
            $DSE_Return_Object = Get-DSSRootDSE @Network_Search_Parameters
            $Configuration_Path = 'CN=Partitions,{0}' -f $DSE_Return_Object.configurationNamingContext
            Write-Verbose ('{0}|Network: Configuration_Path: {1}' -f $Function_Name, $Configuration_Path)

            $Network_Search_Parameters.SearchBase = $Configuration_Path
            $Network_Search_Parameters.Context = $Context
            $Network_Search_Parameters.LDAPFilter = '(&(objectclass=crossref)(netbiosname=*))'
            $Network_Search_Parameters.Properties = @('netbiosname', 'dnsroot')

            Write-Verbose ('{0}|Network: Calling Find-DSSObject' -f $Function_Name)
            $Network_Return_Object = Find-DSSObject @Network_Search_Parameters

            foreach ($Network_Property in $Network_Properties_To_Process) {
                Write-Verbose ('{0}|Network: Adding: {1}' -f $Function_Name, $Network_Property)
                $Network_Property_To_Add = New-Object -TypeName 'System.Management.Automation.PSNoteProperty' -ArgumentList @($Network_Property, $Network_Return_Object.$Network_Property)
                $Domain_Results_To_Return.PSObject.Properties.Add($Network_Property_To_Add)
            }
        }

        # Return the full domain object
        $Domain_Results_To_Return
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
