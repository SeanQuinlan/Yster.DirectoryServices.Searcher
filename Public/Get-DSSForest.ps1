function Get-DSSForest {
    <#
    .SYNOPSIS
        Returns information on a forest from Active Directory.
    .DESCRIPTION
        Returns some forest-specific properties including FSMO roles and child domains.
    .EXAMPLE
        Get-DSSForest -DNSName 'contoso.com'

        Returns basic information on the forest 'contoso.com'
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adforest
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.directorycontext
    #>

    [CmdletBinding(DefaultParameterSetName = 'DNSName')]
    param(
        # The DNSName of the forest.
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'DNSName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DNS')]
        [String]
        $DNSName,

        # The NetBIOS Name of the forest.
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

    # All the properties as per Get-ADForest. Not that many, so no need to return a subset by default.
    [String[]]$Default_Properties = @(
        'applicationpartitions'
        'domainnamingmaster'
        'domains'
        'forestmode'
        'globalcatalogs'
        'name'
        'partitionscontainer'
        'rootdomain'
        'schemamaster'
        'sites'
        'spnsuffixes'
        'upnsuffixes'
    )

    [String[]]$Default_Properties_Not_Yet_Added = @(
        'crossforestreferences'
    )

    $DSE_Properties = @(
        'forestmode'
        'partitionscontainer'
    )
    $Partitions_Properties = @(
        'spnsuffixes'
        'upnsuffixes'
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
                Write-Verbose ('{0}|Wildcard specified, but all properties are default, doing nothing' -f $Function_Name)
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

        $Forest_Results_To_Return = @{}

        $DSE_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
        Write-Verbose ('{0}|Calling Get-DSSRootDSE' -f $Function_Name)
        $DSE_Return_Object = Get-DSSRootDSE @DSE_Search_Parameters

        foreach ($DSE_Property in $DSE_Properties) {
            if ($DSE_Property -eq 'forestmode') {
                $DSE_Property_Value = $DSE_Return_Object.'forestfunctionality'
            } elseif ($DSE_Property -eq 'partitionscontainer') {
                $DSE_Property_Value = 'CN=Partitions,{0}' -f $DSE_Return_Object.'configurationNamingContext'
            }
            Write-Verbose ('{0}|DSE: Setting property: {1} = {2}' -f $Function_Name, $DSE_Property, $DSE_Property_Value)
            $Forest_Results_To_Return[$DSE_Property] = $DSE_Property_Value
        }

        $Partitions_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
        $Partitions_Search_Properties = New-Object -TypeName 'System.Collections.Generic.List[String]'
        foreach ($Partitions_Property in $Partitions_Properties) {
            if ($Partitions_Property -eq 'spnsuffixes') {
                $Partitions_Search_Properties.Add('msds-spnsuffixes')
            } else {
                $Partitions_Search_Properties.Add($Partitions_Property)
            }
        }
        $Partitions_Search_Parameters['Context'] = $Context
        $Partitions_Search_Parameters['Properties'] = $Partitions_Search_Properties
        $Partitions_Search_Parameters['SearchBase'] = $Forest_Results_To_Return['partitionscontainer']
        $Partitions_Search_Parameters['LDAPFilter'] = '(objectclass=crossrefcontainer)'

        Write-Verbose ('{0}|Partitions: Calling Find-DSSObject' -f $Function_Name)
        $Partitions_Return_Object = Find-DSSObject @Partitions_Search_Parameters

        if ($Partitions_Return_Object) {
            foreach ($Partitions_Property in $Partitions_Properties) {
                if ($Partitions_Property -eq 'spnsuffixes') {
                    $Partitions_Property_Value = $Partitions_Return_Object.'msds-spnsuffixes'
                } else {
                    $Partitions_Property_Value = $Partitions_Return_Object.$Partitions_Property
                }
                Write-Verbose ('{0}|Partitions: Adding property: {1} = {2}' -f $Function_Name, $Partitions_Property, $Partitions_Property_Value)
                $Forest_Results_To_Return[$Partitions_Property] = $Partitions_Property_Value
            }
        }

        $Forest_Context_Arguments = $Common_Search_Parameters.PSObject.Copy()
        $Forest_Context_Arguments['Context'] = 'Forest'
        Write-Verbose ('{0}|Forest: Getting forest details' -f $Function_Name)
        $Forest_Context = Get-DSSDirectoryContext @Forest_Context_Arguments
        $Current_Forest_Properties = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($Forest_Context)

        $Directory_Search_Properties | Where-Object { ($DSE_Properties -notcontains $_) -and ($Partitions_Properties -notcontains $_) } | ForEach-Object {
            if ($_ -eq 'domainnamingmaster') {
                $Forest_Result_Value = $Current_Forest_Properties.'NamingRoleOwner'
            } elseif ($_ -eq 'schemamaster') {
                $Forest_Result_Value = $Current_Forest_Properties.'SchemaRoleOwner'
            } else {
                $Forest_Result_Value = $Current_Forest_Properties.$_
            }
            Write-Verbose ('{0}|Forest: Adding property: {1} = {2}' -f $Function_Name, $_, $Forest_Result_Value)
            $Forest_Results_To_Return[$_] = $Forest_Result_Value
        }

        # Return the full domain object after sorting.
        ConvertTo-SortedPSObject -InputObject $Forest_Results_To_Return
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
