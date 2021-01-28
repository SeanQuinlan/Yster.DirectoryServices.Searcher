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

        # The DNSName of the forest.
        # An example of using this property is:
        #
        # -DNSName 'contoso.com'
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'DNSName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DNS')]
        [String]
        $DNSName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name,

        # The NetBIOS Name of the forest.
        # An example of using this property is:
        #
        # -NetBIOSName 'contoso'
        [Parameter(Mandatory = $true, ParameterSetName = 'NetBIOSName')]
        [ValidateNotNullOrEmpty()]
        [Alias('NetBIOS')]
        [String]
        $NetBIOSName,

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

    # All the properties as per Get-ADForest. Not that many, so no need to return a subset by default.
    [String[]]$Default_Properties = @(
        'applicationpartitions'
        'crossforestreferences'
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

    $DSE_Properties = @(
        'forestmode'
        'partitionscontainer'
    )
    $Partitions_Properties = @(
        'spnsuffixes'
        'upnsuffixes'
    )

    try {
        $Basic_Search_Parameters = @{}
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Basic_Search_Parameters['Server'] = $Server
        } else {
            if ($PSBoundParameters.ContainsKey('NetBIOSName')) {
                Write-Verbose ('{0}|Adding NetBIOSName as Server Name: {1}' -f $Function_Name, $NetBIOSName)
                $Basic_Search_Parameters['Server'] = $NetBIOSName
            } else {
                Write-Verbose ('{0}|Adding DNSName as Server Name: {1}' -f $Function_Name, $DNSName)
                $Basic_Search_Parameters['Server'] = $DNSName
            }
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Basic_Search_Parameters['Credential'] = $Credential
        }
        $Common_Search_Parameters = $Basic_Search_Parameters.PSBase.Clone()

        $Function_Search_Properties = New-Object -TypeName 'System.Collections.Generic.List[String]'
        if ($PSBoundParameters.ContainsKey('Properties')) {
            Write-Verbose ('{0}|Adding default properties first' -f $Function_Name)
            $Function_Search_Properties.AddRange($Default_Properties)
            if ($Properties -contains '*') {
                Write-Verbose ('{0}|Wildcard specified, but all properties are default, doing nothing' -f $Function_Name)
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

        $Result_To_Return = @{}

        Write-Verbose ('{0}|Calling Get-DSSRootDSE' -f $Function_Name)
        $DSE_Return_Object = Get-DSSRootDSE @Basic_Search_Parameters

        foreach ($DSE_Property in $DSE_Properties) {
            if ($DSE_Property -eq 'forestmode') {
                $DSE_Property_Value = $DSE_Return_Object.'forestfunctionality'
            } elseif ($DSE_Property -eq 'partitionscontainer') {
                $DSE_Property_Value = 'CN=Partitions,{0}' -f $DSE_Return_Object.'configurationNamingContext'
            }
            Write-Verbose ('{0}|DSE: Setting property: {1} = {2}' -f $Function_Name, $DSE_Property, $DSE_Property_Value)
            $Result_To_Return[$DSE_Property] = $DSE_Property_Value
        }

        $Partitions_Search_Parameters = @{}
        $Partitions_Search_Parameters['Properties'] = $Partitions_Properties
        $Partitions_Search_Parameters['SearchBase'] = $Result_To_Return['partitionscontainer']
        $Partitions_Search_Parameters['LDAPFilter'] = '(objectclass=crossrefcontainer)'

        Write-Verbose ('{0}|Partitions: Calling Find-DSSRawObject' -f $Function_Name)
        $Partitions_Results_To_Return = Find-DSSRawObject @Common_Search_Parameters @Partitions_Search_Parameters

        if ($Partitions_Results_To_Return) {
            foreach ($Partitions_Property in $Partitions_Properties) {
                $Partitions_Property_Value = $Partitions_Results_To_Return.$Partitions_Property
                Write-Verbose ('{0}|Partitions: Adding property: {1} = {2}' -f $Function_Name, $Partitions_Property, $Partitions_Property_Value)
                $Result_To_Return[$Partitions_Property] = $Partitions_Property_Value
            }
        }

        $Forest_Context_Arguments = @{}
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Forest_Context_Arguments['Context'] = 'Server'
        } else {
            $Forest_Context_Arguments['Context'] = 'Forest'
        }
        Write-Verbose ('{0}|Forest: Getting forest details' -f $Function_Name)
        $Forest_Context = Get-DSSDirectoryContext @Common_Search_Parameters @Forest_Context_Arguments
        $Current_Forest_Properties = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($Forest_Context)

        $Function_Search_Properties | Where-Object { ($DSE_Properties -notcontains $_) -and ($Partitions_Properties -notcontains $_) } | ForEach-Object {
            if ($_ -eq 'domainnamingmaster') {
                $Forest_Result_Value = $Current_Forest_Properties.'NamingRoleOwner'
            } elseif ($_ -eq 'schemamaster') {
                $Forest_Result_Value = $Current_Forest_Properties.'SchemaRoleOwner'
            } elseif ($_ -eq 'sites') {
                $Forest_Result_Value = $Current_Forest_Properties.'Sites'.Name | Sort-Object
            } else {
                $Forest_Result_Value = $Current_Forest_Properties.$_
            }
            Write-Verbose ('{0}|Forest: Adding property: {1} = {2}' -f $Function_Name, $_, $Forest_Result_Value)
            $Result_To_Return[$_] = $Forest_Result_Value
        }

        $Result_To_Return | ConvertTo-SortedPSObject

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
