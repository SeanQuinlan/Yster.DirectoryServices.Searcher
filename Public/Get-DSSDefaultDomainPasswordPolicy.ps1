function Get-DSSDefaultDomainPasswordPolicy {
    <#
    .SYNOPSIS
        Returns information on the default password policy from the Active Directory domain.
    .DESCRIPTION
        Returns specific properties related to the default password policy set on the domain.
    .EXAMPLE
        Get-DSSDefaultDomainPasswordPolicy -DNSName 'sales.contoso.com'

        Returns password policy information for the domain 'sales.contoso.com'
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-addefaultdomainpasswordpolicy
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

    # The default properties as per Get-ADDefaultDomainPasswordPolicy. These are always returned, in addition to any others specified in the Properties parameter.
    [String[]]$Default_Properties = @(
        'complexityenabled'
        'distinguishedname'
        'lockoutduration'
        'lockoutobservationwindow'
        'lockoutthreshold'
        'maxpasswordage'
        'minpasswordage'
        'minpasswordlength'
        'objectclass'
        'objectguid'
        'passwordhistorycount'
        'reversibleencryptionenabled'
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

        $Function_Search_Properties = New-Object -TypeName 'System.Collections.Generic.List[String]'
        if ($PSBoundParameters.ContainsKey('Properties')) {
            Write-Verbose ('{0}|Adding default properties first' -f $Function_Name)
            $Function_Search_Properties.AddRange($Default_Properties)
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

        $Directory_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
        $Directory_Search_Parameters['Context'] = $Context
        $Directory_Search_Parameters['Properties'] = $Function_Search_Properties

        $Default_Domain_LDAPFilter = '(objectclass=domaindns)'
        if ($PSBoundParameters.ContainsKey('DNSName')) {
            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $Directory_Search_LDAPFilter = $Default_Domain_LDAPFilter
            $Directory_Search_Parameters['SearchBase'] = $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $Directory_Search_LDAPFilter = '(&({0})(objectsid={1}))' -f $Default_Domain_LDAPFilter, $ObjectSID
        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            $Directory_Search_LDAPFilter = '(&({0})(objectguid={1}))' -f $Default_Domain_LDAPFilter, (Convert-GuidToHex -Guid $ObjectGUID)
            #todo
            #        } elseif ($PSBoundParameters.ContainsKey('NetBIOSName')) {
            #            $Directory_Search_LDAPFilter = '(x={0})' -f $NetBIOSName
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSRawObject' -f $Function_Name)
        $Result_To_Return = Find-DSSRawObject @Directory_Search_Parameters

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
