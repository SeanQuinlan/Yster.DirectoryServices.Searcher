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
        $Common_Search_Parameters['Context'] = $Context

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

        $Directory_Search_Parameters = @{}
        $Directory_Search_Parameters['Properties'] = $Function_Search_Properties

        $Default_Domain_LDAPFilter = '(objectclass=domaindns)'
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

            $NetBIOSName_Search_Parameters = @{}
            $NetBIOSName_Search_Parameters['SearchBase'] = $Partitions_Path
            $NetBIOSName_Search_Parameters['LDAPFilter'] = '(netbiosname={0})' -f $NetBIOSName
            $NetBIOSName_Search_Parameters['Properties'] = @('ncname')

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
        Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters | ConvertTo-SortedPSObject

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
