function Get-DSSRootDSE {
    <#
    .SYNOPSIS
        Gets the special RootDSE object from the directory server.
    .DESCRIPTION
        Retrieves the RootDSE object which provides information about the directory schema, version, supported capabilities and other LDAP server details.
    .EXAMPLE
        (Get-DSSRootDSE).schemaNamingContext

        This returns the naming context (DistinguishedName) of the Schema container.
    .EXAMPLE
        $DomainDN = (Get-DSSRootDSE).defaultNamingContext

        Returns the DistinguishedName of the Active Directory domain.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adrootdse
    #>

    [CmdletBinding()]
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

    try {
        $Directory_Entry_Parameters = @{
            'Context'    = 'Domain'
            'SearchBase' = 'RootDSE'
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Entry_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Entry_Parameters['Credential'] = $Credential
        }
        $Directory_Entry = Get-DSSDirectoryEntry @Directory_Entry_Parameters

        # Format the DirectoryEntry object to match that returned from Find-DSSRawObject.
        Write-Verbose ('{0}|Formatting result' -f $Function_Name)
        $Results_To_Return = @{}
        $Directory_Entry.Properties.PropertyNames | ForEach-Object {
            $RootDSE_Property = $_
            $RootDSE_Value = $($Directory_Entry.$_)
            Write-Verbose ('{0}|Property={1} Value={2}' -f $Function_Name, $RootDSE_Property, $RootDSE_Value)

            if ($RootDSE_Property -eq 'domaincontrollerfunctionality') {
                $Results_To_Return[$RootDSE_Property] = $DomainControllerMode_Table[$RootDSE_Value]
            } elseif ($RootDSE_Property -eq 'domainfunctionality') {
                $Results_To_Return[$RootDSE_Property] = $DomainMode_Table[$RootDSE_Value]
            } elseif ($RootDSE_Property -eq 'forestfunctionality') {
                $Results_To_Return[$RootDSE_Property] = $ForestMode_Table[$RootDSE_Value]
            } else {
                $Results_To_Return[$RootDSE_Property] = $RootDSE_Value
            }
        }

        $Results_To_Return | ConvertTo-SortedPSObject

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}

# From: https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management.addomaincontrollermode?view=activedirectory-management-10.0
$DomainControllerMode_Table = @{
    '0' = 'Windows2000'
    '2' = 'Windows2003'
    '3' = 'Windows2008'
    '4' = 'Windows2008R2'
    '5' = 'Windows2012'
    '6' = 'Windows2012R2'
    '7' = 'Windows2016'
}

# From: https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management.addomainmode?view=activedirectory-management-10.0
$DomainMode_Table = @{
    '0' = 'Windows2000Domain'
    '1' = 'Windows2003InterimDomain'
    '2' = 'Windows2003Domain'
    '3' = 'Windows2008Domain'
    '4' = 'Windows2008R2Domain'
    '5' = 'Windows2012Domain'
    '6' = 'Windows2012R2Domain'
    '7' = 'Windows2016Domain'
}

# From: https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management.adforestmode?view=activedirectory-management-10.0
$ForestMode_Table = @{
    '0' = 'Windows2000Forest'
    '1' = 'Windows2003InterimForest'
    '2' = 'Windows2003Forest'
    '3' = 'Windows2008Forest'
    '4' = 'Windows2008R2Forest'
    '5' = 'Windows2012Forest'
    '6' = 'Windows2012R2Forest'
    '7' = 'Windows2016Forest'
}
