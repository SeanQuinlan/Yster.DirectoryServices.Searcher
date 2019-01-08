function Get-DSSRootDSE {
    <#
    .SYNOPSIS
        Gets the special RootDSE object from the directory server.
    .DESCRIPTION
        Retrieves the RootDSE object which provides information about the directory schema, version, supported capabilities and other LDAP server details
    .EXAMPLE
        (Get-RootDSE).schemaNamingContext

        This returns the naming context (DistinguishedName) of the Schema container.
    .EXAMPLE
        $DomainDN = (Get-RootDSE).defaultNamingContext

        Returns the DistinguishedName of the Active Directory domain.
    #>

    [CmdletBinding()]
    param(
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

    try {
        $Directory_Entry_Parameters = @{
            'Context'    = 'Domain'
            'SearchBase' = 'RootDSE'
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Entry_Parameters.Server = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Entry_Parameters.Credential = $Credential
        }
        $Directory_Entry = Get-DSSDirectoryEntry @Directory_Entry_Parameters

        # Format the DirectoryEntry object to match that returned from Find-DSSObject.
        Write-Verbose ('{0}|Formatting result' -f $Function_Name)
        $RootDSE_Result_To_Return = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

        $Result_Object = @{}
        $Directory_Entry.Properties.PropertyNames | ForEach-Object {
            $RootDSE_Property = $_
            $RootDSE_Value = $($Directory_Entry.$_)
            Write-Verbose ('{0}|Property={1} Value={2}' -f $Function_Name, $RootDSE_Property, $RootDSE_Value)

            if ($RootDSE_Property -eq 'domaincontrollerfunctionality') {
                $Result_Object[$RootDSE_Property] = $DomainControllerMode_Table[$RootDSE_Value]
            } elseif ($RootDSE_Property -eq 'domainfunctionality') {
                $Result_Object[$RootDSE_Property] = $DomainMode_Table[$RootDSE_Value]
            } elseif ($RootDSE_Property -eq 'forestfunctionality') {
                $Result_Object[$RootDSE_Property] = $ForestMode_Table[$RootDSE_Value]
            } else {
                $Result_Object[$RootDSE_Property] = $RootDSE_Value
            }
        }

        # Sort results and then add to a new hashtable, as PSObject requires a hashtable as Property. GetEnumerator() piped into Sort-Object changes the output to an array.
        $Result_Object_Sorted = [ordered]@{}
        $Result_Object.GetEnumerator() | Sort-Object -Property 'Name' | ForEach-Object {
            $Result_Object_Sorted[$_.Name] = $_.Value
        }
        $RootDSE_Result_Object = New-Object -TypeName 'System.Management.Automation.PSObject' -Property $Result_Object_Sorted
        $RootDSE_Result_To_Return.Add($RootDSE_Result_Object)

        # Return the RootDSE object.
        $RootDSE_Result_To_Return
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
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
