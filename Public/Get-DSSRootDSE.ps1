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
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name,$_.Key,($_.Value -join ' ')) }

    $Directory_Entry_Parameters = @{
        'Context'       = 'Domain'
        'SearchBase'    = 'RootDSE'
    }
    if ($PSBoundParameters.ContainsKey('Server')) {
        $Directory_Entry_Parameters.Server = $Server
    }
    if ($PSBoundParameters.ContainsKey('Credential')) {
        $Directory_Entry_Parameters.Credential = $Credential
    }
    $Directory_Entry = Get-DSSDirectoryEntry @Directory_Entry_Parameters

    # Simply return the DirectoryEntry object
    $Directory_Entry
}