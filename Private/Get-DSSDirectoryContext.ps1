function Get-DSSDirectoryContext {
    <#
    .SYNOPSIS
        This creates a DirectoryContext object, which can be used in System.DirectoryServices.ActiveDirectory methods.
    .DESCRIPTION
        Creates a DirectoryContext object, using the specified Context, Server and/or Credentials.
    .EXAMPLE
        $Forest_Context = Get-DSSDirectoryContext -Context Forest -Server root.contoso.com
        [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($Forest_Context)
    .NOTES
        References:
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.directorycontext
    #>

    [CmdletBinding()]
    param(
        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $true)]
        [ValidateSet('Domain', 'Forest', 'Server')]
        [String]
        $Context,

        # The server/domain/forest to run the query on.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Forest', 'Domain')]
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

    $Directory_Context_Arguments = New-Object -TypeName 'System.Collections.Generic.List[String]'
    if ($Context -eq 'Server') {
        $Directory_Context_Arguments.Add('DirectoryServer')
    } else {
        $Directory_Context_Arguments.Add($Context)
    }
    Write-Verbose ('{0}|Using Context: {1}' -f $Function_Name, $Directory_Context_Arguments[0])

    Write-Verbose ('{0}|Using Server/Domain/Forest: {1}' -f $Function_Name, $Server)
    $Directory_Context_Arguments.Add($Server)

    if ($PSBoundParameters.ContainsKey('Credential')) {
        if ($Credential.GetNetworkCredential().Domain) {
            $Credential_User = ('{0}\{1}' -f $Credential.GetNetworkCredential().Domain, $Credential.GetNetworkCredential().UserName)
        } else {
            $Credential_User = $Credential.GetNetworkCredential().UserName
        }
        Write-Verbose ('{0}|Custom credential user: {1}' -f $Function_Name, $Credential_User)
        $Directory_Context_Arguments.Add($Credential_User)
        $Directory_Context_Arguments.Add($Credential.GetNetworkCredential().Password)
    }

    # Return the DirectoryContext object
    New-Object -TypeName 'System.DirectoryServices.ActiveDirectory.DirectoryContext' -ArgumentList $Directory_Context_Arguments
}
