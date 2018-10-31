function Get-DSSDirectoryEntry{
    <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        Example of how to use this script
    .EXAMPLE
        Another example of how to use this script
    #>

    [CmdletBinding()]
    param(
        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $true)]
        [String]
        $Context,

        # The server to run the query on.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        # The base OU to start the search from.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        # The credential to use for access.
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name,$_.Key,($_.Value -join ' ')) }

    $Directory_Entry_Path = New-Object -TypeName 'System.Text.StringBuilder'
    if ($Context -eq 'Forest') {
        Write-Verbose ('{0}|Forest context' -f $Function_Name)
        [void]$Directory_Entry_Path.Append('GC://')
        $Default_SearchBase = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
    } else {
        Write-Verbose ('{0}|Domain context' -f $Function_Name)
        [void]$Directory_Entry_Path.Append('LDAP://')
        $Default_SearchBase = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }
    if ($PSBoundParameters.ContainsKey('Server')) {
        Write-Verbose ('{0}|Using server: {1}' -f $Function_Name,$Server)
        [void]$Directory_Entry_Path.Append(('{0}/' -f $Server))
    }
    if ($PSBoundParameters.ContainsKey('SearchBase')) {
        Write-Verbose ('{0}|Using custom SearchBase: {1}' -f $Function_Name,$SearchBase)
        [void]$Directory_Entry_Path.Append($SearchBase)
    } else {
        Write-Verbose ('{0}|Using default SearchBase: {1}' -f $Function_Name,$Default_SearchBase)
        [void]$Directory_Entry_Path.Append($Default_SearchBase)
    }
    Write-Verbose ('{0}|Directory_Entry_Path: {1}' -f $Function_Name,$Directory_Entry_Path)

    $Directory_Entry_Arguments = @($Directory_Entry_Path.ToString())
    if ($PSBoundParameters.ContainsKey('Credential')) {
        Write-Verbose ('{0}|Using credentials' -f $Function_Name)
        if ($Credential.GetNetworkCredential().Domain) {
            $Directory_Entry_Arguments += ('{0}\{1}' -f $Credential.GetNetworkCredential().Domain,$Credential.GetNetworkCredential().UserName)
        } else {
            $Directory_Entry_Arguments += $Credential.GetNetworkCredential().UserName
        }
        $Directory_Entry_Arguments += $Credential.GetNetworkCredential().Password
    }

    # Return the DirectoryEntry object
    New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList $Directory_Entry_Arguments
}