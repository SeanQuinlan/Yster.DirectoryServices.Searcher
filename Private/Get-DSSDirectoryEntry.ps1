function Get-DSSDirectoryEntry {
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
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context,

        # The server/domain/forest to run the query on.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Forest', 'Domain')]
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
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Directory_Entry_Path = New-Object -TypeName 'System.Text.StringBuilder'
        if ($Context -eq 'Forest') {
            Write-Verbose ('{0}|Forest context' -f $Function_Name)
            [void]$Directory_Entry_Path.Append('GC://')
        } else {
            Write-Verbose ('{0}|Domain context' -f $Function_Name)
            [void]$Directory_Entry_Path.Append('LDAP://')
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            Write-Verbose ('{0}|Using server: {1}' -f $Function_Name, $Server)
            [void]$Directory_Entry_Path.Append(('{0}/' -f $Server))
        } else {
            Write-Verbose ('{0}|No Server specified, attempting to find current domain to use instead...' -f $Function_Name)
            $Check_For_Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            Write-Verbose ('{0}|Found domain: {1}' -f $Function_Name, $Check_For_Domain.Name)
            [void]$Directory_Entry_Path.Append($Check_For_Domain.Name)
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            Write-Verbose ('{0}|Using custom SearchBase: {1}' -f $Function_Name, $SearchBase)
            [void]$Directory_Entry_Path.Append($SearchBase)
        }
        Write-Verbose ('{0}|Directory_Entry_Path: {1}' -f $Function_Name, $Directory_Entry_Path)

        $Directory_Entry_Arguments = @($Directory_Entry_Path.ToString())
        if ($PSBoundParameters.ContainsKey('Credential')) {
            if ($Credential.GetNetworkCredential().Domain) {
                $Credential_User = ('{0}\{1}' -f $Credential.GetNetworkCredential().Domain, $Credential.GetNetworkCredential().UserName)
            } else {
                $Credential_User = $Credential.GetNetworkCredential().UserName
            }
            Write-Verbose ('{0}|Custom credential user: {1}' -f $Function_Name, $Credential_User)
            $Directory_Entry_Arguments += $Credential_User
            $Directory_Entry_Arguments += $Credential.GetNetworkCredential().Password
        }

        # Return the DirectoryEntry object
        New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList $Directory_Entry_Arguments
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
