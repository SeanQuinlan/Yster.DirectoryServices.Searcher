function Get-DSSDirectoryEntry {
    <#
    .SYNOPSIS
        This creates a DirectoryEntry object, which is used when performing LDAP queries.
    .DESCRIPTION
        Creates a DirectoryEntry object, using the specified Context, Server, SearchBase and/or Credentials.

        This is mostly used to provide custom credentials and/or LDAP server to connect to. Omitting Server will result in a serverless bind. Omitting the credentials will use the currently logged in user credentials. The Context is used to decide whether to connect to any LDAP server (Domain) or to a Global Catalog server (Forest).
    .EXAMPLE
        $Directory_Entry_Parameters = @{
            'Context' = 'Domain'
            'Server'  = 'Server01'
        }
        Get-DSSDirectoryEntry @Directory_Entry_Parameters
    .NOTES
        References:
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry
        http://www.selfadsi.org/bind.htm
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
            [void]$Directory_Entry_Path.Append(('{0}' -f $Server))
        } else {
            try {
                Write-Verbose ('{0}|No Server specified, attempting to find current domain to use instead...' -f $Function_Name)
                $Check_For_Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                Write-Verbose ('{0}|Found domain: {1}' -f $Function_Name, $Check_For_Domain.Name)
                [void]$Directory_Entry_Path.Append($Check_For_Domain.Name)
            } catch {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-Active Directory'
                    'Category'       = 'InvalidOperation'
                    'TargetObject'   = $Check_For_Domain
                    'Message'        = $_.Exception.InnerException.Message
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            }
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            Write-Verbose ('{0}|Using custom SearchBase: {1}' -f $Function_Name, $SearchBase)
            if (-not $Directory_Entry_Path.ToString().EndsWith('/')) {
                [void]$Directory_Entry_Path.Append('/')
            }
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
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
