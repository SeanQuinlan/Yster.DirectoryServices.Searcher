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

    [CmdletBinding(DefaultParameterSetName = 'Search')]
    param(
        # The base OU to start the search from.
        [Parameter(Mandatory = $false, ParameterSetName = 'Search')]
        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        # The full path to the object.
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [String]
        $Path,

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

        # The server/domain/forest to run the query on.
        [Parameter(Mandatory = $false)]
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

    try {
        $Directory_Entry_Path = New-Object -TypeName 'System.Text.StringBuilder'
        if ($PSBoundParameters.ContainsKey('Path')) {
            Write-Verbose ('{0}|Full path specified' -f $Function_Name)
            [void]$Directory_Entry_Path.Append($Path)
        } else {
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
                    Write-Verbose ('{0}|No Server specified, attempting to find current {1} to use instead...' -f $Function_Name, $Context)
                    if ($Context -eq 'Forest') {
                        $Check_For_Context = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                    } else {
                        $Check_For_Context = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                    }
                    Write-Verbose ('{0}|Found {1}: {2}' -f $Function_Name, $Context, $Check_For_Context.Name)
                    [void]$Directory_Entry_Path.Append($Check_For_Context.Name)
                } catch {
                    $Terminating_ErrorRecord_Parameters = @{
                        'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                        'ID'             = 'DSS-Active Directory'
                        'Category'       = 'InvalidOperation'
                        'TargetObject'   = $Check_For_Context
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

        try {
            # See here for error handling of this object - https://stackoverflow.com/questions/43145567/powershell-directoryservice-object-error-neither-caught-nor-trapped
            $Directory_Entry_Object = New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList $Directory_Entry_Arguments
            [void]$Directory_Entry_Object.ToString()
            Write-Verbose ('{0}|Found directory entry with distinguishedname: {1}' -f $Function_Name, $($Directory_Entry_Object.'distinguishedname'))
            # Return the DirectoryEntry object
            $Directory_Entry_Object
        } catch {
            if ($_.Exception.InnerException.ErrorCode -eq '-2147016646') {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'ResourceUnavailable'
                    'TargetObject'   = $Directory_Entry_Object
                    'Message'        = 'Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.'
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.InnerException.ErrorCode -eq '-2147016656') {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'ResourceUnavailable'
                    'TargetObject'   = $Directory_Entry_Object
                    'Message'        = ('Base path does not exist: {0}' -f $SearchBase)
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.InnerException.ErrorCode -eq '-2147467259') {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'ResourceUnavailable'
                    'TargetObject'   = $Directory_Entry_Object
                    'Message'        = ('Unable to connect to path: {0}' -f $Path)
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } else {
                throw $_.Exception.InnerException
            }
        }
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
