function Get-DSSUser {
    <#
    .SYNOPSIS
        Returns a specific user object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific user object, based on one of the following specified parameters:
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName

        This is a wrapper function that takes one of the required parameters and passes that to the Find-DSSUser with a specific LDAPFilter.
    .EXAMPLE
        Get-DSSUser -ObjectSID 'S-1-5-21-3515480276-2049723633-1306762111-500'

        Returns the user with the above SID.
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName')]
    param(
        # The DistinguishedName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The SAMAccountName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

        # The properties of any results to return.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain','Forest')]
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
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name,$_.Key,($_.Value -join ' ')) }

    try {
        $Directory_Search_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Search_Parameters.Server = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Search_Parameters.Credential = $Credential
        }
        if ($PSBoundParameters.ContainsKey('Properties')) {
            $Directory_Search_Parameters.Properties = $Properties
        }

        if ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $Directory_Search_LDAPFilter = '(distinguishedname={0})' -f $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $Directory_Search_LDAPFilter = '(objectsid={0})' -f $ObjectSID
        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            $Directory_Search_LDAPFilter = '(objectguid={0})' -f $ObjectGUID
        } elseif ($PSBoundParameters.ContainsKey('SAMAccountName')) {
            $Directory_Search_LDAPFilter = '(samaccountname={0})' -f $SAMAccountName
        }

        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name,$Directory_Search_LDAPFilter)
        $Directory_Search_Parameters.LDAPFilter = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSUser' -f $Function_Name)
        Find-DSSUser @Directory_Search_Parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}