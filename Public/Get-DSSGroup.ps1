function Get-DSSGroup {
    <#
    .SYNOPSIS
        Returns a specific group object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific group object, based on one of the following specified parameters:
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName

        This is a wrapper function that takes one of the required parameters and passes that to the Find-DSSGroup with a specific LDAPFilter.
    .EXAMPLE
        Get-DSSGroup -ObjectSID 'S-1-5-21-3515480276-2049723633-1306762111-1103'

        Returns the group with the above SID.
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName')]
    param(
        # The DistinguishedName of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The SAMAccountName of the group.
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

        # The number of results per page that is returned from the server. This is primarily to save server memory and bandwidth and does not affect the total number of results returned.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ResultPageSize')]
        [Int]
        $PageSize = 500,

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
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
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    $Directory_Search_Parameters = @{
        'Context'  = $Context
        'PageSize' = $PageSize
    }
    if ($PSBoundParameters.ContainsKey('Server')) {
        $Directory_Search_Parameters['Server'] = $Server
    }
    if ($PSBoundParameters.ContainsKey('Credential')) {
        $Directory_Search_Parameters['Credential'] = $Credential
    }
    if ($PSBoundParameters.ContainsKey('Properties')) {
        $Directory_Search_Parameters['Properties'] = $Properties
    }

    if ($PSBoundParameters.ContainsKey('DistinguishedName')) {
        $Directory_Search_LDAPFilter = '(distinguishedname={0})' -f $DistinguishedName
    } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
        $Directory_Search_LDAPFilter = '(objectsid={0})' -f $ObjectSID
    } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
        $Directory_Search_LDAPFilter = '(objectguid={0})' -f (Convert-GuidToHex -Guid $ObjectGUID)
    } elseif ($PSBoundParameters.ContainsKey('SAMAccountName')) {
        $Directory_Search_LDAPFilter = '(samaccountname={0})' -f $SAMAccountName
    }
    Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
    $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

    Write-Verbose ('{0}|Calling Find-DSSGroup' -f $Function_Name)
    Find-DSSGroup @Directory_Search_Parameters
}
