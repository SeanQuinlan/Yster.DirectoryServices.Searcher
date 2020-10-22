function Get-DSSOptionalFeature {
    <#
    .SYNOPSIS
        Returns a specific optional feature object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific optional feature object, based on one of the following specified parameters:
            - DistinguishedName
            - FeatureGUID
            - ObjectGUID (GUID)

        This is a wrapper function that takes one of the required parameters and passes that to the Find-DSSOptionalFeature with a specific LDAPFilter.
    .EXAMPLE
        Get-DSSOptionalFeature -ObjectGUID '4eb845c0-3626-4ae6-a892-873846a2953b'

        Returns the optional feature with the above GUID.
    .EXAMPLE
        Get-DSSOptionalFeature -FeatureGUID '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a'

        Returns the "Recycle Bin Feature", which has the FeatureGUID of 766ddcd8-acd0-445e-f3b9-a7f9b6744f2a.
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName')]
    param(
        # The directory context to search - Domain or Forest. By default this will search within the domain only.
        # If you want to search the entire directory, specify "Forest" for this parameter and the search will be performed on a Global Catalog server, targetting the entire forest.
        # An example of using this property is:
        #
        # -Context 'Forest'
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

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

        # The DistinguishedName of the optional feature.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The FeatureGUID of the optional feature.
        [Parameter(Mandatory = $true, ParameterSetName = 'FeatureGUID')]
        [ValidateNotNullOrEmpty()]
        [String]
        $FeatureGUID,

        # The ObjectGUID of the optional feature.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The number of results per page that is returned from the server. This is primarily to save server memory and bandwidth and does not affect the total number of results returned.
        # An example of using this property is:
        #
        # -PageSize 250
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ResultPageSize')]
        [Int]
        $PageSize = 500,

        # The properties of any results to return.
        # Some examples of using this property are:
        #
        # -Properties 'mail'
        # -Properties 'created','enabled','displayname'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

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
        } elseif ($PSBoundParameters.ContainsKey('FeatureGUID')) {
            $Directory_Search_LDAPFilter = '(msds-optionalfeatureguid={0})' -f (Convert-GuidToHex -Guid $FeatureGUID)
        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            $Directory_Search_LDAPFilter = '(objectguid={0})' -f (Convert-GuidToHex -Guid $ObjectGUID)
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSOptionalFeature' -f $Function_Name)
        Find-DSSOptionalFeature @Directory_Search_Parameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
