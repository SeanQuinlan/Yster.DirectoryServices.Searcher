function Remove-DSSOrganizationalUnit {
    <#
    .SYNOPSIS
        Removes a specific organizational unit (OU) object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific OU object and then deletes it, based on one of the following specified parameters:
            - DistinguishedName
            - ObjectGUID (GUID)
    .EXAMPLE
        Remove-DSSOrganizationalUnit -DistinguishedName 'OU=Sales,OU=Depts,DC=contoso,DC=com'

        Deletes the Sales OU.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/remove-adorganizationalunit
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName', SupportsShouldProcess = $true)]
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

        # The DistinguishedName of the organizational unit.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectGUID of the organizational unit.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # Whether to delete all child objects recursively.
        # An example of using this property is:
        #
        # -Recursive
        [Parameter(Mandatory = $false)]
        [Switch]
        $Recursive,

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
        Write-Verbose ('{0}|Calling Remove-DSSObjectWrapper' -f $Function_Name)
        Remove-DSSObjectWrapper -ObjectType 'OrganizationalUnit' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
